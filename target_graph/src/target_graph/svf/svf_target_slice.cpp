/*
 * Target-site value-flow evidence from SVF-2.9 (LLVM14).
 *
 * This tool uses upstream SVF's Andersen analysis, MemorySSA/SVFG builder,
 * and native value-flow edges. It does NOT claim to implement a complete
 * interprocedural SDG or context-sensitive program slicer.
 *
 * The input bitcode MUST be pre-tagged by DGIdentityPass's dg-tag pass:
 * metadata key "target_graph.dg.inst_id" holds the identity of an ORIGINAL
 * LLVM instruction. This bridge is shared by DG and SVF.
 *
 * Important limitations:
 *  - Backward traversal is context-insensitive over SVFG nodes.
 *  - SVFG contains value-flow, not a complete CDG.
 *  - Some SVFG nodes have no unique LLVM instruction identity.
 *  - A source-level fault location may correspond to multiple inlined IR
 *    instructions; the caller must select and verify the target separately.
 */
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "Util/Options.h"
#include "Util/ExtAPI.h"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <queue>
#include <set>
#include <system_error>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace SVF;

namespace {
const char *const MetadataKey = "target_graph.dg.inst_id";

struct Args {
    std::string input, output, target, extapi;
    size_t max_nodes = 100000, max_edges = 300000;
};

bool parseSize(const std::string &value, size_t &out) {
    if (value.empty() || value[0] == '-')
        return false;
    errno = 0;
    char *end = nullptr;
    unsigned long long number = std::strtoull(value.c_str(), &end, 10);
    if (errno || !end || *end != '\0' || number == 0)
        return false;
    out = static_cast<size_t>(number);
    return static_cast<unsigned long long>(out) == number;
}

bool parseArgs(int argc, char **argv, Args &a) {
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc)
            return false;
        const std::string key(argv[i]), val(argv[i + 1]);
        if (key == "--input") a.input = val;
        else if (key == "--output") a.output = val;
        else if (key == "--target-inst") a.target = val;
        else if (key == "--extapi-bc") a.extapi = val;
        else if (key == "--max-nodes") {
            if (!parseSize(val, a.max_nodes)) return false;
        } else if (key == "--max-edges") {
            if (!parseSize(val, a.max_edges)) return false;
        } else return false;
    }
    return !a.input.empty() && !a.output.empty() && !a.target.empty() &&
           !a.extapi.empty();
}

// Map SVFG evidence back to an ORIGINAL, identity-tagged LLVM instruction.
// SVF node IDs are NOT LLVM instruction IDs, and they must never be confused.
const llvm::Instruction *llvmInstructionFor(const VFGNode *node) {
    const ICFGNode *icfg = node->getICFGNode();
    if (!icfg)
        return nullptr;
    const SVFInstruction *svf_inst = nullptr;
    if (auto *intra = SVFUtil::dyn_cast<IntraICFGNode>(icfg))
        svf_inst = intra->getInst();
    else if (auto *call = SVFUtil::dyn_cast<CallICFGNode>(icfg))
        svf_inst = call->getCallSite();
    else if (auto *ret = SVFUtil::dyn_cast<RetICFGNode>(icfg))
        svf_inst = ret->getCallSite();
    if (!svf_inst)
        return nullptr;
    const llvm::Value *value =
        LLVMModuleSet::getLLVMModuleSet()->getLLVMValue(svf_inst);
    return llvm::dyn_cast_or_null<llvm::Instruction>(value);
}

std::string originalInstructionId(const VFGNode *node) {
    const llvm::Instruction *inst = llvmInstructionFor(node);
    if (!inst)
        return {};
    const llvm::MDNode *md = inst->getMetadata(MetadataKey);
    if (!md || md->getNumOperands() != 1)
        return {};
    const auto *str = llvm::dyn_cast<llvm::MDString>(md->getOperand(0).get());
    return str ? str->getString().str() : std::string();
}

std::string basicBlockId(const std::string &inst) {
    const size_t pos = inst.rfind(':');
    return pos == std::string::npos ? std::string() : inst.substr(0, pos);
}

const char *edgeKind(const VFGEdge *edge) {
    if (edge->isCallDirectVFGEdge()) return "CALL_DIRECT_VALUE_FLOW";
    if (edge->isRetDirectVFGEdge()) return "RETURN_DIRECT_VALUE_FLOW";
    if (edge->isCallIndirectVFGEdge()) return "CALL_INDIRECT_VALUE_FLOW";
    if (edge->isRetIndirectVFGEdge()) return "RETURN_INDIRECT_VALUE_FLOW";
    if (edge->isThreadMHPIndirectVFGEdge()) return "THREAD_INDIRECT_VALUE_FLOW";
    if (edge->isIndirectVFGEdge()) return "INTRA_INDIRECT_VALUE_FLOW";
    return "INTRA_DIRECT_VALUE_FLOW";
}
} // namespace

int main(int argc, char **argv) {
    Args args;
    if (!parseArgs(argc, argv, args)) {
        llvm::errs()
            << "Usage: targetgraph-svf --input TAGGED.bc --target-inst BB:ORD "
            << "--output svfg.json --extapi-bc /path/to/extapi.bc "
            << "[--max-nodes N] [--max-edges N]\n";
        return 2;
    }

    // Upstream SVF needs the matching external-function model. Do not rely
    // on working-directory searches or silently continue without it.
    if (!ExtAPI::setExtBcPath(args.extapi)) {
        llvm::errs() << "[svf] Missing/invalid extapi.bc: " << args.extapi << "\n";
        return 2;
    }

    // SVF 2.9's official library example uses this same construction path.
    std::vector<std::string> modules{args.input};
    SVFModule *module = LLVMModuleSet::buildSVFModule(modules);
    SVFIRBuilder irBuilder(module);
    SVFIR *ir = irBuilder.build();
    Andersen *pta = AndersenWaveDiff::createAndersenWaveDiff(ir);
    SVFGBuilder builder(true);
    SVFG *svfg = builder.buildFullSVFG(pta);
    if (!svfg) {
        llvm::errs() << "[svf] SVFG construction returned null\n";
        return 3;
    }

    // The target instruction can expand into multiple SVFG nodes.
    // Never silently choose only the first matching node.
    std::queue<const VFGNode *> todo;
    std::set<NodeID> visited;
    llvm::json::Array seed_ids;
    for (const auto &entry : *svfg) {
        const VFGNode *node = entry.second;
        if (originalInstructionId(node) == args.target) {
            if (visited.insert(node->getId()).second) {
                todo.push(node);
                seed_ids.push_back(static_cast<int64_t>(node->getId()));
            }
        }
    }
    if (todo.empty()) {
        llvm::errs()
            << "[svf] No SVFG node resolves to the requested original LLVM "
            << "instruction; no slice exported. Check whether the target "
            << "has a value-flow node and was mapped from the same bitcode.\n";
        return 4;
    }

    llvm::json::Array nodes, edges;
    std::set<std::string> instruction_ids, basic_blocks;
    size_t mapped_nodes = 0, unmapped_nodes = 0;
    while (!todo.empty()) {
        const VFGNode *node = todo.front();
        todo.pop();
        if (visited.size() > args.max_nodes ||
            edges.size() > args.max_edges) {
            llvm::errs() << "[svf] Traversal budget exceeded; refusing partial export\n";
            return 5;
        }

        const std::string inst_id = originalInstructionId(node);
        llvm::json::Object record;
        record["svfg_id"] = static_cast<int64_t>(node->getId());
        record["svfg_kind"] = static_cast<int64_t>(node->getNodeKind());
        if (!inst_id.empty()) {
            record["instruction_id"] = inst_id;
            record["bb_id"] = basicBlockId(inst_id);
            ++mapped_nodes;
            instruction_ids.insert(inst_id);
            basic_blocks.insert(basicBlockId(inst_id));
        } else {
            record["instruction_id"] = nullptr;
            record["bb_id"] = nullptr;
            ++unmapped_nodes;
        }
        nodes.push_back(std::move(record));

        for (auto it = node->InEdgeBegin(); it != node->InEdgeEnd(); ++it) {
            const VFGEdge *edge = *it;
            const VFGNode *src = edge->getSrcNode();
            llvm::json::Object relation;
            relation["src_svfg_id"] = static_cast<int64_t>(src->getId());
            relation["dst_svfg_id"] = static_cast<int64_t>(node->getId());
            relation["kind"] = edgeKind(edge);
            relation["analysis_status"] = "may";
            // Native SVFG edges do not, by themselves, certify a crash cause.
            edges.push_back(std::move(relation));
            if (edges.size() > args.max_edges) {
                llvm::errs() << "[svf] Edge budget exceeded; refusing partial export\n";
                return 5;
            }
            if (visited.insert(src->getId()).second) {
                if (visited.size() > args.max_nodes) {
                    llvm::errs() << "[svf] Node budget exceeded; refusing partial export\n";
                    return 5;
                }
                todo.push(src);
            }
        }
    }

    if (!instruction_ids.count(args.target)) {
        llvm::errs() << "[svf] Target lost during identity mapping\n";
        return 4;
    }
    llvm::json::Array mapped_instructions, mapped_bbs;
    for (const auto &s : instruction_ids) mapped_instructions.push_back(s);
    for (const auto &s : basic_blocks) mapped_bbs.push_back(s);

    llvm::json::Object report;
    report["schema_version"] = 1;
    report["backend"] = "SVF-2.9/SVFG";
    report["analysis"] = "BACKWARD_VALUE_FLOW_ONLY";
    report["status"] = "EXPLORATORY_ONLY";
    report["validated_for_supervision"] = false;
    report["target_site_verified"] = false;
    report["context_sensitive"] = false;
    report["control_dependencies_included"] = false;
    report["target"] = args.target;
    report["target_seed_svfg_ids"] = std::move(seed_ids);
    report["svfg_total_nodes"] = static_cast<int64_t>(svfg->getSVFGNodeNum());
    report["visited_svfg_nodes"] = static_cast<int64_t>(visited.size());
    report["mapped_svfg_nodes"] = static_cast<int64_t>(mapped_nodes);
    report["unmapped_svfg_nodes"] = static_cast<int64_t>(unmapped_nodes);
    report["traversed_edges"] = static_cast<int64_t>(edges.size());
    report["instruction_ids"] = std::move(mapped_instructions);
    report["basic_blocks"] = std::move(mapped_bbs);
    report["svfg_nodes"] = std::move(nodes);
    report["svfg_edges"] = std::move(edges);

    std::error_code error;
    llvm::raw_fd_ostream output(args.output, error, llvm::sys::fs::OF_Text);
    if (error) {
        llvm::errs() << "[svf] Cannot open output: " << error.message() << "\n";
        return 6;
    }
    output << llvm::formatv("{0:2}", llvm::json::Value(std::move(report))) << "\n";
    output.flush();
    return output.has_error() ? 6 : 0;
}
