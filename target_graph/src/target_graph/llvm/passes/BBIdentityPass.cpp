/*
 * BBIdentityPass.cpp
 * Unified LLVM New-PM plugin providing two canonical BB identity passes:
 *
 * 1. bb-tag (alias: target-graph):
 *    Computes deterministic canonical BB IDs via BBIdentity.h, writes
 *    bb_map.jsonl and pass_summary.json, and tags each BasicBlock terminator
 *    with !target_graph.bb_id metadata.
 *
 * 2. bb-trace:
 *    Fail-closed trace instrumentation pass. Requires target_graph.bb_id (or
 *    target_graph.dg.inst_id) metadata on every BasicBlock, inserts a call to
 *    __target_graph_trace_bb(uint64_t bb_id), and adds Attribute::SanitizeAddress
 *    to all non-declaration functions.
 */

#include "BBIdentity.h"

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <utility>

using namespace llvm;

namespace {

class BBTagPass : public PassInfoMixin<BBTagPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
        (void)MAM;
        const char *buildIdEnv = std::getenv("TARGET_GRAPH_BUILD_ID");
        std::string buildId = buildIdEnv ? buildIdEnv : "default_build";

        const char *outDirEnv = std::getenv("TARGET_GRAPH_OUT_DIR");
        std::string outDir = outDirEnv ? outDirEnv : ".";
        std::string moduleName = M.getName().str();

        std::map<const BasicBlock *, std::string> bbToId;
        size_t collisionCount = 0;
        target_graph::computeCanonicalBBIds(M, buildId, moduleName, bbToId, &collisionCount);

        std::error_code EC;
        raw_fd_ostream bbMapOut(outDir + "/bb_map.jsonl", EC, sys::fs::OF_Text);
        if (EC) {
            report_fatal_error(Twine("Failed to open bb_map.jsonl: ") + EC.message());
        }

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            std::string funcName = F.getName().str();

            for (BasicBlock &BB : F) {
                const std::string &bbId = bbToId[&BB];
                target_graph::writeBBIdMetadata(BB, bbId);

                std::set<std::pair<std::string, unsigned>> debugLocs;
                for (Instruction &I : BB) {
                    if (DILocation *Loc = I.getDebugLoc()) {
                        StringRef file = Loc->getFilename();
                        StringRef dir = Loc->getDirectory();
                        std::string fullPath = dir.empty() ? file.str() : (dir + "/" + file).str();
                        debugLocs.insert({fullPath, Loc->getLine()});
                    }
                }

                json::OStream J(bbMapOut);
                J.object([&] {
                    J.attribute("build_id", buildId);
                    J.attribute("module", moduleName);
                    J.attribute("function", funcName);
                    J.attribute("bb_id", bbId);
                    J.attributeArray("debug_locations", [&] {
                        for (const auto &loc : debugLocs) {
                            J.object([&] {
                                J.attribute("file", loc.first);
                                J.attribute("line", static_cast<int64_t>(loc.second));
                            });
                        }
                    });
                    J.attributeArray("successors", [&] {
                        if (const Instruction *term = BB.getTerminator()) {
                            for (unsigned i = 0; i < term->getNumSuccessors(); ++i) {
                                const BasicBlock *succ = term->getSuccessor(i);
                                auto it = bbToId.find(succ);
                                if (it != bbToId.end()) {
                                    J.value(it->second);
                                }
                            }
                        }
                    });
                });
                bbMapOut << "\n";
            }
        }

        raw_fd_ostream summaryOut(outDir + "/pass_summary.json", EC, sys::fs::OF_Text);
        if (EC) {
            report_fatal_error(Twine("Failed to open pass_summary.json: ") + EC.message());
        }
        json::OStream S(summaryOut, 2);
        S.object([&] {
            S.attribute("build_id", buildId);
            S.attribute("module_name", moduleName);
            S.attribute("total_bbs", static_cast<int64_t>(bbToId.size()));
            S.attribute("collisions_resolved", static_cast<int64_t>(collisionCount));
        });
        summaryOut << "\n";

        return PreservedAnalyses::none();
    }
};

class BBTracePass : public PassInfoMixin<BBTracePass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
        (void)MAM;

        // Pass 1: Require canonical BB IDs from tagged metadata (fail-closed).
        std::map<BasicBlock *, uint64_t> bbToIdVal;

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            for (BasicBlock &BB : F) {
                std::string bbId = target_graph::readBBIdMetadata(BB);
                if (bbId.empty()) {
                    report_fatal_error(
                        Twine("BBTracePass: missing target_graph.bb_id metadata in function ") +
                        F.getName());
                }
                bbToIdVal[&BB] = std::stoull(bbId, nullptr, 16);
            }
        }

        // Pass 2: Insert __target_graph_trace_bb(bb_id) and enable ASan attribute.
        LLVMContext &Ctx = M.getContext();
        FunctionCallee traceFn = M.getOrInsertFunction(
            "__target_graph_trace_bb",
            Type::getVoidTy(Ctx),
            Type::getInt64Ty(Ctx));

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            if (F.getName() == "__target_graph_trace_bb") continue;

            F.addFnAttr(Attribute::SanitizeAddress);

            for (BasicBlock &BB : F) {
                auto it = bbToIdVal.find(&BB);
                if (it == bbToIdVal.end()) continue;

                auto IP = BB.getFirstInsertionPt();
                if (IP == BB.end()) continue;

                IRBuilder<> Builder(&BB, IP);
                Builder.CreateCall(traceFn, {Builder.getInt64(it->second)});
            }
        }

        return PreservedAnalyses::none();
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "BBIdentityPass",
        LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "bb-tag" || Name == "target-graph") {
                        MPM.addPass(BBTagPass());
                        return true;
                    }
                    if (Name == "bb-trace") {
                        MPM.addPass(BBTracePass());
                        return true;
                    }
                    return false;
                });
        }
    };
}
