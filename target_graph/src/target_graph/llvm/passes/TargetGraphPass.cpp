/*
 * TargetGraphPass.cpp
 * LLVM New-PM Pass for Target-Conditioned Program Graph Extraction.
 *
 * Emits:
 * 1. bb_map.jsonl: Basic Block metadata, source locations, and CFG successors (with collision-free stable BB IDs)
 * 2. raw_edges.jsonl: Multi-relational edges (CFG, DDG_SSA, DDG_MEM, CDG, CALL, RETURN)
 * 3. raw_nodes.jsonl: Basic Block node declarations
 * 4. pass_summary.json: Extraction summary and collision audit metadata
 */

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/SHA256.h"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>

using namespace llvm;

namespace {

// Format SHA-256 hash cleanly into 16 lowercase hex characters (8 bytes)
// Uses unsigned char casting to prevent negative sign extension / "ff" truncation
static std::string sha256_short(const std::string &input, size_t num_bytes = 8) {
    SHA256 hasher;
    hasher.update(ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(input.data()), input.size()));
    StringRef hash = hasher.final();
    std::string hex;
    hex.reserve(num_bytes * 2);
    static const char hexChars[] = "0123456789abcdef";
    for (size_t i = 0; i < num_bytes && i < hash.size(); ++i) {
        uint8_t byte = static_cast<uint8_t>(hash[i]);
        hex.push_back(hexChars[(byte >> 4) & 0x0f]);
        hex.push_back(hexChars[byte & 0x0f]);
    }
    return hex;
}

class TargetGraphPass : public PassInfoMixin<TargetGraphPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
        const char *buildIdEnv = getenv("TARGET_GRAPH_BUILD_ID");
        std::string buildId = buildIdEnv ? buildIdEnv : "default_build";
        
        const char *outDirEnv = getenv("TARGET_GRAPH_OUT_DIR");
        std::string outDir = outDirEnv ? outDirEnv : ".";

        std::error_code EC;
        raw_fd_ostream bbMapOut(outDir + "/bb_map.jsonl", EC, sys::fs::OF_Text | sys::fs::OF_Append);
        raw_fd_ostream edgesOut(outDir + "/raw_edges.jsonl", EC, sys::fs::OF_Text | sys::fs::OF_Append);
        raw_fd_ostream nodesOut(outDir + "/raw_nodes.jsonl", EC, sys::fs::OF_Text | sys::fs::OF_Append);

        std::string moduleName = M.getName().str();

        // Pass 1: Assign stable, collision-free BB IDs
        std::map<const BasicBlock *, std::string> bbToId;
        std::map<const BasicBlock *, std::string> bbToFunc;
        std::map<std::string, const BasicBlock *> funcEntryBB;
        std::map<const BasicBlock *, std::set<std::pair<std::string, unsigned>>> bbDebugLocs;
        std::map<const BasicBlock *, std::vector<std::string>> bbInstIds;

        std::map<std::string, const BasicBlock *> idToBB;
        size_t collisionCount = 0;
        size_t unresolvedCallsCount = 0;

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            std::string funcName = F.getName().str();
            size_t bbOrdinal = 0;

            for (BasicBlock &BB : F) {
                std::string bbKey = buildId + ":" + moduleName + ":" + funcName + ":" + std::to_string(bbOrdinal);
                std::string bbId = sha256_short(bbKey);

                // Collision detection and deterministic disambiguation
                if (idToBB.count(bbId) && idToBB[bbId] != &BB) {
                    collisionCount++;
                    errs() << "[TargetGraphPass] Collision detected for " << bbId
                           << " (" << funcName << ":" << bbOrdinal << " vs "
                           << bbToFunc[idToBB[bbId]] << "). Resolving...\n";
                    size_t disambig = 1;
                    std::string newId;
                    do {
                        newId = sha256_short(bbKey + "#disambig_" + std::to_string(disambig++));
                    } while (idToBB.count(newId));
                    bbId = newId;
                }

                idToBB[bbId] = &BB;
                bbToId[&BB] = bbId;
                bbToFunc[&BB] = funcName;
                if (bbOrdinal == 0) {
                    funcEntryBB[funcName] = &BB;
                }

                // Collect debug source lines and instruction IDs
                std::set<std::pair<std::string, unsigned>> debugLocs;
                std::vector<std::string> instIds;
                size_t instOrdinal = 0;

                for (Instruction &I : BB) {
                    instIds.push_back(bbId + ":" + std::to_string(instOrdinal++));
                    if (DILocation *Loc = I.getDebugLoc()) {
                        StringRef file = Loc->getFilename();
                        StringRef dir = Loc->getDirectory();
                        std::string fullPath = dir.empty() ? file.str() : (dir + "/" + file).str();
                        debugLocs.insert({fullPath, Loc->getLine()});
                    }
                }
                bbDebugLocs[&BB] = debugLocs;
                bbInstIds[&BB] = instIds;

                bbOrdinal++;
            }
        }

        // Pass 2: Emit nodes.jsonl, bb_map.jsonl, and extract multi-relational edges
        FunctionAnalysisManager &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            std::string funcName = F.getName().str();
            PostDominatorTree &PDT = FAM.getResult<PostDominatorTreeAnalysis>(F);
            DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(F);
            LoopInfo &LI = FAM.getResult<LoopAnalysis>(F);
            AAResults &AA = FAM.getResult<AAManager>(F);

            // Collect memory writes and reads per block for intra-procedural DDG_MEM
            struct MemAcc {
                Instruction *inst;
                MemoryLocation loc;
                bool isWrite;
            };
            std::map<const BasicBlock *, std::vector<MemAcc>> bbMemAccesses;
            for (BasicBlock &BB : F) {
                std::vector<MemAcc> accesses;
                for (Instruction &I : BB) {
                    if (auto *SI = dyn_cast<StoreInst>(&I)) {
                        accesses.push_back({SI, MemoryLocation::get(SI), true});
                    } else if (auto *LIInst = dyn_cast<LoadInst>(&I)) {
                        accesses.push_back({LIInst, MemoryLocation::get(LIInst), false});
                    }
                }
                if (!accesses.empty()) {
                    bbMemAccesses[&BB] = std::move(accesses);
                }
            }

            // Extract intra-procedural memory dependencies (DDG_MEM - Relation ID 5)
            // Enforces CFG reachability: store in srcBB can only dependently reach load in dstBB
            // if a feasible execution path exists from srcBB to dstBB (accounting for loops).
            for (auto &srcPair : bbMemAccesses) {
                const BasicBlock *srcBB = srcPair.first;
                std::string srcId = bbToId[srcBB];

                for (auto &dstPair : bbMemAccesses) {
                    const BasicBlock *dstBB = dstPair.first;
                    if (srcBB == dstBB) continue;

                    // Feasible path check: eliminate impossible flows (e.g. store executing after load in acyclic code)
                    if (!isPotentiallyReachable(srcBB, dstBB, nullptr, &DT, &LI)) {
                        continue;
                    }

                    std::string dstId = bbToId[dstBB];
                    size_t mustCount = 0;
                    size_t mayCount = 0;

                    for (auto &accSrc : srcPair.second) {
                        if (!accSrc.isWrite) continue;
                        for (auto &accDst : dstPair.second) {
                            if (accDst.isWrite) continue;
                            AliasResult AR = AA.alias(accSrc.loc, accDst.loc);
                            if (AR == AliasResult::MustAlias) {
                                mustCount++;
                            } else if (AR == AliasResult::MayAlias) {
                                mayCount++;
                            }
                        }
                    }

                    if (mustCount > 0) {
                        edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << dstId
                                 << "\",\"relation_id\":5,\"callsite_id\":\"\",\"evidence_count\":" << mustCount
                                 << ",\"analysis_status\":\"must\"}\n";
                    } else if (mayCount > 0) {
                        edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << dstId
                                 << "\",\"relation_id\":5,\"callsite_id\":\"\",\"evidence_count\":" << mayCount
                                 << ",\"analysis_status\":\"may\"}\n";
                    }
                }
            }

            size_t bbOrdinal = 0;
            for (BasicBlock &BB : F) {
                std::string srcId = bbToId[&BB];
                bool isEntry = (bbOrdinal == 0);
                bool isExit = isa<ReturnInst>(BB.getTerminator());
                auto &debugLocs = bbDebugLocs[&BB];
                auto &instIds = bbInstIds[&BB];

                // 2.1 Emit raw_nodes.jsonl
                nodesOut << "{\"build_id\":\"" << buildId << "\","
                         << "\"bb_id\":\"" << srcId << "\","
                         << "\"function_id\":\"" << funcName << "\","
                         << "\"mapping_status\":\"mapped\","
                         << "\"is_entry\":" << (isEntry ? "true" : "false") << ","
                         << "\"is_exit\":" << (isExit ? "true" : "false") << ","
                         << "\"source_spans\":[";
                
                bool firstLoc = true;
                for (auto &loc : debugLocs) {
                    if (!firstLoc) nodesOut << ",";
                    firstLoc = false;
                    nodesOut << "{\"file\":\"" << loc.first << "\",\"start_line\":" << loc.second
                             << ",\"start_col\":0,\"end_line\":" << loc.second << ",\"end_col\":0}";
                }
                nodesOut << "],\"instruction_ids\":[";
                for (size_t i = 0; i < instIds.size(); ++i) {
                    if (i > 0) nodesOut << ",";
                    nodesOut << "\"" << instIds[i] << "\"";
                }
                nodesOut << "]}\n";

                // 2.2 Emit bb_map.jsonl with stable BB successor IDs
                bbMapOut << "{\"build_id\":\"" << buildId << "\","
                         << "\"module\":\"" << moduleName << "\","
                         << "\"function\":\"" << funcName << "\","
                         << "\"bb_id\":\"" << srcId << "\","
                         << "\"debug_locations\":[";
                firstLoc = true;
                for (auto &loc : debugLocs) {
                    if (!firstLoc) bbMapOut << ",";
                    firstLoc = false;
                    bbMapOut << "{\"file\":\"" << loc.first << "\",\"line\":" << loc.second << "}";
                }
                bbMapOut << "],\"successors\":[";
                Instruction *term = BB.getTerminator();
                if (term) {
                    bool firstSucc = true;
                    for (unsigned i = 0; i < term->getNumSuccessors(); ++i) {
                        BasicBlock *succ = term->getSuccessor(i);
                        if (bbToId.count(succ)) {
                            if (!firstSucc) bbMapOut << ",";
                            firstSucc = false;
                            bbMapOut << "\"" << bbToId[succ] << "\"";
                        }
                    }
                }
                bbMapOut << "]}\n";

                // 2.3 CFG Edges
                if (auto *BI = dyn_cast<BranchInst>(term)) {
                    if (BI->isConditional()) {
                        BasicBlock *trueSucc = BI->getSuccessor(0);
                        BasicBlock *falseSucc = BI->getSuccessor(1);
                        if (bbToId.count(trueSucc)) {
                            edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[trueSucc]
                                     << "\",\"relation_id\":0,\"callsite_id\":\"\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                        }
                        if (bbToId.count(falseSucc)) {
                            edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[falseSucc]
                                     << "\",\"relation_id\":1,\"callsite_id\":\"\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                        }
                    } else if (BI->getNumSuccessors() > 0) {
                        BasicBlock *succ = BI->getSuccessor(0);
                        if (bbToId.count(succ)) {
                            edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[succ]
                                     << "\",\"relation_id\":2,\"callsite_id\":\"\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                        }
                    }
                } else if (term) {
                    for (unsigned i = 0; i < term->getNumSuccessors(); ++i) {
                        BasicBlock *succ = term->getSuccessor(i);
                        if (bbToId.count(succ)) {
                            edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[succ]
                                     << "\",\"relation_id\":3,\"callsite_id\":\"\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                        }
                    }
                }

                // 2.4 CDG Edges (Control Dependence via Post-Dominance)
                if (term && term->getNumSuccessors() > 1) {
                    for (unsigned i = 0; i < term->getNumSuccessors(); ++i) {
                        BasicBlock *succ = term->getSuccessor(i);
                        if (!PDT.dominates(succ, &BB)) {
                            DomTreeNodeBase<BasicBlock> *curr = PDT.getNode(succ);
                            DomTreeNodeBase<BasicBlock> *ipdom = PDT.getNode(&BB) ? PDT.getNode(&BB)->getIDom() : nullptr;
                            while (curr && curr != ipdom) {
                                BasicBlock *cdNode = curr->getBlock();
                                if (cdNode && bbToId.count(cdNode) && cdNode != &BB) {
                                    edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[cdNode]
                                             << "\",\"relation_id\":6,\"callsite_id\":\"\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                                }
                                curr = curr->getIDom();
                            }
                        }
                    }
                }

                // 2.5 DDG_SSA & CALL/RETURN Edges
                size_t instOrdinal = 0;
                for (Instruction &I : BB) {
                    // SSA def-use across basic blocks
                    for (User *U : I.users()) {
                        if (Instruction *UI = dyn_cast<Instruction>(U)) {
                            BasicBlock *useBB = UI->getParent();
                            if (useBB && useBB != &BB && bbToId.count(useBB)) {
                                edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[useBB]
                                         << "\",\"relation_id\":4,\"callsite_id\":\"\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                            }
                        }
                    }

                    // CALL & RETURN with callsite matching and unresolved indirect tracking
                    if (auto *CB = dyn_cast<CallBase>(&I)) {
                        Function *callee = CB->getCalledFunction();
                        std::string callsiteId = srcId + ":cs:" + std::to_string(instOrdinal);

                        if (callee && !callee->isDeclaration() && funcEntryBB.count(callee->getName().str())) {
                            const BasicBlock *entry = funcEntryBB[callee->getName().str()];
                            
                            // ICFG CALL edge (relation_id 7)
                            edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[entry]
                                     << "\",\"relation_id\":7,\"callsite_id\":\"" << callsiteId
                                     << "\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";

                            // ICFG RETURN edge (relation_id 8)
                            for (BasicBlock &calleeBB : *callee) {
                                if (isa<ReturnInst>(calleeBB.getTerminator()) && bbToId.count(&calleeBB)) {
                                    edgesOut << "{\"src_bb\":\"" << bbToId[&calleeBB] << "\",\"dst_bb\":\"" << srcId
                                             << "\",\"relation_id\":8,\"callsite_id\":\"" << callsiteId
                                             << "\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                                }
                            }

                            // SDG PARAM_IN edges (relation_id 9):
                            // Caller actual argument -> Callee formal parameter entry block
                            for (unsigned argIdx = 0; argIdx < CB->arg_size(); ++argIdx) {
                                Value *argVal = CB->getArgOperand(argIdx);
                                std::string argDefBBId = srcId;
                                if (auto *argInst = dyn_cast<Instruction>(argVal)) {
                                    BasicBlock *argDefBB = argInst->getParent();
                                    if (argDefBB && bbToId.count(argDefBB)) {
                                        argDefBBId = bbToId[argDefBB];
                                    }
                                }
                                edgesOut << "{\"src_bb\":\"" << argDefBBId << "\",\"dst_bb\":\"" << bbToId[entry]
                                         << "\",\"relation_id\":9,\"callsite_id\":\"" << callsiteId
                                         << "\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";

                                // Callsite summary edge (relation_id 11): actual-in -> actual-out at callsite
                                if (!CB->getType()->isVoidTy()) {
                                    edgesOut << "{\"src_bb\":\"" << argDefBBId << "\",\"dst_bb\":\"" << srcId
                                             << "\",\"relation_id\":11,\"callsite_id\":\"" << callsiteId
                                             << "\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                                }
                            }

                            // SDG PARAM_OUT edges (relation_id 10):
                            // Callee formal return -> Caller receiving callsite and use blocks
                            if (!CB->getType()->isVoidTy()) {
                                for (BasicBlock &calleeBB : *callee) {
                                    if (isa<ReturnInst>(calleeBB.getTerminator()) && bbToId.count(&calleeBB)) {
                                        edgesOut << "{\"src_bb\":\"" << bbToId[&calleeBB] << "\",\"dst_bb\":\"" << srcId
                                                 << "\",\"relation_id\":10,\"callsite_id\":\"" << callsiteId
                                                 << "\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                                        for (User *U : CB->users()) {
                                            if (Instruction *UI = dyn_cast<Instruction>(U)) {
                                                BasicBlock *useBB = UI->getParent();
                                                if (useBB && useBB != &BB && bbToId.count(useBB)) {
                                                    edgesOut << "{\"src_bb\":\"" << bbToId[&calleeBB] << "\",\"dst_bb\":\"" << bbToId[useBB]
                                                             << "\",\"relation_id\":10,\"callsite_id\":\"" << callsiteId
                                                             << "\",\"evidence_count\":1,\"analysis_status\":\"verified\"}\n";
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if (CB->isIndirectCall() || !callee) {
                            unresolvedCallsCount++;
                            FunctionType *FTy = CB->getFunctionType();
                            for (auto &pair : funcEntryBB) {
                                Function *candF = M.getFunction(pair.first);
                                if (candF && candF->hasAddressTaken() && candF->getFunctionType() == FTy) {
                                    edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[pair.second]
                                             << "\",\"relation_id\":7,\"callsite_id\":\"" << callsiteId
                                             << "\",\"evidence_count\":1,\"analysis_status\":\"may\"}\n";

                                    // May-target PARAM_IN
                                    edgesOut << "{\"src_bb\":\"" << srcId << "\",\"dst_bb\":\"" << bbToId[pair.second]
                                             << "\",\"relation_id\":9,\"callsite_id\":\"" << callsiteId
                                             << "\",\"evidence_count\":1,\"analysis_status\":\"may\"}\n";

                                    for (BasicBlock &candBB : *candF) {
                                        if (isa<ReturnInst>(candBB.getTerminator()) && bbToId.count(&candBB)) {
                                            edgesOut << "{\"src_bb\":\"" << bbToId[&candBB] << "\",\"dst_bb\":\"" << srcId
                                                     << "\",\"relation_id\":8,\"callsite_id\":\"" << callsiteId
                                                     << "\",\"evidence_count\":1,\"analysis_status\":\"may\"}\n";
                                            if (!CB->getType()->isVoidTy()) {
                                                edgesOut << "{\"src_bb\":\"" << bbToId[&candBB] << "\",\"dst_bb\":\"" << srcId
                                                         << "\",\"relation_id\":10,\"callsite_id\":\"" << callsiteId
                                                         << "\",\"evidence_count\":1,\"analysis_status\":\"may\"}\n";
                                            }
                                        }
                                    }
                                }
                            }
                        } else if (callee && callee->isDeclaration()) {
                            unresolvedCallsCount++;
                        }
                    }

                    instOrdinal++;
                }

                bbOrdinal++;
            }
        }

        // Emit pass_summary.json for audit and integrity verification
        raw_fd_ostream summaryOut(outDir + "/pass_summary.json", EC, sys::fs::OF_Text);
        if (!EC) {
            summaryOut << "{\n"
                       << "  \"build_id\": \"" << buildId << "\",\n"
                       << "  \"module_name\": \"" << moduleName << "\",\n"
                       << "  \"total_bbs\": " << bbToId.size() << ",\n"
                       << "  \"collisions_resolved\": " << collisionCount << ",\n"
                       << "  \"unresolved_calls\": " << unresolvedCallsCount << "\n"
                       << "}\n";
        }

        return PreservedAnalyses::all();
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "TargetGraphPass",
        LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "target-graph") {
                        MPM.addPass(TargetGraphPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}
