/*
 * TargetGraphPass.cpp
 * Minimal, deterministic LLVM New-PM Pass for canonical BB identity & mapping.
 *
 * Emits:
 * 1. bb_map.jsonl: Canonical BB IDs, function names, debug locations, and CFG successors
 * 2. pass_summary.json: Provenance metadata (build_id, module_name, total_bbs, collisions_resolved)
 *
 * Also tags each BasicBlock terminator with !target_graph.bb_id metadata.
 */

#include "BBIdentity.h"

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <utility>

using namespace llvm;

namespace {

class TargetGraphPass : public PassInfoMixin<TargetGraphPass> {
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
