/*
 * TraceInstrumentPass.cpp
 * LLVM New-PM Pass that instruments every BasicBlock with a direct call to
 * __target_graph_trace_bb(uint64_t bb_id) and adds Attribute::SanitizeAddress.
 *
 * Reads canonical BB IDs from LLVM metadata (target_graph.bb_id /
 * target_graph.dg.inst_id) when present, falling back to the shared
 * BBIdentity.h deterministic formula otherwise.
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

#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>

using namespace llvm;

namespace {

class TraceInstrumentPass : public PassInfoMixin<TraceInstrumentPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
        (void)MAM;
        const char *buildIdEnv = std::getenv("TARGET_GRAPH_BUILD_ID");
        std::string buildId = buildIdEnv ? buildIdEnv : "default_build";
        const char *idModuleEnv = std::getenv("TARGET_GRAPH_ID_MODULE_NAME");
        std::string moduleName =
            (idModuleEnv && *idModuleEnv) ? std::string(idModuleEnv) : M.getName().str();

        // Pass 1: Resolve canonical BB IDs (prefer tagged metadata; fallback to shared formula).
        std::map<BasicBlock *, uint64_t> bbToIdVal;
        std::map<const BasicBlock *, std::string> computedIds;
        bool needComputed = false;

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            for (BasicBlock &BB : F) {
                std::string bbId = target_graph::readBBIdMetadata(BB);
                if (bbId.empty()) {
                    needComputed = true;
                    break;
                }
            }
            if (needComputed) break;
        }

        if (needComputed) {
            target_graph::computeCanonicalBBIds(M, buildId, moduleName, computedIds);
        }

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            for (BasicBlock &BB : F) {
                std::string bbId = target_graph::readBBIdMetadata(BB);
                if (bbId.empty()) {
                    bbId = computedIds[&BB];
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
        "TraceInstrumentPass",
        LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "target-graph-trace") {
                        MPM.addPass(TraceInstrumentPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}
