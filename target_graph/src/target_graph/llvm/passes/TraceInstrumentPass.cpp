/*
 * TraceInstrumentPass.cpp
 * LLVM New-PM Pass that instruments every BasicBlock with a direct call to
 * __target_graph_trace_bb(uint64_t bb_id) using the exact same deterministic
 * BB ID formula as TargetGraphPass, and adds Attribute::SanitizeAddress
 * so compiling <bin>_trace.bc with -fsanitize=address instruments the code.
 */

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Attributes.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SHA256.h"

#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>

using namespace llvm;

namespace {

// Must match TargetGraphPass::sha256_short identically.
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

class TraceInstrumentPass : public PassInfoMixin<TraceInstrumentPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
        (void)MAM;
        const char *buildIdEnv = std::getenv("TARGET_GRAPH_BUILD_ID");
        std::string buildId = buildIdEnv ? buildIdEnv : "default_build";
        std::string moduleName = M.getName().str();

        // Pass 1: Compute canonical BB IDs identically to TargetGraphPass.
        std::map<BasicBlock *, uint64_t> bbToIdVal;
        std::map<std::string, const BasicBlock *> idToBB;

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            std::string funcName = F.getName().str();
            size_t bbOrdinal = 0;

            for (BasicBlock &BB : F) {
                std::string bbKey = buildId + ":" + moduleName + ":" + funcName + ":" + std::to_string(bbOrdinal);
                std::string bbId = sha256_short(bbKey);

                if (idToBB.count(bbId) && idToBB[bbId] != &BB) {
                    int disambig = 1;
                    std::string newId;
                    do {
                        newId = sha256_short(bbKey + "#disambig_" + std::to_string(disambig++));
                    } while (idToBB.count(newId));
                    bbId = newId;
                }

                idToBB[bbId] = &BB;
                bbToIdVal[&BB] = std::stoull(bbId, nullptr, 16);
                bbOrdinal++;
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
