/*
 * Identity-only LLVM 14 adapter for DG's llvm-slicer.
 *
 * Do NOT perform dependence analysis here. Tag original instructions using
 * the same BB hash/ordinal scheme as TargetGraphPass and AnalysisV2Pass.
 * After DG slices the tagged bitcode, export surviving original identities.
 * Any new instructions created by DG remain untagged and are not inferred to
 * correspond to original instructions.
 */
#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <set>
#include <string>

using namespace llvm;

namespace {
constexpr const char *IdentityMetadata = "target_graph.dg.inst_id";

std::string shortSHA256(const std::string &Input) {
  SHA256 Hasher;
  Hasher.update(ArrayRef<uint8_t>(
      reinterpret_cast<const uint8_t *>(Input.data()), Input.size()));
  StringRef Bytes = Hasher.final();
  static const char Hex[] = "0123456789abcdef";
  std::string Result;
  for (unsigned I = 0; I < 8; ++I) {
    const unsigned char Byte = static_cast<unsigned char>(Bytes[I]);
    Result += Hex[Byte >> 4];
    Result += Hex[Byte & 15];
  }
  return Result;
}

class DGTagPass : public PassInfoMixin<DGTagPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const char *BuildIdEnv = std::getenv("TARGET_GRAPH_BUILD_ID");
    if (!BuildIdEnv || !*BuildIdEnv)
      report_fatal_error("dg-tag requires TARGET_GRAPH_BUILD_ID");
    const std::string BuildId(BuildIdEnv);
    // Identity provenance is the *original* TargetGraphPass module name.
    // The LLVM module identifier may change when a case is copied/aliased.
    // This overrides hashing only; the actual IR module is not renamed.
    const char *IdModuleEnv = std::getenv("TARGET_GRAPH_ID_MODULE_NAME");
    const std::string IdModule =
        (IdModuleEnv && *IdModuleEnv) ? std::string(IdModuleEnv)
                                     : M.getName().str();
    if (IdModule != M.getName().str())
      errs() << "[dg-identity] using canonical module identity: " << IdModule
             << " (bitcode module name: " << M.getName() << ")\n";
    std::set<std::string> SeenBlocks;
    size_t Tagged = 0;

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      unsigned BlockOrdinal = 0;
      for (BasicBlock &BB : F) {
        const std::string Key = BuildId + ":" + IdModule + ":" +
                                F.getName().str() + ":" +
                                std::to_string(BlockOrdinal++);
        std::string BBId = shortSHA256(Key);
        unsigned Disambiguator = 1;
        while (!SeenBlocks.insert(BBId).second)
          BBId = shortSHA256(Key + "#disambig_" +
                             std::to_string(Disambiguator++));
        unsigned InstOrdinal = 0;
        for (Instruction &Inst : BB) {
          if (Inst.getMetadata(IdentityMetadata))
            report_fatal_error("input bitcode is already tagged");
          const std::string InstId =
              BBId + ":" + std::to_string(InstOrdinal++);
          Inst.setMetadata(
              IdentityMetadata,
              MDNode::get(M.getContext(),
                          {MDString::get(M.getContext(), InstId)}));
          ++Tagged;
        }
      }
    }

    errs() << "[dg-identity] tagged original instructions: " << Tagged
           << "\n";
    return PreservedAnalyses::none();
  }
};

class DGExportPass : public PassInfoMixin<DGExportPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const char *Path = std::getenv("TARGET_GRAPH_DG_EXPORT");
    if (!Path || !*Path)
      report_fatal_error("dg-export requires TARGET_GRAPH_DG_EXPORT");

    std::error_code EC;
    raw_fd_ostream Output(Path, EC, sys::fs::OF_Text);
    if (EC)
      report_fatal_error("dg-export could not open output file");

    std::set<std::string> IDs;
    size_t Unmarked = 0;
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      for (BasicBlock &BB : F) {
        for (Instruction &Inst : BB) {
          MDNode *MD = Inst.getMetadata(IdentityMetadata);
          if (!MD || MD->getNumOperands() != 1) {
            ++Unmarked;
            continue;
          }
          auto *String = dyn_cast<MDString>(MD->getOperand(0).get());
          if (!String) {
            ++Unmarked;
            continue;
          }
          const std::string Id = String->getString().str();
          const size_t Colon = Id.rfind(':');
          if (Colon == std::string::npos || !IDs.insert(Id).second)
            report_fatal_error("dg-export found malformed/duplicate identity");
          json::Object Record;
          Record["id"] = Id;
          Record["bb_id"] = Id.substr(0, Colon);
          Record["function"] = F.getName().str();
          Record["opcode"] = Inst.getOpcodeName();
          Output << formatv("{0}", json::Value(std::move(Record))) << "\n";
        }
      }
    }
    errs() << "[dg-identity] surviving tagged instructions: " << IDs.size()
           << ", untagged instructions: " << Unmarked << "\n";
    return PreservedAnalyses::all();
  }
};
} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DGIdentityPass", "0.1",
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "dg-tag") {
                    MPM.addPass(DGTagPass());
                    return true;
                  }
                  if (Name == "dg-export") {
                    MPM.addPass(DGExportPass());
                    return true;
                  }
                  return false;
                });
          }};
}
