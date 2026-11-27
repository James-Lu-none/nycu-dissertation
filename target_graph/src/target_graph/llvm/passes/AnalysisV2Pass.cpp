/*
 * AnalysisV2Pass: conservative instruction-level value-flow extraction.
 *
 * Verified: LLVM SSA operand def-use, exact direct-call actual->formal
 * argument binding, return-operand->call-result binding, LLVM PDT-based CDG.
 * Unknown: memory reaching definitions, external calls and indirect calls.
 * This pass does not claim to be a complete SDG or MemorySSA analysis.
 */
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

namespace {
static std::string sha256short(const std::string &Input) {
  SHA256 Hasher;
  Hasher.update(ArrayRef<uint8_t>(
      reinterpret_cast<const uint8_t *>(Input.data()), Input.size()));
  StringRef Bytes = Hasher.final();
  const char *Hex = "0123456789abcdef";
  std::string Result;
  for (unsigned I = 0; I < 8; ++I) {
    unsigned char C = static_cast<unsigned char>(Bytes[I]);
    Result.push_back(Hex[C >> 4]);
    Result.push_back(Hex[C & 15]);
  }
  return Result;
}

static void emitJSON(raw_ostream &OS, json::Object Record) {
  OS << formatv("{0}", json::Value(std::move(Record))) << "\n";
}

static void emitEdge(raw_ostream &OS, StringRef Src, StringRef Dst,
                     StringRef Kind, StringRef Status = "verified",
                     StringRef Callsite = "", int ArgIndex = -1) {
  json::Object O;
  O["src"] = Src.str();
  O["dst"] = Dst.str();
  O["kind"] = Kind.str();
  O["status"] = Status.str();
  O["callsite_id"] = Callsite.str();
  O["arg_index"] = ArgIndex;
  emitJSON(OS, std::move(O));
}

static std::string textOf(const Value &V) {
  std::string Text;
  raw_string_ostream OS(Text);
  V.printAsOperand(OS, false);
  OS.flush();
  if (Text.size() > 256)
    Text.resize(256);
  return Text;
}

class AnalysisV2Pass : public PassInfoMixin<AnalysisV2Pass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    const char *BuildEnv = std::getenv("TARGET_GRAPH_BUILD_ID");
    const char *DirEnv = std::getenv("TARGET_GRAPH_OUT_DIR");
    const std::string BuildId = BuildEnv ? BuildEnv : "default_build";
    const char *OriginalModuleEnv = std::getenv("TARGET_GRAPH_ID_MODULE_NAME");
    const std::string CanonicalModuleName =
        (OriginalModuleEnv && *OriginalModuleEnv) ? OriginalModuleEnv
                                               : M.getName().str();
    const std::string Dir = DirEnv ? DirEnv : ".";

    std::error_code EC;
    raw_fd_ostream Nodes(Dir + "/analysis_v2_nodes.jsonl", EC,
                         sys::fs::OF_Text);
    if (EC) {
      errs() << "[analysis-v2] node file: " << EC.message() << "\n";
      return PreservedAnalyses::all();
    }
    raw_fd_ostream Edges(Dir + "/analysis_v2_edges.jsonl", EC,
                         sys::fs::OF_Text);
    if (EC) {
      errs() << "[analysis-v2] edge file: " << EC.message() << "\n";
      return PreservedAnalyses::all();
    }

    std::map<const BasicBlock *, std::string> BBIds;
    std::map<const BasicBlock *, std::string> GateIds;
    std::map<const Instruction *, std::string> InstIds;
    std::map<const Argument *, std::string> FormalIds;
    std::set<std::string> SeenBBIDs;
    std::size_t NodeCount = 0, EdgeCount = 0, UnknownMem = 0;
    std::size_t UnknownCalls = 0, DirectCalls = 0;

    auto Node = [&](const std::string &Id, const std::string &Kind,
                    const std::string &Func, const std::string &BB,
                    const std::string &Text, unsigned Line = 0,
                    const std::string &File = "",
                    const std::string &CalleeName = "",
                    const DILocation *InstructionLoc = nullptr) {
      json::Object O;
      O["id"] = Id;
      O["kind"] = Kind;
      O["function"] = Func;
      O["bb_id"] = BB;
      O["text"] = Text;
      O["line"] = static_cast<int64_t>(Line);
      O["source_file"] = File;
      O["called_function"] = CalleeName;
      if (InstructionLoc) {
        json::Array CallsiteChain;
        // The source location can belong to an inlined callee. Each
        // inlinedAt parent represents a callsite in the LLVM owner (or
        // the next inlining ancestor), not another execution event.
        for (const DILocation *Callsite = InstructionLoc->getInlinedAt();
             Callsite; Callsite = Callsite->getInlinedAt()) {
          json::Object Frame;
          const std::string ParentDir = Callsite->getDirectory().str();
          const std::string ParentFile = Callsite->getFilename().str();
          Frame["file"] = ParentDir.empty() ? ParentFile
                                             : ParentDir + "/" + ParentFile;
          Frame["line"] = static_cast<int64_t>(Callsite->getLine());
          Frame["column"] = static_cast<int64_t>(Callsite->getColumn());
          Frame["discriminator"] =
              static_cast<int64_t>(Callsite->getDiscriminator());
          CallsiteChain.push_back(std::move(Frame));
        }
        O["inline_callsite_chain"] = std::move(CallsiteChain);
      }
      emitJSON(Nodes, std::move(O));
      ++NodeCount;
    };
    auto Edge = [&](StringRef Src, StringRef Dst, StringRef Kind,
                    StringRef Status = "verified", StringRef Callsite = "",
                    int Index = -1) {
      emitEdge(Edges, Src, Dst, Kind, Status, Callsite, Index);
      ++EdgeCount;
    };

    // Exactly reproduce the original BB ID scheme for Parquet/trace alignment.
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      unsigned BBOrdinal = 0;
      for (BasicBlock &BB : F) {
        const std::string Key = BuildId + ":" + CanonicalModuleName + ":" +
                                F.getName().str() + ":" +
                                std::to_string(BBOrdinal++);
        std::string BBId = sha256short(Key);
        unsigned Disambig = 1;
        while (!SeenBBIDs.insert(BBId).second)
          BBId = sha256short(Key + "#disambig_" +
                             std::to_string(Disambig++));
        BBIds[&BB] = BBId;
        GateIds[&BB] = BBId + ":control_gate";
        unsigned I = 0;
        for (Instruction &Inst : BB)
          InstIds[&Inst] = BBId + ":" + std::to_string(I++);
      }
      for (Argument &Arg : F.args())
        FormalIds[&Arg] = BuildId + ":" + F.getName().str() +
                          ":formal:" + std::to_string(Arg.getArgNo());
    }

    // Emit nodes first, including call results separated from call execution.
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      for (Argument &Arg : F.args())
        Node(FormalIds.at(&Arg), "formal", F.getName().str(),
             BBIds.at(&F.getEntryBlock()), "arg#" +
             std::to_string(Arg.getArgNo()));
      for (BasicBlock &BB : F) {
        const std::string BBId = BBIds.at(&BB);
        Node(GateIds.at(&BB), "control_gate", F.getName().str(), BBId, "");
        for (Instruction &Inst : BB) {
          unsigned Line = Inst.getDebugLoc() ? Inst.getDebugLoc().getLine() : 0;
          std::string File;
          if (DILocation *Loc = Inst.getDebugLoc()) {
            const std::string Dir = Loc->getDirectory().str();
            const std::string Name = Loc->getFilename().str();
            File = Dir.empty() ? Name : Dir + "/" + Name;
          }
          std::string CalleeName;
          if (auto *CB = dyn_cast<CallBase>(&Inst))
            if (Function *Target = CB->getCalledFunction())
              CalleeName = Target->getName().str();
          Node(InstIds.at(&Inst), "instruction", F.getName().str(), BBId,
               Inst.getOpcodeName(), Line, File, CalleeName,
               Inst.getDebugLoc().get());
          if (auto *CB = dyn_cast<CallBase>(&Inst))
            if (!CB->getType()->isVoidTy())
              Node(InstIds.at(&Inst) + ":result", "call_result",
                   F.getName().str(), BBId, "");
          if (isa<LoadInst>(&Inst) || isa<AtomicRMWInst>(&Inst) ||
              isa<AtomicCmpXchgInst>(&Inst)) {
            Node(InstIds.at(&Inst) + ":memory_unknown", "memory_unknown",
                 F.getName().str(), BBId,
                 "MemorySSA/SVF reaching definition not analyzed");
            Edge(InstIds.at(&Inst) + ":memory_unknown", InstIds.at(&Inst),
                 "MEMORY_UNKNOWN", "unknown");
            ++UnknownMem;
          }
        }
      }
    }

    // Use a separate result node for a non-void call to avoid the unsound
    // relation "all actual arguments influence the returned value".
    auto ValueId = [&](const Value *V, const Instruction *Use,
                       unsigned OpIndex) -> std::string {
      if (auto *Def = dyn_cast<Instruction>(V)) {
        const std::string &Id = InstIds.at(Def);
        if (auto *CB = dyn_cast<CallBase>(Def))
          if (!CB->getType()->isVoidTy())
            return Id + ":result";
        return Id;
      }
      if (auto *Formal = dyn_cast<Argument>(V))
        return FormalIds.at(Formal);
      return InstIds.at(Use) + ":operand:" + std::to_string(OpIndex);
    };

    // Instruction SSA, exact argument bindings, return-value bindings.
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      for (BasicBlock &BB : F) {
        for (Instruction &Inst : BB) {
          const std::string &UseId = InstIds.at(&Inst);
          // Compiler debug metadata is not runtime program dependence.
          if (isa<DbgInfoIntrinsic>(&Inst))
            continue;
          Edge(GateIds.at(&BB), UseId, "GUARD");
          unsigned OpIndex = 0;
          for (Use &Operand : Inst.operands()) {
            Value *V = Operand.get();
            unsigned Index = OpIndex++;
            if (isa<BasicBlock>(V))
              continue; // CFG targets are not value definitions.
            const std::string DefId = ValueId(V, &Inst, Index);
            if (!isa<Instruction>(V) && !isa<Argument>(V)) {
              Node(DefId, "literal_or_global", F.getName().str(),
                   BBIds.at(&BB), textOf(*V));
              // A global's memory content is NOT proven by this leaf.
              Edge(DefId, UseId, "VALUE_REFERENCE",
                   isa<GlobalValue>(V) || isa<ConstantExpr>(V)
                     ? "unknown" : "verified", "", Index);
            } else {
              Edge(DefId, UseId, "SSA", "verified", "", Index);
            }
          }

          auto *CB = dyn_cast<CallBase>(&Inst);
          if (!CB)
            continue;
          const std::string Callsite = UseId;
          Function *Callee = CB->getCalledFunction();
          if (!Callee || Callee->isDeclaration()) {
            ++UnknownCalls;
            json::Object Unresolved;
            Unresolved["id"] = Callsite + ":unresolved";
            Unresolved["kind"] = "unresolved_call";
            Unresolved["function"] = F.getName().str();
            Unresolved["bb_id"] = BBIds.at(&BB);
            Unresolved["text"] = Callee ? "external declaration" : "indirect call";
            Unresolved["line"] = static_cast<int64_t>(0);
            Unresolved["source_file"] = "";
            Unresolved["called_function"] = Callee ? Callee->getName().str() : "";
            // This is metadata, not an inferred call-target edge.
            emitJSON(Nodes, std::move(Unresolved));
            ++NodeCount;
            Edge(Callsite + ":unresolved",
                 CB->getType()->isVoidTy() ? Callsite : Callsite + ":result",
                 "CALL_UNKNOWN", "unknown", Callsite);
            continue;
          }
          ++DirectCalls;
          unsigned Index = 0;
          for (Argument &Formal : Callee->args()) {
            if (Index >= CB->arg_size())
              break;
            const Value *Actual = CB->getArgOperand(Index);
            // CallBase arg operands are first in its operand list.
            const std::string ActualId = ValueId(Actual, &Inst, Index);
            Edge(ActualId, FormalIds.at(&Formal), "PARAM_IN",
                 "verified", Callsite, Index);
            ++Index;
          }
          if (!CB->getType()->isVoidTy()) {
            for (BasicBlock &CalleeBB : *Callee) {
              if (auto *Ret = dyn_cast<ReturnInst>(CalleeBB.getTerminator()))
                if (Ret->getReturnValue())
                  Edge(InstIds.at(Ret), Callsite + ":result",
                       "RET_BIND", "verified", Callsite);
            }
          }
        }
      }
    }

    // LLVM postdominator-based *control* dependence as branch->gate, where
    // gate->instruction does not pull unrelated data instructions into a slice.
    auto &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      PostDominatorTree &PDT = FAM.getResult<PostDominatorTreeAnalysis>(F);
      for (BasicBlock &BB : F) {
        Instruction *Term = BB.getTerminator();
        if (!Term || Term->getNumSuccessors() < 2)
          continue;
        std::set<const BasicBlock *> Added;
        for (unsigned K = 0; K < Term->getNumSuccessors(); ++K) {
          BasicBlock *Succ = Term->getSuccessor(K);
          if (PDT.dominates(Succ, &BB))
            continue;
          auto *Curr = PDT.getNode(Succ);
          auto *Parent = PDT.getNode(&BB);
          auto *Stop = Parent ? Parent->getIDom() : nullptr;
          while (Curr && Curr != Stop) {
            const BasicBlock *Dependent = Curr->getBlock();
            if (Dependent && Dependent != &BB &&
                Added.insert(Dependent).second)
              Edge(InstIds.at(Term), GateIds.at(Dependent), "CONTROL");
            Curr = Curr->getIDom();
          }
        }
      }
    }

    raw_fd_ostream Summary(Dir + "/analysis_v2_summary.json", EC,
                           sys::fs::OF_Text);
    if (!EC) {
      json::Object S;
      S["schema_version"] = 1;
      S["build_id"] = BuildId;
      S["module"] = CanonicalModuleName;
      S["node_count"] = static_cast<int64_t>(NodeCount);
      S["edge_count"] = static_cast<int64_t>(EdgeCount);
      S["direct_calls"] = static_cast<int64_t>(DirectCalls);
      S["unresolved_calls"] = static_cast<int64_t>(UnknownCalls);
      S["unknown_memory_reads"] = static_cast<int64_t>(UnknownMem);
      S["memory_provenance_complete"] = false;
      S["indirect_calls_resolved"] = false;
      S["status"] = "PARTIAL_STATIC_VALUE_FLOW";
      emitJSON(Summary, std::move(S));
    }
    errs() << "[analysis-v2] nodes=" << NodeCount << " edges=" << EdgeCount
           << " unresolved_calls=" << UnknownCalls
           << " unresolved_memory_reads=" << UnknownMem << "\n";
    return PreservedAnalyses::all();
  }
};
} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AnalysisV2Pass", "0.1",
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name != "analysis-v2")
                    return false;
                  MPM.addPass(AnalysisV2Pass());
                  return true;
                });
          }};
}
