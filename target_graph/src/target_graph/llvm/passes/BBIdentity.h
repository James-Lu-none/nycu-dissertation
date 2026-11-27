#ifndef TARGET_GRAPH_BB_IDENTITY_H
#define TARGET_GRAPH_BB_IDENTITY_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/SHA256.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace target_graph {

constexpr const char *kBBIdMetadata = "target_graph.bb_id";
constexpr const char *kDGInstIdMetadata = "target_graph.dg.inst_id";

/// Format SHA-256 hash cleanly into 16 lowercase hex characters (8 bytes).
inline std::string sha256Short(const std::string &input, size_t numBytes = 8) {
    llvm::SHA256 hasher;
    hasher.update(llvm::ArrayRef<uint8_t>(
        reinterpret_cast<const uint8_t *>(input.data()), input.size()));
    llvm::StringRef hash = hasher.final();
    std::string hex;
    hex.reserve(numBytes * 2);
    static const char hexChars[] = "0123456789abcdef";
    for (size_t i = 0; i < numBytes && i < hash.size(); ++i) {
        uint8_t byte = static_cast<uint8_t>(hash[i]);
        hex.push_back(hexChars[(byte >> 4) & 0x0f]);
        hex.push_back(hexChars[byte & 0x0f]);
    }
    return hex;
}

/// Compute canonical, collision-free BB IDs for every defined BasicBlock in M.
inline void computeCanonicalBBIds(
    llvm::Module &M,
    const std::string &buildId,
    const std::string &moduleName,
    std::map<const llvm::BasicBlock *, std::string> &bbToId,
    size_t *collisionCount = nullptr) {
    std::set<std::string> seenIds;
    if (collisionCount) *collisionCount = 0;

    for (llvm::Function &F : M) {
        if (F.isDeclaration()) continue;
        std::string funcName = F.getName().str();
        size_t bbOrdinal = 0;

        for (llvm::BasicBlock &BB : F) {
            std::string bbKey = buildId + ":" + moduleName + ":" + funcName + ":" + std::to_string(bbOrdinal);
            std::string bbId = sha256Short(bbKey);

            if (!seenIds.insert(bbId).second) {
                if (collisionCount) (*collisionCount)++;
                size_t disambig = 1;
                std::string newId;
                do {
                    newId = sha256Short(bbKey + "#disambig_" + std::to_string(disambig++));
                } while (!seenIds.insert(newId).second);
                bbId = newId;
            }

            bbToId[&BB] = bbId;
            bbOrdinal++;
        }
    }
}

/// Read canonical BB ID from LLVM metadata if already tagged on BB.
inline std::string readBBIdMetadata(const llvm::BasicBlock &BB) {
    for (const llvm::Instruction &I : BB) {
        if (auto *MD = I.getMetadata(kBBIdMetadata)) {
            if (MD->getNumOperands() >= 1) {
                if (auto *S = llvm::dyn_cast<llvm::MDString>(MD->getOperand(0))) {
                    return S->getString().str();
                }
            }
        }
        if (auto *MD = I.getMetadata(kDGInstIdMetadata)) {
            if (MD->getNumOperands() >= 1) {
                if (auto *S = llvm::dyn_cast<llvm::MDString>(MD->getOperand(0))) {
                    llvm::StringRef val = S->getString();
                    size_t colon = val.find(':');
                    if (colon != llvm::StringRef::npos) {
                        return val.substr(0, colon).str();
                    }
                }
            }
        }
    }
    return "";
}

/// Attach canonical BB ID metadata onto the BasicBlock terminator.
inline void writeBBIdMetadata(llvm::BasicBlock &BB, const std::string &bbId) {
    if (auto *Term = BB.getTerminator()) {
        auto &Ctx = BB.getContext();
        Term->setMetadata(
            kBBIdMetadata,
            llvm::MDNode::get(Ctx, {llvm::MDString::get(Ctx, bbId)}));
    }
}

} // namespace target_graph

#endif // TARGET_GRAPH_BB_IDENTITY_H
