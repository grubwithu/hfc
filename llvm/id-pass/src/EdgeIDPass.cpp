// OrchestraEdgeIDPass: LLVM pass that instruments conditional branch
// successors and emits a JSON manifest with deterministic edge IDs.
//
// The pass does two things:
// 1. At compile time: writes a JSONL manifest of all edge facts.
// 2. At runtime: inserts a callback __orchestra_record_edge(edge_id) at
//    the entry of each successor block, so the runtime can record which
//    edges were actually executed.
//
// Edge IDs are assigned by a stable hash of:
//   (function name, file, line, column, successor ordinal, IR fingerprint)
//
// This pass writes facts only. It does not resolve CodeQL entities.

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <set>
#include <string>
#include <vector>

using namespace llvm;

namespace {

// FNV-1a hash, 32-bit, for deterministic edge IDs.
static uint32_t stableHash(const std::string &s) {
  uint32_t hash = 0x811c9dc5u;
  for (char c : s) {
    hash ^= static_cast<uint8_t>(c);
    hash *= 0x01000193u;
  }
  return hash;
}

static uint32_t computeEdgeID(const std::string &funcName,
                              const std::string &file, unsigned line,
                              unsigned column, unsigned succOrdinal,
                              const std::string &irFp) {
  std::string key = funcName + "|" + file + "|" +
                    std::to_string(line) + ":" +
                    std::to_string(column) + "|" +
                    std::to_string(succOrdinal) + "|" + irFp;
  return stableHash(key);
}

static std::string buildIRFingerprint(BranchInst *br) {
  std::string fp;
  raw_string_ostream os(fp);
  os << "br_i1";
  if (br->isConditional()) {
    Value *cond = br->getCondition();
    os << "_" << cond->getType()->getTypeID();
    if (auto *cmp = dyn_cast<ICmpInst>(cond)) {
      os << "_icmp_" << CmpInst::getPredicateName(cmp->getPredicate()).str();
    }
  }
  os << "_succ" << br->getNumSuccessors();
  os.flush();
  return fp;
}

static std::string linkageName(Function &F) {
  switch (F.getLinkage()) {
  case GlobalValue::ExternalLinkage: return "external";
  case GlobalValue::InternalLinkage:  return "internal";
  case GlobalValue::PrivateLinkage:   return "private";
  case GlobalValue::LinkOnceODRLinkage: return "linkonce_odr";
  case GlobalValue::LinkOnceAnyLinkage: return "linkonce";
  case GlobalValue::WeakODRLinkage:    return "weak_odr";
  case GlobalValue::WeakAnyLinkage:    return "weak";
  default: return "other";
  }
}

struct SourceLoc {
  std::string file;
  unsigned line = 0;
  unsigned column = 0;
  std::vector<std::string> inlineStack;
};

static SourceLoc getBranchLocation(BranchInst *br) {
  SourceLoc loc;
  if (const DILocation *dia = br->getDebugLoc()) {
    loc.line = dia->getLine();
    loc.column = dia->getColumn();
    if (const DIFile *file = dia->getFile()) {
      loc.file = (file->getDirectory() + "/" + file->getFilename()).str();
    }
    const DILocation *inlineAt = dia->getInlinedAt();
    while (inlineAt) {
      std::string frame;
      if (const DISubprogram *sp = inlineAt->getScope()->getSubprogram())
        frame = sp->getName().str();
      else
        frame = "unknown";
      frame += ":" + std::to_string(inlineAt->getLine());
      loc.inlineStack.push_back(frame);
      inlineAt = inlineAt->getInlinedAt();
    }
  }
  return loc;
}

struct EdgeFact {
  uint32_t edgeID;
  std::string functionName;
  std::string functionLinkage;
  std::string file;
  unsigned line;
  unsigned column;
  unsigned successorOrdinal;
  std::string irFingerprint;
  std::vector<std::string> inlineStack;
  BranchInst *branch;
  unsigned successorIndex;
};

static std::vector<EdgeFact> collectEdges(Module &M) {
  std::vector<EdgeFact> edges;
  std::set<uint32_t> seenIDs;

  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::string funcName = F.getName().str();
    std::string linkage = linkageName(F);

    for (BasicBlock &BB : F) {
      BranchInst *term = dyn_cast<BranchInst>(BB.getTerminator());
      if (!term || !term->isConditional())
        continue;

      SourceLoc loc = getBranchLocation(term);
      std::string irFp = buildIRFingerprint(term);

      for (unsigned i = 0; i < term->getNumSuccessors(); i++) {
        uint32_t id = computeEdgeID(funcName, loc.file, loc.line,
                                    loc.column, i, irFp);
        if (seenIDs.count(id))
          continue;
        seenIDs.insert(id);

        EdgeFact fact;
        fact.edgeID = id;
        fact.functionName = funcName;
        fact.functionLinkage = linkage;
        fact.file = loc.file;
        fact.line = loc.line;
        fact.column = loc.column;
        fact.successorOrdinal = i;
        fact.irFingerprint = irFp;
        fact.inlineStack = loc.inlineStack;
        fact.branch = term;
        fact.successorIndex = i;
        edges.push_back(std::move(fact));
      }
    }
  }
  return edges;
}

static std::string jsonEscape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
    case '"':  out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\n': out += "\\n";  break;
    case '\t': out += "\\t";  break;
    case '\r': out += "\\r";  break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        char buf[8];
        snprintf(buf, sizeof(buf), "\\u%04x", c);
        out += buf;
      } else {
        out += c;
      }
    }
  }
  return out;
}

// Write edge facts as JSON Lines (append mode).
static void writeManifest(const std::vector<EdgeFact> &edges) {
  const char *envPath = getenv("ORCHESTRA_EDGE_MANIFEST");
  std::error_code ec;
  std::string jsonl;
  for (const EdgeFact &e : edges) {
    jsonl += "{";
    jsonl += "\"edge_id\":" + std::to_string(e.edgeID) + ",";
    jsonl += "\"function_name\":\"" + jsonEscape(e.functionName) + "\",";
    jsonl += "\"function_linkage\":\"" + jsonEscape(e.functionLinkage) + "\",";
    jsonl += "\"file\":\"" + jsonEscape(e.file) + "\",";
    jsonl += "\"line\":" + std::to_string(e.line) + ",";
    jsonl += "\"column\":" + std::to_string(e.column) + ",";
    jsonl += "\"successor_ordinal\":" + std::to_string(e.successorOrdinal) + ",";
    jsonl += "\"ir_fingerprint\":\"" + jsonEscape(e.irFingerprint) + "\",";
    jsonl += "\"inline_stack\":[";
    for (size_t j = 0; j < e.inlineStack.size(); j++) {
      if (j > 0) jsonl += ",";
      jsonl += "\"" + jsonEscape(e.inlineStack[j]) + "\"";
    }
    jsonl += "]}";
    jsonl += "\n";
  }

  if (envPath && envPath[0]) {
    raw_fd_ostream out(envPath, ec, sys::fs::OF_Append | sys::fs::OF_Text);
    if (ec) {
      errs() << "OrchestraEdgeIDPass: cannot write manifest: " << ec.message() << "\n";
      errs() << jsonl;
    } else {
      out << jsonl;
    }
  } else {
    errs() << jsonl;
  }
}

// Insert runtime edge coverage callbacks. This inserts a call to
// __orchestra_record_edge(edge_id) at the entry of each successor block.
// If the strong definition (from liborchestra_edge_runtime.a) is not linked,
// a weak no-op definition in this module ensures the symbol always resolves.
static void instrumentEdges(Module &M, const std::vector<EdgeFact> &edges) {
  if (edges.empty())
    return;

  LLVMContext &ctx = M.getContext();
  FunctionType *callbackTy = FunctionType::get(
      Type::getVoidTy(ctx),
      {Type::getInt32Ty(ctx)},
      false);
  FunctionCallee callback = M.getOrInsertFunction(
      "__orchestra_record_edge", callbackTy);

  // Ensure a weak no-op definition exists so that binaries which do NOT link
  // liborchestra_edge_runtime.a still resolve the symbol. If the strong
  // definition from the runtime library is linked, it overrides this weak one.
  auto *callbackFn = dyn_cast<Function>(callback.getCallee());
  if (callbackFn && callbackFn->isDeclaration()) {
    callbackFn->setLinkage(GlobalValue::WeakAnyLinkage);
    BasicBlock *body = BasicBlock::Create(ctx, "entry", callbackFn);
    IRBuilder<> builder(body);
    builder.CreateRetVoid();
  }

  for (const EdgeFact &e : edges) {
    BasicBlock *succ = e.branch->getSuccessor(e.successorIndex);
    if (!succ || succ->empty())
      continue;
    // Insert the callback at the beginning of the successor block.
    // PHIs must come first, so insert after the last PHI.
    Instruction *insertBefore = &succ->front();
    while (insertBefore && isa<PHINode>(insertBefore)) {
      insertBefore = insertBefore->getNextNode();
    }
    if (!insertBefore)
      continue;
    IRBuilder<> builder(insertBefore);
    Value *edgeIDVal = ConstantInt::get(Type::getInt32Ty(ctx), e.edgeID);
    builder.CreateCall(callback, {edgeIDVal});
  }
}

class OrchestraEdgeIDPass : public PassInfoMixin<OrchestraEdgeIDPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    auto edges = collectEdges(M);
    writeManifest(edges);
    instrumentEdges(M, edges);
    errs() << "OrchestraEdgeIDPass: emitted " << edges.size()
           << " edge facts\n";
    // We modified the IR by inserting callbacks.
    return PreservedAnalyses::none();
  }

  static bool isRequired() { return true; }
};

} // namespace

extern "C" PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "OrchestraEdgeIDPass",
          LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // Register at the optimizer's last EP so the pass runs after
            // all optimization passes. This avoids interfering with meson's
            // and cmake's compiler feature detection probes, which happen
            // during the pipeline start EP.
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel,
                   ThinOrFullLTOPhase) {
                  MPM.addPass(OrchestraEdgeIDPass());
                });
          }};
}
