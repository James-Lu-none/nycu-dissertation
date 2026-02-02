#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Pass.h"
// #include "llvm/Transforms/IPO/PassManagerBuilder.h" deprecated in llvm17
// instead, use the following three includes
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <iostream>
#include <string>

// using namespace llvm;
using namespace std;

// the following function pass will insert a print statement at the beginning of each function and also count how many times each function is called during runtime
namespace llvm {
// Runtime Print Function Call Counter Pass (inherits from FunctionPass)
// struct RPFCC : public FunctionPass { // deprecated in llvm17, instead use PassInfoMixin
class RPFCC : public PassInfoMixin<RPFCC> {
    // boilerplate code: initialize pass ID 
public:
    static bool isRequired() { return true; }

    // main function that runs on each function in the module
    // this is the function that we will override to implement our pass logic
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) { // F is the object that contains llvmir instruction sequence for the current compiling function
        // Get the llvm compile information context
        LLVMContext &context = F.getContext();
        // Get the parent module of the function (see what module we are in??)
        Module *module = F.getParent();

        // we are going to insert a call to printf function, but instead of including stdio.h in normal C/C++ way, we need to declare the function prototype in LLVM IR way, and tell llvm what printf is and how to call it
        FunctionType *printfType = FunctionType::get(
            Type::getInt32Ty(context),        // printf returns int
            {PointerType::get(context, 0)}, // Type::getInt8PtrTy is deprecated in llvm17, use PointerType::getUnmanaged instead
            true                              // printf is variadic
        );
        FunctionCallee printfFunc = module->getOrInsertFunction("printf", printfType);

        string functionName = F.getName().str();
        string functionCallVarName = functionName + "_call_count";
        GlobalVariable *functionCallCount = module->getGlobalVariable(functionCallVarName);

        // init the global variable if functionCallCount is a null pointer 
        if (!functionCallCount) {
            // Create a global variable to hold the call count, initialized to 0
            functionCallCount = new GlobalVariable(
                *module,
                Type::getInt32Ty(context),
                false, // isConstant
                GlobalValue::CommonLinkage,
                0, // initializer, we set it 0 since we want to count from 0
                functionCallVarName
            );
            // Initialize the call count to 0
            functionCallCount->setInitializer(ConstantInt::get(Type::getInt32Ty(context), 0));
        }

        // get the fisrt instruction of the first basic block of the function F
        Instruction *firstInstruction = &F.front().front();
        // create an IRBuilder to insert instructions before the first instruction
        IRBuilder<> builder(firstInstruction);
        
        // Load the current call count, add it, and store it back
        Value *loadedCallCount = builder.CreateLoad(Type::getInt32Ty(context), functionCallCount);
        Value *addedCallCount = builder.CreateAdd(loadedCallCount, ConstantInt::get(Type::getInt32Ty(context), 1));
        builder.CreateStore(addedCallCount, functionCallCount);
    
        string printLog = functionName + " %d\n";
        Value *formatStr = builder.CreateGlobalStringPtr(printLog);
        
        // Insert the printf call
        builder.CreateCall(printfFunc, {formatStr, addedCallCount});

        return PreservedAnalyses::none(); // indicate that the function was modified
    }
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, // API version
        "rpfcc",                 // Plugin name
        LLVM_VERSION_STRING,     // LLVM version
        [](PassBuilder &PB)
        {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>)
                {
                    if (Name == "rpfcc")
                    {
                        FPM.addPass(RPFCC());
                        return true;
                    }
                    return false;
                });
        }};
}
} // namespace llvm