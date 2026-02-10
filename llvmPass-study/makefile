CXX = clang++-18
CXXFLAGS = -O0 -fno-inline -S -emit-llvm
LDFLAGS = `llvm-config --cxxflags --ldflags --system-libs --libs core passes`
# Targets
all: rpfcc.so output

rpfcc.so: rpfcc.cpp
	$(CXX) -fPIC -shared rpfcc.cpp -o rpfcc.so $(LDFLAGS)

input.ll: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o input.ll

output.ll: rpfcc.so input.ll
	opt -load-pass-plugin=./rpfcc.so -passes="rpfcc" input.ll -S -o output.ll

output: output.ll
	clang++ -O0 -fno-inline output.ll -o output

clean:
	rm -f rpfcc.so input.ll output.ll output