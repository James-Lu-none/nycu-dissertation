# attempt 1: 先使用 opt 產生 LLVM IR，再用 clang++ 編譯成可執行檔
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

# attempt 2: 直接使用 clang++ 一次完成編譯與連結，讓 Clang 處理 DFSAN 的 Runtime
# CXX = clang++-18
# # 這裡需要確保編譯 Pass 本身時包含 LLVM 的 Headers
# CXXFLAGS_PASS = -fPIC -shared `llvm-config --cxxflags`
# LDFLAGS_PASS = `llvm-config --ldflags --system-libs --libs core passes`

# # 目標程式的 Flag
# # 注意：要把 -fpass-plugin 掛在編譯命令中

# all: rpfcc.so output

# # 編譯你的 LLVM Pass
# rpfcc.so: rpfcc.cpp
# 	$(CXX) $(CXXFLAGS_PASS) rpfcc.cpp -o rpfcc.so $(LDFLAGS_PASS)

# # 直接使用 clang++ 一次完成編譯與連結，讓 Clang 處理 DFSAN 的 Runtime
# output: rpfcc.so main.cpp
# 	$(CXX) -O0 -fno-inline -fsanitize=dataflow -fpass-plugin=./rpfcc.so main.cpp -o output

# clean:
# 	rm -f rpfcc.so output
	
	
# attempt 3: 直接使用 clang++ 一次完成編譯與連結，讓 Clang 處理 DFSAN 的 Runtime，並且使用 -Xclang 來載入 Pass
# CXX = clang++-18
# CXXFLAGS = -O0 -fno-inline -S -emit-llvm
# LDFLAGS = `llvm-config --cxxflags --ldflags --system-libs --libs core passes`
# # Targets
# all: rpfcc.so output

# rpfcc.so: rpfcc.cpp
# 	$(CXX) -fPIC -shared rpfcc.cpp -o rpfcc.so $(LDFLAGS)

# output: main.cpp
# 	clang++ -Xclang -load -Xclang ./rpfcc.so \
# 			-Xclang -add-plugin -Xclang rpfcc \
# 			-O0 -fno-inline -fsanitize=dataflow main.cpp -o output
# clean:
# 	rm -f rpfcc.so input.ll output.ll output