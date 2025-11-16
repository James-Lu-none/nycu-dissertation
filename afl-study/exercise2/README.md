# Exercise 2: Fuzzing with AFL++ (Problem 2)

```bash
docker pull aflplusplus/aflplusplus
docker run -it --rm -v $(pwd):/src aflplusplus/aflplusplus bash
```

```bash
read -p "Press enter to build the target program..."

# build src with afl-gcc
rm -rf /src/build
mkdir -p /src/build
cd /src/build
CC=/AFLplusplus/afl-clang-lto CXX=/AFLplusplus/afl-clang-lto++ cmake ..
# afl-clang-lto uses link time optimization (LTO) to provide better instrumentation for some programs, especially C++ programs with heavy use of templates. It may produce better results in some cases, but can also be slower than afl-clang-fast.
make

read -p "Press enter to create seed files..."

# create seed files
rm -rf /src/seeds
mkdir -p /src/seeds
for i in {0..4}; do dd if=/dev/urandom of=/src/seeds/seed_$i bs=64 count=10; done
# enter to continue

read -p "Press enter to start fuzzing..."

/AFLplusplus/afl-fuzz -i /src/seeds -o out -m none -d -- /src/build/medium
```

Look familiar? That's because the process to run AFL++ on Problem 2 is identical to the process of running it on Problem 1. These two problems are not something you would come across in the real world, but were written to get you familiar with how AFL++ functions and what it looks like to actually run AFL++. In Problem 3, we will walk you through a simplified version of what you may actually encounter in a real fuzzing project.