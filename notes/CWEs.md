Native Code CVE types （C/C++、Rust）

1. Memory Safety 漏洞（ASan / UBSan / TSan）
CWE-119 Improper Restriction of Operations within Memory Bounds
CWE-120 Classic Buffer Overflow
CWE-121 Stack-Based Buffer Overflow
CWE-122 Heap-Based Buffer Overflow
CWE-124 Out-of-bounds Write
CWE-125 Out-of-bounds Read
CWE-787 Out-of-bounds Write
CWE-788 Out-of-bounds Read

2.  Use-after-free / Double free 類型 (ASan)
CWE-416 Use After Free
CWE-415 Double Free

3. Integer 相關（常用 UBSan/logic fuzzing）
CWE-190 Integer Overflow or Wraparound
CWE-191 Integer Underflow
CWE-681 Incorrect Conversion
CWE-680 Integer Overflow leading to Buffer Overflow

4. Pointer / Memory Mapping 類（ASan / UBSan）
CWE-822 Untrusted Pointer Dereference
CWE-476 NULL Pointer Dereference
CWE-129 Improper Validation of Array Index

5. Concurrency / Race 類（TSan）
CWE-362 Race Condition
CWE-366 TOCTOU（Time-of-check Time-of-use）

6. Undefined Behavior (UBSan)
CWE-758 Undefined Behavior
CWE-469 Use of Pointer Subtraction Incorrectly
CWE-681 Incorrect Conversion

7. Format String / Type Confusion / Bounds Checking 類
CWE-134 Uncontrolled Format String
CWE-843 Type Confusion
CWE-787 / 125 Bounds Checking Error
