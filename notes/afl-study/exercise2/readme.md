# exercise2: Fuzzing a Simple Program with AFL++

Phase 3: Analyzing Codebases for potential Vulnerabilities
How to Use Sourcetrail
After the project is built, open Sourcetrail and click New Project. Name the project something relevant and in the "Sourcetrail Project Location" text box, click the three dots on the right and navigate to the directory where your project lives. After the path is listed in the text box, click "Add Source Group" at the bottom of the window.
In the new pop up, select the "CDB" option if it is a C or C++ project. A new window will pop up. Click the three dots in the "Compilation Database" textbox, and navigate to the "compile_commands.json" file within the build folder you created in the target. This will allow the files to be indexed in Sourcetrail.
On a Windows machine, this process is the same, but must be done within the virtual machine.
Once everything is indexed in Sourcetrail, open the project in another program for viewing code (like VS code, sublime, etc.) so you can see the files listed out and can navigate the file tree. This will allow you to glance over code and find things that might be interesting to investigate further using Sourcetrail (Sourcetrail has a search bar, so you can find any function or chunk of code very quickly).
The best way to find potential entry points in your targets is to look for files dealing with inputs from an outside source
This could look like sensors, GPS systems, user inputs, communication modules, etc.
We had success looking at "MAVLink"-related functions and files.
After finding a file that could be of interest, navigate to it in Sourcetrail by looking it up. You will see the functions in the file and the inputs to those functions. You can click through those things to learn more about them.
In general, its good practice to bookmark things in Soucetrail that look interesting so you can come back to them later.

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
CC=/AFLplusplus/afl-clang-fast CXX=/AFLplusplus/afl-clang-fast++ cmake ..
make

read -p "Press enter to create seed files..."

# create seed files
rm -rf /src/seeds
mkdir -p /src/seeds
for i in {0..4}; do dd if=/dev/urandom of=/src/seeds/seed_$i bs=64 count=10; done
# enter to continue

read -p "Press enter to start fuzzing..."

# start fuzzing with afl-fuzz
/AFLplusplus/afl-fuzz -i /src/seeds -o out -m none -d -- /src/build/simple_crash
```

## asm code analysis

```bash
# analyze the asm code of simple_crash (using INTEL syntax)
cd /src/build

# Disassembling Executable Sections
objdump -d -M intel simple_crash > simple_crash_disasm.asm
# interleave source code with assembly  (if compiled with debug symbols)
objdump -d -M intel -S simple_crash > simple_crash_with_source.asm
# Displaying overall file header information, including architecture, file format, and entry point
objdump -f simple_crash > simple_crash_file_header.txt
# Displaying object-specific file header contents, such as program headers
objdump -p simple_crash > simple_crash_object_header.txt
# Listing the section headers, showing details like section type, size, and memory location
objdump -h simple_crash > simple_crash_section_header.txt
# Displaying comprehensive header information, including all headers, section headers, program headers, and the symbol table
objdump -x simple_crash > simple_crash_all_header.txt
# Displaying the hexadecimal contents of all sections
objdump -s simple_crash > simple_crash_section_hex.txt
```