# Running Instructions

This guide explains how to build and run the CS311 Chomsky Hierarchy Security Simulator project.

## Prerequisites

- **C++ Compiler**: `g++` (GNU Compiler Collection)
  - Windows: Install via [MinGW-w64](https://www.mingw-w64.org/) or [MSYS2](https://www.msys2.org/)
  - Linux: `sudo apt-get install g++` (Ubuntu/Debian) or `sudo yum install gcc-c++` (RHEL/CentOS)
  - macOS: `xcode-select --install` or use Homebrew: `brew install gcc`

- **Build Tools** (Optional):
  - `make` - For using the makefile (Linux/Mac/Windows with MSYS2)
  - PowerShell - For Windows build script (included by default on Windows 10+)

## Quick Start

### Option 1: Using Build Scripts (Recommended for Windows)

> **⚠️ WARNING**: If `simulator.exe` is currently running, the build will fail because the file is locked. Close the program before rebuilding.

#### PowerShell (Windows):
```powershell
.\.scripts\build.ps1
.\simulator.exe
```

#### Command Prompt (Windows):
```cmd
.scripts\build.bat
simulator.exe
```

### Option 2: Using Makefile (Linux/Mac/Windows with make)

```bash
make          # Build the project
make run      # Build and run
make clean    # Remove compiled files
```

### Option 3: Manual Build

If you prefer to build manually:

```bash
# Compile source files
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/main.cpp -o obj/main.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/regexparser/RegexParser.cpp -o obj/regexparser/RegexParser.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/pda/PDAModule.cpp -o obj/pda/PDAModule.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/dfa/DFAModule.cpp -o obj/dfa/DFAModule.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/jsonparser/JSONParser.cpp -o obj/jsonparser/JSONParser.o

# Link object files
g++ obj/main.o obj/regexparser/RegexParser.o obj/pda/PDAModule.o obj/dfa/DFAModule.o obj/jsonparser/JSONParser.o -o simulator.exe
```

## Project Structure

```
suspicious-filename-detection-automata/
├── src/                    # Source code
│   ├── main.cpp           # Main program entry point
│   ├── dfa/               # DFA module (Type-3 Regular)
│   ├── pda/               # PDA module (Type-2 Context-Free)
│   ├── regexparser/       # Regex parsing utilities
│   └── jsonparser/        # JSON parsing utilities
├── archive/               # Input data files
│   ├── Malicious_file_trick_detection.jsonl
│   └── tcp_handshake_traces_expanded.jsonl
├── obj/                   # Compiled object files (generated)
├── output/                # Output reports (generated at runtime)
├── .scripts/              # Scripts and utilities
│   ├── build.ps1         # PowerShell build script (Windows)
│   ├── build.bat         # Batch build script (Windows)
│   └── generate_tcp_dataset.py  # Python script for generating TCP dataset
├── makefile              # Build configuration (for make)
└── simulator.exe         # Compiled executable (generated)
```

## What the Program Does

The simulator demonstrates the Chomsky Hierarchy through two security-focused modules:

### Module 1: DFA-based Filename Pattern Detection (Type-3 Regular)
- Detects suspicious filename patterns (`.exe`, `.scr`, `.bat`, `.vbs`, etc.)
- Uses Deterministic Finite Automaton (DFA)
- Reads from: `archive/Malicious_file_trick_detection.jsonl`
- Outputs detection metrics and performance statistics

### Module 2: PDA-based TCP Protocol Validation (Type-2 Context-Free)
- Validates TCP handshake sequences (SYN → SYN-ACK → ACK)
- Uses Pushdown Automaton (PDA) with stack memory
- Reads from: `archive/tcp_handshake_traces_expanded.jsonl`
- Demonstrates context-free language recognition

### Output
- Results are saved to the `output/` directory (created automatically)
- Console output shows detailed execution traces and metrics

## Troubleshooting

### "g++: command not found"
- Install a C++ compiler (see Prerequisites)
- Ensure the compiler is in your system PATH

### "make: command not found"
- Install `make` or use the build scripts (`.scripts/build.ps1` or `.scripts/build.bat`) instead
- On Windows, you can use the PowerShell script without `make`

### "Permission denied" (Linux/Mac)
- Make the executable runnable: `chmod +x simulator` or `chmod +x simulator.exe`

### Build errors
- **"Permission denied" or "Access is denied" when building**: The `simulator.exe` file may be locked because it's currently running. Close the program and try building again.
- Ensure all source files are present in the `src/` directory
- Check that the data files exist in the `archive/` directory
- Verify compiler supports C++17 standard

### Runtime errors
- Ensure `archive/` directory contains the required JSONL files
- Check file paths are correct (program expects relative paths)

## Platform-Specific Notes

### Windows
- Use `.scripts/build.ps1` (PowerShell) or `.scripts/build.bat` (CMD)
- Executable will be `simulator.exe`
- If PowerShell execution is blocked, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### Linux/Mac
- Use `make` or build scripts
- Executable will be `simulator` (no `.exe` extension)
- May need to use `./simulator` to run from current directory

## Clean Build

To remove all compiled files and start fresh:

```bash
# Using make
make clean

# Manual cleanup
rm -rf obj/ simulator.exe    # Linux/Mac
rmdir /s obj simulator.exe   # Windows CMD
Remove-Item -Recurse -Force obj, simulator.exe  # PowerShell
```

## Additional Resources

- [Makefile Documentation](https://www.gnu.org/software/make/manual/)
- [GCC/G++ Documentation](https://gcc.gnu.org/onlinedocs/)
- [C++17 Standard Reference](https://en.cppreference.com/w/cpp/17)

