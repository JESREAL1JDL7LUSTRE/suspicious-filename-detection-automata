# Setup and Running Instructions

This guide explains how to set up and run the CS311 Chomsky Hierarchy Security Simulator project, including both the C++ backend and the React frontend.

## Prerequisites

### C++ Backend
- **C++ Compiler**: `g++` (GNU Compiler Collection)
  - Windows: Install via [MinGW-w64](https://www.mingw-w64.org/) or [MSYS2](https://www.msys2.org/)
  - Linux: `sudo apt-get install g++` (Ubuntu/Debian) or `sudo yum install gcc-c++` (RHEL/CentOS)
  - macOS: `xcode-select --install` or use Homebrew: `brew install gcc`

- **Build Tools** (Optional):
  - `make` - For using the makefile (Linux/Mac/Windows with MSYS2)
  - PowerShell - For Windows build script (included by default on Windows 10+)

### Frontend
- **Node.js**: Version 16 or higher
  - Download from [nodejs.org](https://nodejs.org/)
  - Verify installation: `node --version` and `npm --version`

## Project Structure

```
suspicious-filename-detection-automata/
├── src/                    # C++ source code
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
├── display/              # Frontend visualization (React + TypeScript)
│   ├── src/              # React source code
│   ├── server.js         # Node.js backend server
│   └── package.json      # Frontend dependencies
├── makefile              # Build configuration (for make)
└── simulator.exe         # Compiled executable (generated)
```

## Setup

### Step 1: Build the C++ Simulator

> **⚠️ WARNING**: If `simulator.exe` is currently running, the build will fail because the file is locked. Close the program before rebuilding.

#### Option 1: Using Build Scripts (Recommended for Windows)

**PowerShell (Windows):**
```powershell
.\.scripts\build.ps1
```

**Command Prompt (Windows):**
```cmd
.scripts\build.bat
```

#### Option 2: Using Makefile (Linux/Mac/Windows with make)

```bash
make          # Build the project
make run      # Build and run
make clean    # Remove compiled files
```

#### Option 3: Manual Build

If you prefer to build manually:

```bash
# Compile source files
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/main.cpp -o obj/main.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/AutomataJSON.cpp -o obj/AutomataJSON.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/regexparser/RegexParser.cpp -o obj/regexparser/RegexParser.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/pda/PDAModule.cpp -o obj/pda/PDAModule.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/dfa/DFAModule.cpp -o obj/dfa/DFAModule.o
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/jsonparser/JSONParser.cpp -o obj/jsonparser/JSONParser.o

# Link object files
g++ obj/main.o obj/AutomataJSON.o obj/regexparser/RegexParser.o obj/pda/PDAModule.o obj/dfa/DFAModule.o obj/jsonparser/JSONParser.o -o simulator.exe
```

### Step 2: Setup Frontend

1. Navigate to the display directory:
```bash
cd display
```

2. Install dependencies:
```bash
npm install
```

This will install:
- `express` - Backend server
- `cors` - CORS support
- `concurrently` - Run frontend and backend together
- React, TypeScript, Vite, and other frontend dependencies

## Running the Application

### Option A: Run from Frontend (Recommended)

The frontend includes an integrated terminal that can run the C++ simulator directly from the web interface.

**Run both frontend and backend together:**
```bash
cd display
npm run dev:all
```

This starts:
- Backend server on `http://localhost:3001`
- Frontend dev server on `http://localhost:5173`

**Or run separately:**

Terminal 1 (Backend):
```bash
cd display
npm run dev:server
```

Terminal 2 (Frontend):
```bash
cd display
npm run dev
```

**Usage:**
1. Open `http://localhost:5173` in your browser
2. Click **"Run Simulator"** button
3. Watch the terminal output on the left side with real-time streaming
4. After completion, click **"Load Automata"** to view the generated graphs
5. Use **"Stop Simulator"** to cancel if needed

### Option B: Run C++ Simulator Directly

If you prefer to run the simulator from the command line:

**Windows:**
```powershell
.\simulator.exe
```

**Linux/Mac:**
```bash
./simulator
# or
make run
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
- JSON files are generated for graph visualization:
  - `automata.json` - Combined automata
  - `pda.json` - PDA visualization
  - `dfa_0.json` through `dfa_4.json` - Individual DFA visualizations

## Frontend Features

- **Run Simulator Button**: Execute the C++ backend from the frontend
- **Live Terminal Output**: See real-time output from the simulator with:
  - Progressive typing effect
  - Color-coded messages (INFO, SUCCESS, ERROR, etc.)
  - Smart parsing of headers, tables, and metrics
- **Graph Visualization**: Interactive ReactFlow visualization of automata
- **File Selector**: Choose which JSON file to visualize
- **Load Automata Button**: Loads graphs after simulator completes (disabled until successful run)

## Architecture

- **Frontend** (React + TypeScript): `display/src/`
  - Components: `Header.tsx`, `Terminal.tsx`, `GraphVisualization.tsx`
  - Hooks: `useSimulator.ts`, `useGraphLoader.ts`, `useOutputDir.ts`
- **Backend API** (Node.js/Express): `display/server.js`
  - Server-Sent Events (SSE) for streaming output
  - Spawns and manages C++ simulator process
- **API Proxy**: Configured in `vite.config.ts` to proxy `/api/*` to backend

## Troubleshooting

### C++ Build Issues

**"g++: command not found"**
- Install a C++ compiler (see Prerequisites)
- Ensure the compiler is in your system PATH

**"make: command not found"**
- Install `make` or use the build scripts (`.scripts/build.ps1` or `.scripts/build.bat`) instead
- On Windows, you can use the PowerShell script without `make`

**"Permission denied" (Linux/Mac)**
- Make the executable runnable: `chmod +x simulator` or `chmod +x simulator.exe`

**Build errors**
- **"Permission denied" or "Access is denied" when building**: The `simulator.exe` file may be locked because it's currently running. Close the program and try building again.
- Ensure all source files are present in the `src/` directory
- Check that the data files exist in the `archive/` directory
- Verify compiler supports C++17 standard

**Runtime errors**
- Ensure `archive/` directory contains the required JSONL files
- Check file paths are correct (program expects relative paths)

### Frontend Issues

**"Failed to start simulator"**
- Make sure `simulator.exe` exists in the project root
- Run `.\.scripts\build.ps1` to build it first
- Ensure the simulator was built successfully

**"Connection refused" or API errors**
- Make sure the backend server is running (`npm run dev:server`)
- Check that port 3001 is not in use
- Verify the backend server started without errors

**Terminal not showing output**
- Check browser console for errors (F12)
- Verify the backend server is running and accessible
- Check that the simulator process is spawning correctly (check backend terminal logs)

**"Load Automata" button disabled**
- The button is only enabled after a successful simulator run
- Run the simulator first using the "Run Simulator" button
- Check terminal output for any errors

## Platform-Specific Notes

### Windows
- Use `.scripts/build.ps1` (PowerShell) or `.scripts/build.bat` (CMD)
- Executable will be `simulator.exe`
- If PowerShell execution is blocked, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- Paths with spaces are automatically handled by the backend server

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
- [React Documentation](https://react.dev/)
- [Vite Documentation](https://vitejs.dev/)
- [ReactFlow Documentation](https://reactflow.dev/)
