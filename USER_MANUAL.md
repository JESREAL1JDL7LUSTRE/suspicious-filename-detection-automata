# Suspicious Filename Detection Automata — User Manual

Repository: https://github.com/JESREAL1JDL7LUSTRE/suspicious-filename-detection-automata.git

---

**Overview:**
- **Purpose:** This project demonstrates a pipeline of automata-based detectors: DFA-based suspicious filename detection, DFA content scans, and an optional PDA-based TCP trace validator. The software contains a C++ simulator that runs analysis and writes automata artifacts to `output/`, and a React frontend (in `display/`) to run the simulator, stream and visualize output, and run file scans.

**Quick links:**
- Frontend code: `display/` (Vite + React)
- Backend server for the frontend: `display/server.js` (express SSE wrapper)
- Native simulator (C++): sources in `src/` — built artifact: `simulator` (or `simulator.exe` on Windows)
- Output artifacts (JSON, DOT, reports): `output/`

---

**Prerequisites**
- Git (to clone repository)
- Node.js (v18+ recommended) and `npm` (for frontend)
- A C++17 toolchain to build the simulator (one of below):
  - Linux/macOS: `g++` (gcc) or `clang++`
  - Windows: Use MSVC (Visual Studio Developer Tools) or MinGW-w64 / WSL with `g++`
- `make` (optional) — the repository includes a `makefile` that uses `g++`.

Notes for Windows users: The provided `makefile` assumes a POSIX shell. On Windows either use:
- WSL (Windows Subsystem for Linux) and build there, or
- Install MinGW-w64 + MSYS2 and use `make`, or
- Use Visual Studio: open the `src/` sources and build a console executable named `simulator.exe`.

---

1) Clone repository

PowerShell (copy-paste):
```powershell
git clone https://github.com/JESREAL1JDL7LUSTRE/suspicious-filename-detection-automata.git
cd suspicious-filename-detection-automata
```

2) Build the C++ simulator (writes artifacts to `output/` when run)

Option A — Linux / macOS / WSL / MinGW (recommended):
```powershell
# from project root
make
# result: `simulator` (on Unix-like) placed in project root
```

If you don't have `make`, you can run the `g++` command manually (example):
```powershell
g++ -std=c++17 -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser \
  src/main.cpp src/AutomataJSON.cpp src/jsonparser/JSONParser.cpp src/dfa/DFAModule.cpp src/pda/PDAModule.cpp src/regexparser/RegexParser.cpp -o simulator
```

Option B — Windows + Visual Studio (MSVC):
- Create a new Console project and add the `src/` sources or use `cl.exe` from Developer Command Prompt. Ensure C++17 is enabled.

3) Install and run the frontend (display)

PowerShell commands (run from repo root):
```powershell
cd display
npm install
# Start backend server (streams simulator output via SSE) and frontend dev server
# Either run both in parallel (requires `concurrently`) or in two terminals:
npm run dev:server   # starts express SSE backend on http://localhost:3001
npm run dev          # starts Vite dev server (default http://localhost:5173)
```

Tip: `npm run dev:all` will run both the server and the Vite dev server using `concurrently` (if you have it installed via `npm install`).

4) Environment configuration
- The frontend determines where to read automata JSON files from via `VITE_OUTPUT_DIR` (in Vite env). By default, `useOutputDir()` falls back to `../output` (relative to `display/`). When running dev server from the project root this works out-of-the-box.

---

How it works (high level)
- The C++ `simulator` does data loading, builds DFAs and PDAs, performs scans, and writes JSON/DOT files under `output/` (e.g. `automata.json`, `dfa_min_0.json`, `pda.json`, `graph_from_run.dot`, reports, etc.).
- The frontend `display/` has an Express backend (`server.js`) that spawns the simulator (or runs it in scan mode). The server exposes SSE endpoints:
  - POST `/api/run-simulator` — spawn the simulator (no file args) and stream its stdout/stderr as SSE events
  - POST `/api/scan` — spawn the simulator with file paths (scan mode) and stream per-file output
- The React UI listens to SSE events and displays them in a terminal, visualizes automata graphs (JSON) and supports selecting files/folders for scanning.

---

Using the Frontend — Features & Buttons (detailed)

Main layout: header (top), left terminal, main visualization, right-side controls (file upload + scan UI).

Header (`Header` component)
- **Run Simulator / Stop Simulator** (primary button):
  - Label: `Run Simulator` (when not running) or `Stop Simulator` (when running)
  - Action: If no files are selected, clicking runs the simulator via backend `/api/run-simulator` which:
    - Builds automata from bundled datasets in `archive/`, runs DFA content scans and PDA validations, and writes artifacts to `output/`.
  - If files are selected (user added files/folders), the same button becomes the entry to scan mode (see File Upload section).
- **JSON selection dropdown**:
  - Choose which automata JSON to load into the graph visualization. Default list (from `useGraphLoader`): `automata.json`, `pda.json`, `dfa_min_0.json` … `dfa_min_8.json`.
  - Changing selection updates the `selected` file; you must click `Load Automata` to load the chosen file.
- **Load Automata**:
  - Loads the selected JSON from the `output/` directory and converts it to a ReactFlow graph.
  - Disabled while simulator is running. After a successful simulator run this becomes enabled.
- **Reset**:
  - Reset all state (clears terminal, scan results, selected files, graph and mode). Disabled while running.

File upload (`FileUpload` component) and scan controls
- **Add Files**: opens a file picker to select one or more files to scan.
- **Add Folder**: opens a folder selector (uses `webkitdirectory` fallback in supported browsers) — collects all files under the folder.
- **Clear**: clears the current selection. Shows number of selected files in button label when files selected.
- UI note: If no files are selected, clicking Run Simulator uses default datasets packaged with the project. If files are selected, clicking the primary Run button will start a scan instead (POST `/api/scan`) and the frontend will show scan progress in the terminal and visualize visited states.

Scan panel
- Appears when files are selected or when `mode === 'scan'`.
- **Scan X File(s)** (small button shown in the right-side box): runs the selected files through the DFAs (the server launches simulator in scan mode with the file list as arguments). The `FileProcessingIndicator` component shows current file, progress bar and a status badge (SAFE vs SUSPICIOUS) with severity coloring.

Terminal (`Terminal` component)
- Displays streaming output from the backend (SSE). Parsed and colored messages include:
  - State transitions (q0 → q1), Final state, File processing lines like `[1/32] Analyzing: filename`, metrics and `[INFO]/[ERROR]/[WARN]` messages.
- Terminal controls (top-right of terminal):
  - `States (3)` / `All States` toggle: toggles whether state transitions are collapsed or fully shown.
  - `Top`: scroll to top of terminal output.
  - `Down`: scroll to bottom instantly.
  - `Auto Scroll`: toggle auto-scroll on/off (auto-scroll tries to smoothly keep view at bottom; will stop if user scrolls up).

Visualization (`GraphVisualization`)
- Uses `reactflow` to render nodes and edges from the selected JSON file. Node/edge colors update during scan mode: visited states and transitions will be animated and colored according to `safe`/`suspicious` and severity (`high` → red, `medium` → yellow, `low` → orange, `safe` → blue).
- Legend below the graph explains color mapping and counts (Safe vs Suspicious).

File Processing Indicator (`FileProcessingIndicator`)
- Shows current file being processed (parsed from terminal lines like `[idx/total] Analyzing: filename`).
- Shows progress bar, current status badge and pattern if available.

---

Where output files are placed
- After running the simulator (normal mode or scan mode), the program writes many artifacts to `output/` such as:
  - `automata.json` (combined graph)
  - `pda.json`
  - `dfa_min_*.json` and `dfa_content_min_*.json`
  - `*.dot` files (`dfa_min_*.dot`, `pda.dot`, `graph_from_run.dot`)
  - Various `grammar_*.txt`, `dfa_report.txt`, `content_dfa_report.txt` and `pda.json`

The frontend `useGraphLoader()` will load JSONs from the `output/` directory (path resolved via Vite `VITE_OUTPUT_DIR` or auto-detected fallback). If the frontend can't find files, ensure you ran the simulator and that `output/` contains JSON files.

---

Common workflows
- Run whole pipeline and view graphs (default dataset):
  1. Build `simulator` (see step 2).
  2. Start backend server: `cd display; npm run dev:server`.
  3. Start frontend: `cd display; npm run dev`.
  4. In UI: Click `Run Simulator`. Wait for simulator to finish and enable `Load Automata`.
  5. Select a JSON from the dropdown and click `Load Automata`.

- Scan your files/folder:
  1. Open the UI and click `Add Files` / `Add Folder` and choose files.
  2. Click the small `Scan X File(s)` button (or `Run Simulator` when files selected) to start scan.
  3. Watch terminal output and progress; graphs will color visited states as scanning progresses.

---

Troubleshooting
- `simulator` won't start / spawn error in `display/server.js`:
  - Ensure `simulator` executable exists in project root and is executable. On Windows ensure it's `simulator.exe` or update `server.js` to point to correct executable path.
  - If you build with Visual Studio, copy the generated `simulator.exe` to the project root.
- Frontend can't load automata JSONs:
  - Confirm `output/` contains JSON files after simulator run.
  - Check console for `useOutputDir()` computed path and adjust `VITE_OUTPUT_DIR` if necessary.
- SSE disconnects / blank terminal:
  - Network proxies or corporate firewalls can close streaming connections. Check `display/server.js` logs on the server terminal.
  - Server `keepalive` pings are sent every 30s to keep the connection alive.
- Windows build problems:
  - We recommend building with WSL or MinGW if you want to keep the `make` experience. For MSVC, open a Developer Command Prompt and compile using `cl.exe` (enable /std:c++17) or use Visual Studio solution import.

---

Developer notes (brief)
- The frontend receives streaming SSE events with JSON objects: `{ type: 'stdout'|'stderr'|'start'|'end'|'error', message, code? }`.
- `useFileScan()` parses `[i/N] Analyzing:` lines and `✓ Result: SUSPICIOUS (pattern)` lines to construct `ScanResult[]` and `VisitedState[]` used by the graph visualization.

---

Contributing / Extending
- To add new automata artifacts or patterns, edit `src/dfa/DFAModule.*`, recompile the simulator and re-run.
- To change UI text/labels, edit `display/src/components/*`.

---

If you'd like, I can also:
- Add this `USER_MANUAL.md` to a `docs/` folder and update `display/README.md` with quick-start commands.
- Create a small PowerShell script `scripts/build-and-run.ps1` that automates build and dev server startup for Windows.

---

End of manual.
