**Run-Everything Launcher — Quick User Manual**

Purpose: A one-click Windows launcher that clones (if needed), installs frontend dependencies, builds the native simulator, starts the simulator, and launches the frontend and backend development servers.

File: `scripts\run-everything.bat`

Overview: Double-click `scripts\run-everything.bat` to run the full development startup flow. The script opens separate PowerShell windows for build, simulator, backend, and frontend so you can see live output. It also opens your default browser to `http://localhost:5173` once the servers start.

Prerequisites (must be on PATH)

- `git` — for cloning the repository.
- `node` and `npm` — for frontend development and running Vite/Express commands.
- A C++ toolchain (e.g., `g++` / MinGW or MSVC) — required by `.scripts\build.ps1` to compile `simulator.exe`.
- `make` is optional if your build script uses it; otherwise the included PowerShell build script will invoke `g++` directly.

How to run (recommended)

1. Double-click `scripts\run-everything.bat` from Windows Explorer.
2. OR run from PowerShell to watch messages in the calling terminal:

```powershell
cd 'D:\SCHOOL\Automata\suspicious-filename-detection-automata\scripts'
.\run-everything.bat
```

What the script does (step-by-step)

- Detects script location and chooses project root (handles being run from inside `scripts\`).
- If repository not present, clones `https://github.com/JESREAL1JDL7LUSTRE/suspicious-filename-detection-automata.git`.
- Runs `npm install` in `display/` (the frontend folder).
- Runs the project build script `.scripts\build.ps1` in the project root to compile `simulator.exe`.
- Starts `simulator.exe` in a new PowerShell window (if build succeeded).
- Starts backend (`npm run dev:server`) and frontend (`npm run dev`) each in their own PowerShell windows.
- Opens `http://localhost:5173` in your default browser.

Stopping everything

- Close the PowerShell windows titled "Simulator", "Backend Server", and "Frontend (Vite)" to stop those processes.
- If you started the script from a terminal, press Ctrl+C in that terminal to stop any foreground job.

Troubleshooting

- Build fails / `simulator.exe` not produced:
  - Ensure `g++` (or other compiler) is installed and on PATH. Run `g++ --version`.
  - Open `.scripts\build.ps1` and run it manually from the project root to see compiler errors:

```powershell
cd 'D:\SCHOOL\Automata\suspicious-filename-detection-automata'
powershell -NoProfile -ExecutionPolicy Bypass -File .scripts\build.ps1
```
- `npm install` fails:
  - Check `node`/`npm` versions (`node -v`, `npm -v`).
  - Run `npm install` manually in `display\` and examine output.
- Browser doesn't open:
  - Script attempts to open `http://localhost:5173` after starting servers. If your browser or firewall blocks it, open the URL manually.
- Ports in use (`5173` or backend port): stop the process using the port, or change port in `display/package.json` / server config.

If you prefer a minimal manual run

- Build only (from project root):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .scripts\build.ps1
```
- Run simulator only (after successful build):

```powershell
cd 'D:\SCHOOL\Automata\suspicious-filename-detection-automata'
powershell -NoExit -Command "& '.\simulator.exe'"
```
- Start frontend/backend manually (in `display/`):

```powershell
cd 'D:\SCHOOL\Automata\suspicious-filename-detection-automata\display'
npm install
npm run dev:server    # backend
npm run dev            # frontend
```

Notes & tips

- Run the batch from PowerShell if you want to capture the initial script messages in your terminal rather than relying on the spawned windows.
- Keep the opened windows visible to see runtime logs. If you want logs saved to files, tell me and I can add that option back.
- If you provide this single-file launcher to someone else, include the prerequisites above and verify their PATH contains `git`, `node`, and a C++ compiler.

If you want, I can also add a shortcut generator to create a Desktop shortcut to this `run-everything.bat` or add an option to produce log files. Which would you prefer?
