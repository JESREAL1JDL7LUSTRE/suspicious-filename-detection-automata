# Build & Run Instructions

## Steps to build (make sure to install dependencies first)
1. `npm run build:cpp`
2. `npm run build:frontend`
3. `npm run build:portable`
4. `npm run build:sfx`

### Build all at once
`npm run build:all`

## Steps to run
1. Navigate to `release/sfx`
2. You will see the file called `Suspicious Filename Detector (INSTALLER).exe`
3. Open it and choose a folder where you want to extract or install it. Make sure to <span style="color:red">create a new folder</span>, as it contains many files.
4. After extraction, go to the chosen file path
5. You will see a folder named `Suspicious Filename Detector`
6. Open the folder and run `Suspicious Filename Detector.exe`
7. To uninstall, simply delete the entire folder

---

## If you messed up
1. `Remove-Item -Recurse -Force release`

---

## if you want to run it directly in vscode without building some shi up
1. `cd display`
2. `cd ..`
3. `npm run dev`

---

## Credits / Source
Original automata implementation by [JESREAL1JDL7LUSTRE/suspicious-filename-detection-automata](https://github.com/JESREAL1JDL7LUSTRE/suspicious-filename-detection-automata)

Added Electron wrapper to build standalone executable.