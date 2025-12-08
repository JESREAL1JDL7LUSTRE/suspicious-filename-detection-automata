# Suspicious Filename Detector — User Manual (Option 2)

**Standalone Application with Self-Extracting Installer**

---

## Overview

The **Suspicious Filename Detector** is a standalone Windows application that scans files and folders for suspicious filename patterns. 

**This is Option 2** — a portable executable version with a self-extracting installer built using Electron and 7-Zip, requiring no additional software installation.

> **Note:** If you prefer the development environment, see Option 1 documentation for using the `run-everything.bat` launcher.

---

## Download

**Pre-built Installer:** [Download](https://drive.google.com/drive/folders/1c1QoPBVeMr7HVps5rsW5NU2sXTjHZrDe?usp=sharing)

---

## System Requirements

- **Operating System:** Windows 10 or later (64-bit)
- **Disk Space:** ~150 MB for installation
- **No Additional Software Required:** No Node.js, Git, or development tools needed

---

## Installation

### Step 1: Locate the Installer
- Find the file: **`Suspicious Filename Detector (INSTALLER).exe`**
- This file is located in the `release/sfx/` folder

### Step 2: Run the Installer
1. **Double-click** `Suspicious Filename Detector (INSTALLER).exe`
2. A 7-Zip self-extracting window will appear

### Step 3: Choose Installation Location
1. Click **Browse** or type a destination path
2. ⚠️ **IMPORTANT:** You must specify or create a **dedicated folder** for the application
   - The installer extracts many files directly to the chosen location
   - It does NOT automatically create a subfolder
   - **Recommended approach:**
     - Create a new folder first (e.g., `SuspiciousDetector\` or `FilenameScanner\`)
     - Choose that empty folder as the extraction path
   - **Examples of good paths:**
     - `C:\Program Files\SuspiciousFilenameDetector\`
     - `D:\PortableApps\FilenameChecker\`
     - `C:\Users\YourName\Tools\FileScanner\`
   - ⚠️ **DO NOT** extract to:
     - Desktop directly
     - Any folder with existing files
     - Root of C:\ drive

### Step 4: Extract
1. Click **Extract**
2. Wait for extraction to complete (10-30 seconds)
3. Navigate to your chosen folder — you'll see multiple files and folders extracted there

---

## Running the Application

### Step 1: Navigate to Installation Folder
- Open the folder where you extracted the files
- You should see files like `Suspicious Filename Detector.exe`, `resources/`, `locales/`, etc.

### Step 2: Launch
1. Find **`Suspicious Filename Detector.exe`**
2. **Double-click** to launch the application
3. The application window will open

---

## Using the Application

### Main Interface

**Header Controls:**
- **Run Simulator**: Starts analysis with built-in sample files
- **JSON Selection Dropdown**: Choose which automata to visualize
- **Load Automata**: Loads selected automata graph
- **Reset**: Clears all data and resets the application

**File Upload Panel (Right):**
- **Add Files**: Select individual files to scan
- **Add Folder**: Select entire folder for scanning
- **Clear**: Remove selected files
- **Scan X File(s)**: Start scanning selected files

**Terminal (Left):**
- Real-time scanning progress
- Detection results and state transitions
- Auto-scrolling output

**Visualization (Center):**
- Interactive graph of detection automata
- Color-coded results:
  - 🔵 **Blue**: Safe
  - 🟡 **Yellow**: Medium-risk suspicious
  - 🟠 **Orange**: Low-risk suspicious
  - 🔴 **Red**: High-risk suspicious

---

## Scanning Files

### Scan Your Files
1. Click **Add Files** or **Add Folder**
2. Select files/folder to scan
3. Click **Scan X File(s)**
4. View results in terminal and graph

### Scan Results
- **✅ SAFE**: No suspicious patterns detected
- **⚠️ SUSPICIOUS**: Potentially dangerous pattern found
  - **High**: Strong malicious indicators (e.g., double extensions)
  - **Medium**: Common phishing patterns
  - **Low**: Minor suspicious characteristics

---

## Uninstallation

1. Close the application if running
2. Navigate to your installation folder (the folder you chose during extraction)
3. **Delete the entire folder** and all its contents
4. Empty Recycle Bin

**No registry changes or system modifications** — complete removal by folder deletion.

---

## Troubleshooting

### Application Won't Start
- Right-click `Suspicious Filename Detector.exe` → **Run as Administrator**
- Check antivirus software isn't blocking it
- Re-extract the installer to a fresh, empty folder

### "File Not Found" Errors
- Ensure all files were extracted properly
- Don't move individual files — keep folder structure intact
- Re-run installer if files are missing

### Files Scattered Everywhere
- **Problem:** You extracted to Desktop or Downloads and now have many files mixed with your other files
- **Solution:** Delete all extracted files, create a new dedicated folder, and re-extract there

### Blank Screen or No Output
- Click **Reset** and try again
- Restart the application
- Check antivirus isn't blocking the detection engine

### Slow Performance
- Large folders (1000+ files) take time
- Scan smaller batches

---

## Privacy & Security

- ✅ All processing is done locally on your computer
- ✅ No internet connection required
- ✅ No data uploaded or shared
- ✅ Portable — runs entirely from installation folder
- ✅ No system registry modifications

---

## Credits

**Original Implementation:**  
[JESREAL1JDL7LUSTRE/suspicious-filename-detection-automata](https://github.com/JESREAL1JDL7LUSTRE/suspicious-filename-detection-automata)

**Electron Wrapper:**  
Added standalone executable with 7-Zip self-extracting installer for easy distribution and portability.

---

## Quick Reference

| Task | Steps |
|------|-------|
| **Install** | Run installer → Create/choose empty folder → Extract |
| **Launch** | Open installation folder → Run `.exe` file |
| **Scan** | Add Files/Folder → Click Scan |
| **Uninstall** | Delete installation folder |

---

**Version:** 1.0  
**Last Updated:** December 2025

---