# Add .gitignore and Windows Build Scripts

## Summary
This PR adds essential project configuration files to improve the development workflow and make the project more accessible to Windows users.

## Changes

### Added Files
- **`.gitignore`** - Excludes build artifacts, compiled binaries, and IDE-specific files from version control
- **`build.ps1`** - PowerShell build script for Windows users (no `make` required)
- **`build.bat`** - Batch build script for Windows Command Prompt users
- **`introductions/RUNNING_INSTRUCTIONS.md`** - Comprehensive guide for building and running the project

### Modified Files
- None (this PR only adds new files)

## Motivation

1. **Repository Cleanliness**: The `.gitignore` prevents committing compiled binaries (`simulator.exe`) and object files (`obj/`), which are platform-specific and can be regenerated from source.

2. **Windows Accessibility**: Many Windows users don't have `make` installed. The build scripts (`build.ps1` and `build.bat`) allow Windows users to build the project using only `g++`, which is more commonly available.

3. **Documentation**: Added clear running instructions to help new contributors get started quickly.

## Benefits

- ✅ Reduces repository size by excluding binaries
- ✅ Prevents merge conflicts from compiled files
- ✅ Makes the project accessible to Windows users without `make`
- ✅ Provides clear documentation for new contributors
- ✅ Follows standard C++ project practices

## Testing

- [x] Verified `build.ps1` successfully compiles the project on Windows
- [x] Verified `build.bat` successfully compiles the project on Windows
- [x] Verified `.gitignore` correctly excludes build artifacts
- [x] Verified generated executable runs correctly
- [x] Tested on Windows 10 with PowerShell

## Usage

After merging, users can build the project using:

**Windows (PowerShell):**
```powershell
.\build.ps1
.\simulator.exe
```

**Windows (CMD):**
```cmd
build.bat
simulator.exe
```

**Linux/Mac (with make):**
```bash
make
./simulator
```

## Files to Review

- `.gitignore` - Standard C++ project exclusions
- `build.ps1` - PowerShell build automation
- `build.bat` - Batch file build automation
- `introductions/RUNNING_INSTRUCTIONS.md` - Complete running guide

## Notes

- The `simulator.exe` file should be removed from git tracking after this PR is merged (using `git rm --cached simulator.exe`)
- Build scripts are equivalent to the existing `makefile` functionality
- All build methods produce the same executable output

