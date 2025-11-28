# Build script for Windows PowerShell
# Equivalent to running 'make'

$CXX = "g++"
$CXXFLAGS = @("-std=c++17", "-Wall", "-Wextra", "-O2", "-I./src", "-I./src/dfa", "-I./src/pda", "-I./src/regexparser", "-I./src/jsonparser")
$TARGET = "simulator.exe"
$SRCDIR = "src"
$OBJDIR = "obj"

# Source files
$SOURCES = @(
    "$SRCDIR/main.cpp",
    "$SRCDIR/regexparser/RegexParser.cpp",
    "$SRCDIR/pda/PDAModule.cpp",
    "$SRCDIR/dfa/DFAModule.cpp",
    "$SRCDIR/jsonparser/JSONParser.cpp"
)

# Create obj directory structure if it doesn't exist
if (-not (Test-Path "$OBJDIR/dfa")) { New-Item -ItemType Directory -Path "$OBJDIR/dfa" -Force | Out-Null }
if (-not (Test-Path "$OBJDIR/pda")) { New-Item -ItemType Directory -Path "$OBJDIR/pda" -Force | Out-Null }
if (-not (Test-Path "$OBJDIR/regexparser")) { New-Item -ItemType Directory -Path "$OBJDIR/regexparser" -Force | Out-Null }
if (-not (Test-Path "$OBJDIR/jsonparser")) { New-Item -ItemType Directory -Path "$OBJDIR/jsonparser" -Force | Out-Null }

Write-Host "Building $TARGET..." -ForegroundColor Green

# Compile each source file to object file
$OBJECTS = @()
foreach ($source in $SOURCES) {
    $objFile = $source -replace "$SRCDIR/", "$OBJDIR/" -replace "\.cpp$", ".o"
    $OBJECTS += $objFile
    
    Write-Host "  Compiling $source..." -ForegroundColor Yellow
    & $CXX @CXXFLAGS -c $source -o $objFile
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error compiling $source" -ForegroundColor Red
        exit 1
    }
}

# Link object files into executable
Write-Host "  Linking $TARGET..." -ForegroundColor Yellow
& $CXX @OBJECTS -o $TARGET
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error linking $TARGET" -ForegroundColor Red
    exit 1
}

Write-Host "Build complete! Run with: .\$TARGET" -ForegroundColor Green

