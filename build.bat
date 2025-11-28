@echo off
REM Build script for Windows CMD
REM Equivalent to running 'make'

set CXX=g++
set CXXFLAGS=-std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser
set TARGET=simulator.exe
set SRCDIR=src
set OBJDIR=obj

REM Create obj directory structure
if not exist "%OBJDIR%\dfa" mkdir "%OBJDIR%\dfa"
if not exist "%OBJDIR%\pda" mkdir "%OBJDIR%\pda"
if not exist "%OBJDIR%\regexparser" mkdir "%OBJDIR%\regexparser"
if not exist "%OBJDIR%\jsonparser" mkdir "%OBJDIR%\jsonparser"

echo Building %TARGET%...

REM Compile source files
echo   Compiling src\main.cpp...
%CXX% %CXXFLAGS% -c src\main.cpp -o obj\main.o
if errorlevel 1 goto :error

echo   Compiling src\regexparser\RegexParser.cpp...
%CXX% %CXXFLAGS% -c src\regexparser\RegexParser.cpp -o obj\regexparser\RegexParser.o
if errorlevel 1 goto :error

echo   Compiling src\pda\PDAModule.cpp...
%CXX% %CXXFLAGS% -c src\pda\PDAModule.cpp -o obj\pda\PDAModule.o
if errorlevel 1 goto :error

echo   Compiling src\dfa\DFAModule.cpp...
%CXX% %CXXFLAGS% -c src\dfa\DFAModule.cpp -o obj\dfa\DFAModule.o
if errorlevel 1 goto :error

echo   Compiling src\jsonparser\JSONParser.cpp...
%CXX% %CXXFLAGS% -c src\jsonparser\JSONParser.cpp -o obj\jsonparser\JSONParser.o
if errorlevel 1 goto :error

REM Link object files
echo   Linking %TARGET%...
%CXX% obj\main.o obj\regexparser\RegexParser.o obj\pda\PDAModule.o obj\dfa\DFAModule.o obj\jsonparser\JSONParser.o -o %TARGET%
if errorlevel 1 goto :error

echo Build complete! Run with: %TARGET%
goto :end

:error
echo Build failed!
exit /b 1

:end

