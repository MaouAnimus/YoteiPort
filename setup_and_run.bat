@echo off
setlocal enabledelayedexpansion

echo ============================================================================
echo  YoteiPort - Experimental Native PC Runtime ^& Asset Pipeline Setup
echo  Target: Ghost of Yotei (PS5 - PPSA26344 v02.002.000)
echo ============================================================================
echo.

set "DUMP_DIR=%~1"
if "%DUMP_DIR%"=="" (
    if exist "%~dp0PPSA26344\PPSA26344-app\eboot.bin" (
        set "DUMP_DIR=%~dp0PPSA26344\PPSA26344-app"
    ) else (
        echo [!] Usage: setup_and_run.bat "C:\Path\To\Your\PPSA26344-app"
        echo     Please provide the path to your legally dumped PPSA26344-app folder
        echo     containing eboot.bin, ampr_emu.index, and cache_ps5\.
        exit /b 1
    )
)

if not exist "%DUMP_DIR%\eboot.bin" (
    echo [!] Error: eboot.bin not found in "%DUMP_DIR%"
    exit /b 1
)

echo [*] Step 1/3: Extracting decrypted PS5 SELF/SPRX modules to ELF64...
python "%~dp0tools\unself.py" "%DUMP_DIR%\eboot.bin" "%~dp0extracted_elf\eboot.elf"
if exist "%DUMP_DIR%\fakelib\libSceAgc.sprx" (
    python "%~dp0tools\unself.py" "%DUMP_DIR%\fakelib\libSceAgc.sprx" "%~dp0extracted_elf\libSceAgc.elf"
)
if exist "%DUMP_DIR%\fakelib\libSceAgcDriver.sprx" (
    python "%~dp0tools\unself.py" "%DUMP_DIR%\fakelib\libSceAgcDriver.sprx" "%~dp0extracted_elf\libSceAgcDriver.elf"
)
if exist "%DUMP_DIR%\fakelib\libSceAmpr.sprx" (
    python "%~dp0tools\unself.py" "%DUMP_DIR%\fakelib\libSceAmpr.sprx" "%~dp0extracted_elf\libSceAmpr.elf"
)

echo.
echo [*] Step 2/3: Building C++20 Native HLE Runtime (yotei_runtime.exe)...
set "VCVARS="
for %%P in (
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) do (
    if exist %%P set "VCVARS=%%~P"
)

if "%VCVARS%"=="" (
    echo [!] Visual Studio 2022 vcvars64.bat not found. Please install VS 2022 C++ Build Tools.
    exit /b 1
)

call "%VCVARS%" >nul
cmake -S "%~dp0." -B "%~dp0build" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "%~dp0build"
if errorlevel 1 (
    echo [!] Build failed.
    exit /b 1
)

echo.
echo [*] Step 3/3: Launching YoteiPort Native x86-64 HLE Runtime...
"%~dp0build\yotei_runtime.exe" "%~dp0extracted_elf\eboot.elf" "%~dp0docs\nid_resolution_table.json"
