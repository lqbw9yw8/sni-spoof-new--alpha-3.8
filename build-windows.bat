@echo off
setlocal
cd /d "%~dp0"

echo.
echo === dpi_guard: build Windows exe ===
echo Folder: %CD%
echo.

where cargo >nul 2>&1
if errorlevel 1 (
  echo [ERROR] cargo not found.
  echo Install Rust from https://rustup.rs/  then close this window and run again.
  pause
  exit /b 1
)

echo [1/4] Windows target...
rustup target add x86_64-pc-windows-msvc
if errorlevel 1 (
  echo [ERROR] rustup target add failed. Install Visual Studio Build Tools with "Desktop development with C++".
  pause
  exit /b 1
)

echo [2/4] Checking WinDivert build files...
rem windivert-sys 0.9.3 needs the official DLL, LIB and SYS files at link time.
rem .cargo/config.toml pins WINDIVERT_PATH to this folder for every cargo run
rem (force = true, so a stale WINDIVERT_PATH in your environment is ignored and
rem the build script cannot panic on a path that does not exist). All this
rem script has to do is make sure the three files are really here.
rem They are NOT committed to git - see .gitignore.
if not exist "%CD%\WinDivert.lib" (
  echo WinDivert.lib not found - fetching the pinned official release...
  powershell -NoProfile -ExecutionPolicy Bypass -File "%CD%\scripts\fetch-windivert.ps1" -Arch x64
  if errorlevel 1 (
    echo [ERROR] automatic fetch failed. Download WinDivert 2.2.2 from
    echo   https://github.com/basil00/WinDivert/releases
    echo and copy these three files into %CD% :
    echo   WinDivert.dll  WinDivert.lib  WinDivert64.sys
    pause
    exit /b 1
  )
)
if not exist "%CD%\WinDivert.dll" (
  echo [ERROR] WinDivert.dll missing from %CD%
  exit /b 1
)
if not exist "%CD%\WinDivert.lib" (
  echo [ERROR] WinDivert.lib missing from %CD%
  exit /b 1
)
if not exist "%CD%\WinDivert64.sys" (
  echo [ERROR] WinDivert64.sys missing from %CD%
  exit /b 1
)
echo Using WinDivert files from: %CD%

echo [3/4] cargo build --release ...
cargo build --release --target x86_64-pc-windows-msvc
if errorlevel 1 (
  echo [ERROR] build failed. If you see link.exe, install VS Build Tools C++ workload.
  pause
  exit /b 1
)

set OUT=%CD%\target\x86_64-pc-windows-msvc\release
if not exist "%OUT%\dpi_guard.toml" copy /Y "%CD%\dpi_guard.toml.example" "%OUT%\dpi_guard.toml" >nul
rem WinDivert.dll is needed to start, WinDivert64.sys is the driver it loads.
rem Both live at the repo root after step [2/4], so put them next to the exe.
copy /Y "%CD%\WinDivert.dll"   "%OUT%\WinDivert.dll"   >nul
copy /Y "%CD%\WinDivert64.sys" "%OUT%\WinDivert64.sys" >nul

echo.
echo [4/4] DONE
echo EXE:
echo   %OUT%\dpi_guard.exe
echo   %OUT%\WinDivert.dll
echo   %OUT%\WinDivert64.sys
echo.
echo NEXT:
echo   1. Edit dpi_guard.toml in that same folder
echo      relay_connect_host = your domain   ^(no ping needed^)
echo   2. Right-click dpi_guard.exe - Run as administrator
echo.
pause
