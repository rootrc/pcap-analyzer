@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."

cmake -S "%PROJECT_ROOT%" -B "%PROJECT_ROOT%\build" -G "MinGW Makefiles" -DBUILD_TESTING=OFF

if errorlevel 1 exit /b %errorlevel%

cmake --build "%PROJECT_ROOT%\build"

if errorlevel 1 exit /b %errorlevel%

endlocal
