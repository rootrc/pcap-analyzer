@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."

if not defined CMAKE_BUILD_TYPE set "CMAKE_BUILD_TYPE=Release"

cmake -S "%PROJECT_ROOT%" -B "%PROJECT_ROOT%\build" -G "MinGW Makefiles" -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE="%CMAKE_BUILD_TYPE%"

if errorlevel 1 exit /b %errorlevel%

cmake --build "%PROJECT_ROOT%\build"

if errorlevel 1 exit /b %errorlevel%

endlocal
