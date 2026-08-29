@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."

set "ITERATIONS=%~1"
if "%ITERATIONS%"=="" set "ITERATIONS=100"

cmake -S "%PROJECT_ROOT%" -B "%PROJECT_ROOT%\build" -G "MinGW Makefiles" -DBUILD_TESTING=ON -DRANDOMIZED_ITERATIONS="%ITERATIONS%"

if errorlevel 1 exit /b %errorlevel%

cmake --build "%PROJECT_ROOT%\build" -j2

if errorlevel 1 exit /b %errorlevel%

ctest --test-dir "%PROJECT_ROOT%\build" --progress

if errorlevel 1 exit /b %errorlevel%

endlocal
