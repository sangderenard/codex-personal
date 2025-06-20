@echo off
setlocal EnableDelayedExpansion

:: Configuration
set "SANDBOX_ROOT=C:\Users\%USERNAME%\sandbox"
set "DEPTH=3"

:: Prepare sandbox root
if exist "%SANDBOX_ROOT%" rd /s /q "%SANDBOX_ROOT%"
md "%SANDBOX_ROOT%"

rem Set the sandbox directory owner before adjusting permissions
icacls "%SANDBOX_ROOT%" /inheritance:r
icacls "%SANDBOX_ROOT%" /grant:r %USERNAME%:(OI)(CI)F /T /C
if %errorlevel% neq 0 (
    echo Error: Failed to grant permissions to %USERNAME% for %SANDBOX_ROOT%.
    exit /B 1
)

:: Build nested directories under sandbox root
set "PREV=%SANDBOX_ROOT%"
for /L %%i in (1,1,%DEPTH%) do (
    set "DEST=%SANDBOX_ROOT%\copy_%%i"
    xcopy "%PREV%" "!DEST!" /E /I /H /C /Y
    set "PREV=!DEST!"
)

:: Validate command line
set "CMDLINE=%*"
echo %CMDLINE% | findstr /R "\<cd\s*\.\."
if %errorlevel%==0 (
    echo Error: 'cd ..' is not allowed.
    exit /B 1
)

:: Launch command under restricted environment
echo Launching sandbox in %SANDBOX_ROOT%...
echo Permissions for %SANDBOX_ROOT%:
icacls "%SANDBOX_ROOT%"

:: Capture the current user and runner information
for /f "tokens=*" %%u in ('whoami /user') do set "environ_user=%%u"
set "runner=%USERNAME%"

:: Print the captured information
echo Running as user: %runner%
echo Environment user: %environ_user%

echo Running command: %CMDLINE%
cd "%SANDBOX_ROOT%"
%CMDLINE% > "%SANDBOX_ROOT%\cmd_output.txt" 2>&1
echo Command executed. Output saved to %SANDBOX_ROOT%\cmd_output.txt
if exist "%SANDBOX_ROOT%\cmd_output.txt" (
    type "%SANDBOX_ROOT%\cmd_output.txt"
) else (
    echo Error: Output file "%SANDBOX_ROOT%\cmd_output.txt" does not exist.
)
endlocal
