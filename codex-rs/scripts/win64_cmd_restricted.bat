@echo off
setlocal EnableDelayedExpansion

:: Configuration
set "SANDBOX_USER=SandboxUser"
set "SANDBOX_PASS=YourStrongP@ssw0rd"
set "SANDBOX_ROOT=%CD%\sandbox"
set "DEPTH=3"

:: Create the user if needed
net user "%SANDBOX_USER%" "%SANDBOX_PASS%" /add /Y /expires:never /passwordchg:no /passwordreq:yes
net localgroup Users "%SANDBOX_USER%" /add /Y

:: Prepare sandbox root
if exist "%SANDBOX_ROOT%" rd /s /q "%SANDBOX_ROOT%"
md "%SANDBOX_ROOT%"

icacls "%SANDBOX_ROOT%" /inheritance:r
icacls "%SANDBOX_ROOT%" /grant:r %SANDBOX_USER%:(OI)(CI)F
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

:: Launch command under restricted user
echo Launching sandbox as %SANDBOX_USER% in %SANDBOX_ROOT%...
echo Permissions for %SANDBOX_ROOT%:
icacls "%SANDBOX_ROOT%"
whoami
echo Running command: %CMDLINE%
runas /user:%COMPUTERNAME%\%SANDBOX_USER% "cd \"%SANDBOX_ROOT%\"; %CMDLINE% > \"%SANDBOX_ROOT%\\cmd_output.txt\" 2>&1"
echo Command executed. Output saved to %SANDBOX_ROOT%\cmd_output.txt
if exist "%SANDBOX_ROOT%\cmd_output.txt" (
    type "%SANDBOX_ROOT%\cmd_output.txt"
) else (
    echo Error: Output file "%SANDBOX_ROOT%\cmd_output.txt" does not exist.
)
endlocal
