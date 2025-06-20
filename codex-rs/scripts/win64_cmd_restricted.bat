@echo off
setlocal EnableDelayedExpansion

:: Configuration
set "SANDBOX_USER=SandboxUser"
set "SANDBOX_PASS=YourStrongP@ssw0rd"
set "SANDBOX_ROOT=%CD%\sandbox"
set "DEPTH=3"

:: Create the user if needed
net user "%SANDBOX_USER%" "%SANDBOX_PASS%" /add /expires:never /passwordchg:no /passwordreq:yes >nul 2>&1
net localgroup Users "%SANDBOX_USER%" /add >nul 2>&1

:: Prepare sandbox root
if exist "%SANDBOX_ROOT%" rd /s /q "%SANDBOX_ROOT%"
md "%SANDBOX_ROOT%"

:: Build nested directories under sandbox root
set "PREV=%SANDBOX_ROOT%"
for /L %%i in (1,1,%DEPTH%) do (
    set "DEST=%SANDBOX_ROOT%\copy_%%i"
    xcopy "%PREV%" "!DEST!" /E /I /H /C /Y >nul
    set "PREV=!DEST!"
)

:: Validate command line
set "CMDLINE=%*"
echo %CMDLINE% | findstr /R "\<cd\s*\.\." >nul
if %errorlevel%==0 (
    echo Error: 'cd ..' is not allowed.
    exit /B 1
)

:: Launch command under restricted user
echo Launching sandbox as %SANDBOX_USER% in %SANDBOX_ROOT%...
runas /user:%COMPUTERNAME%\%SANDBOX_USER% "cmd.exe /c cd /d \"%SANDBOX_ROOT%\" && %CMDLINE%"

endlocal
