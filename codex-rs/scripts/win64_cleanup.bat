@echo off
net user SandboxUser /del >nul 2>&1
rd /s /q "%CD%\sandbox"
