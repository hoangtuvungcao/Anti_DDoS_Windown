@echo off
title WAF-Shield Service Uninstaller
cd /d "%~dp0"

:: Auto self-elevation to Administrator
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [THONG BAO] Dang yeu cau quyen Administrator...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

cls
echo ========================================================
echo   WAF-Shield Enterprise - Go Bo Windows Service
echo ========================================================
echo.
waf-game.exe -uninstall
echo.
pause
