@echo off
title WAF-Shield Service Installer
cd /d "%~dp0"

:: Auto self-elevation to Administrator
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [THONG BAO] Dang yeu cau quyen Administrator de cai dat Windows Service...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

cls
echo ========================================================
echo   WAF-Shield Enterprise - Cai Dat Windows Service
echo ========================================================
echo.
waf-game.exe -install
echo.
echo De khoi dong dich vu ngay bay gio, hay chay file BAT_SERVICE.bat
echo Hoac he thong se tu dong chay ngam moi khi VPS/Server mo may.
echo.
pause
