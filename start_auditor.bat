@echo off
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
title SystemAuditor Enterprise — Zero-Trust OS Compliance Platform
cd /d "%~dp0"
python "%~dp0run_system.py" %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Wystapil blad podczas uruchamiania. Sprawdz komunikaty powyzej.
    pause
)
