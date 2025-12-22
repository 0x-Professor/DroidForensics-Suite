@echo off
REM FIA Android Forensics Framework - Windows Launcher
REM Run the forensic investigation agent

echo.
echo ========================================
echo FIA Android Digital Forensics Framework
echo ========================================
echo.

REM Check for Python
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found. Please install Python 3.13+
    pause
    exit /b 1
)

REM Check for virtual environment
if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
)

REM Run the forensics agent
echo Starting Forensic Investigation Agent...
echo.
python run_forensics.py

pause
