@echo off
REM FIA Android Forensics Framework - Web UI Launcher
REM Launch the interactive investigation interface

echo.
echo ========================================
echo FIA Android Digital Forensics Framework
echo        Interactive Web UI
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

REM Run the UI
echo Starting Web UI...
echo.
echo The interface will open in your browser automatically.
echo.
python run_ui.py %*

pause
