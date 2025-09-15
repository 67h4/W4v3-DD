@echo off
ECHO Installing required Python packages for safe_wave_ui.py...

:: Check if Python is installed
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Python is not installed. Please install Python 3.7 or higher and try again.
    PAUSE
    EXIT /B 1
)

:: Upgrade pip to the latest version
ECHO Upgrading pip...
python -m pip install --upgrade pip
IF %ERRORLEVEL% NEQ 0 (
    ECHO Failed to upgrade pip. Continuing with installations...
)

:: Install required packages
ECHO Installing PyQt5...
pip install PyQt5
IF %ERRORLEVEL% NEQ 0 (
    ECHO Failed to install PyQt5. Please check your internet connection or pip configuration.
    PAUSE
    EXIT /B 1
)

ECHO Installing aiohttp...
pip install aiohttp
IF %ERRORLEVEL% NEQ 0 (
    ECHO Failed to install aiohttp. Please check your internet connection or pip configuration.
    PAUSE
    EXIT /B 1
)

:: Run the Python script
ECHO All dependencies installed. Starting safe_wave_ui.py...
python safe_wave_ui.py
IF %ERRORLEVEL% NEQ 0 (
    ECHO Failed to run safe_wave_ui.py. Please ensure the script is in the same directory as this batch file.
    PAUSE
    EXIT /B 1
)

ECHO Script executed successfully.
PAUSE