@echo off
echo ========================================================
echo   Advanced IDS - One-Click Deployment
echo ========================================================
echo.
echo This script will:
echo  1. Install all dependencies
echo  2. Set up directory structure
echo  3. Copy templates to correct location
echo  4. Generate training data
echo  5. Train ML models
echo  6. Start the application
echo.
echo ========================================================
pause

REM Check if Python is installed
echo.
echo [1/7] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)
echo OK - Python found

REM Check current directory
echo.
echo [2/7] Verifying project directory...
if not exist "config.py" (
    echo ERROR: config.py not found!
    echo Please run this script from the advanced_ids directory
    pause
    exit /b 1
)
echo OK - In correct directory: %CD%

REM Install dependencies
echo.
echo [3/7] Installing dependencies...
echo This may take a few minutes...
pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo WARNING: Some dependencies may have failed to install
    echo Trying without --quiet flag...
    pip install -r requirements.txt
)
echo OK - Dependencies installed

REM Create directories
echo.
echo [4/7] Creating directory structure...
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "ml" mkdir ml
if not exist "templates" mkdir templates
if not exist "dashboard\templates" mkdir dashboard\templates
echo OK - Directories created

REM Fix template location
echo.
echo [5/7] Setting up templates...
if exist "dashboard\templates\dashboard.html" (
    copy /Y "dashboard\templates\dashboard.html" "templates\dashboard.html" >nul 2>&1
    echo OK - Template copied to templates folder
) else (
    echo WARNING: dashboard\templates\dashboard.html not found
)

if exist "templates\dashboard_realtime.html" (
    echo OK - Real-time template found
)

REM Generate training data
echo.
echo [6/7] Generating training data...
python ml\trainer.py --generate-data
if %errorlevel% neq 0 (
    echo WARNING: Training data generation failed
    echo You can generate it later with: python ml\trainer.py --generate-data
) else (
    echo OK - Training data generated
)

REM Train models
echo.
echo [7/7] Training ML models (this may take 2-3 minutes)...
python ml\trainer.py --train-once
if %errorlevel% neq 0 (
    echo WARNING: Model training failed
    echo You can train later with: python ml\trainer.py --train-once
) else (
    echo OK - Models trained successfully
)

echo.
echo ========================================================
echo   Setup Complete!
echo ========================================================
echo.
echo The IDS system is ready to run!
echo.
echo Starting the application in 3 seconds...
timeout /t 3 >nul

REM Start the application
echo.
echo ========================================================
echo   Starting Advanced IDS
echo ========================================================
echo.
echo Dashboard will be available at: http://localhost:5000
echo.
echo Press Ctrl+C to stop the application
echo ========================================================
echo.

python app.py

REM If we get here, app has stopped
echo.
echo ========================================================
echo Application stopped
echo ========================================================
pause