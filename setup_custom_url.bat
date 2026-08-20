@echo off
REM ================================================================
REM  Sets up a friendly local URL: vaishnavis-cyberproject.local
REM  instead of the numeric http://127.0.0.1:5000
REM
REM  MUST BE RUN AS ADMINISTRATOR:
REM  Right-click this file -> "Run as administrator"
REM ================================================================

echo Adding vaishnavis-cyberproject.local to your hosts file...
echo 127.0.0.1 vaishnavis-cyberproject.local >> %WINDIR%\System32\drivers\etc\hosts

if %errorlevel% == 0 (
    echo.
    echo SUCCESS! You can now access your project at:
    echo   http://vaishnavis-cyberproject.local:5000
    echo.
    echo (Keep "python app.py" running in another window as usual.)
) else (
    echo.
    echo FAILED - please make sure you right-clicked this file and
    echo chose "Run as administrator", then try again.
)
pause
