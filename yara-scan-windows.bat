@echo off
setlocal enabledelayedexpansion

echo =====================================
echo Log4Shell YARA Scanner for Windows
echo =====================================
echo.

REM Set YARA executable path (adjust if needed)
set YARA_PATH=yara64.exe
set RULES_PATH=%~dp0detection-rules

REM Check if YARA exists
where %YARA_PATH% >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] YARA not found in PATH. Please install YARA first.
    echo Download from: https://github.com/virustotal/yara/releases
    echo.
    pause
    exit /b 1
)

REM Set scan paths
set /p SCAN_PATH="Enter path to scan (or press Enter for current directory): "
if "%SCAN_PATH%"=="" set SCAN_PATH=%CD%

echo.
echo Scan Configuration:
echo - Path: %SCAN_PATH%
echo - Rules: %RULES_PATH%\log4shell.yar
echo - Enhanced Rules: %RULES_PATH%\log4shell-enhanced.yar
echo.

REM Create temp directory for filtered files
set TEMP_SCAN=%TEMP%\yara_scan_%RANDOM%
mkdir "%TEMP_SCAN%" 2>nul

echo [1/4] Collecting high-priority log files...
REM High priority extensions
for %%e in (log txt out err json xml access error) do (
    echo   - Scanning *.%%e files...
    for /r "%SCAN_PATH%" %%f in (*.%%e) do (
        echo %%f >> "%TEMP_SCAN%\files_to_scan.txt"
    )
)

echo [2/4] Collecting web server logs...
REM Common log directories on Windows
for %%d in (
    "C:\inetpub\logs\LogFiles"
    "C:\Windows\System32\LogFiles"
    "C:\ProgramData\Apache*\logs"
    "C:\ProgramData\nginx\logs"
    "C:\Program Files\Apache*\logs"
    "C:\Program Files (x86)\Apache*\logs"
    "%SCAN_PATH%\logs"
) do (
    if exist "%%~d" (
        echo   - Checking %%~d...
        for /r "%%~d" %%f in (*) do (
            echo %%f >> "%TEMP_SCAN%\files_to_scan.txt"
        )
    )
)

echo [3/4] Collecting Java-related files...
for %%e in (jar war ear properties class jsp jspx java) do (
    echo   - Scanning *.%%e files...
    for /r "%SCAN_PATH%" %%f in (*.%%e) do (
        echo %%f >> "%TEMP_SCAN%\files_to_scan.txt"
    )
)

echo [4/4] Running YARA scan...
echo.

REM Count files
for /f %%a in ('type "%TEMP_SCAN%\files_to_scan.txt" 2^>nul ^| find /c /v ""') do set FILE_COUNT=%%a
echo Total files to scan: %FILE_COUNT%
echo.

REM Run YARA scan with standard rules
echo === Scanning with standard rules ===
if exist "%RULES_PATH%\log4shell.yar" (
    %YARA_PATH% -r "%RULES_PATH%\log4shell.yar" "%SCAN_PATH%" 2>nul | findstr /v "^$"
) else (
    echo [WARNING] Standard rules not found at %RULES_PATH%\log4shell.yar
)

echo.
echo === Scanning with enhanced rules ===
if exist "%RULES_PATH%\log4shell-enhanced.yar" (
    %YARA_PATH% -r "%RULES_PATH%\log4shell-enhanced.yar" "%SCAN_PATH%" 2>nul | findstr /v "^$"
) else (
    echo [WARNING] Enhanced rules not found at %RULES_PATH%\log4shell-enhanced.yar
)

REM Cleanup
del "%TEMP_SCAN%\files_to_scan.txt" 2>nul
rmdir "%TEMP_SCAN%" 2>nul

echo.
echo =====================================
echo Scan Complete
echo =====================================
echo.
echo Scanned extensions:
echo - Logs: .log, .txt, .out, .err
echo - Web: .json, .xml, .jsp, .jspx
echo - Java: .jar, .war, .ear, .class, .properties
echo.
echo For more thorough scanning, use:
echo   %YARA_PATH% -r "%RULES_PATH%\log4shell-enhanced.yar" "%SCAN_PATH%" -g -s
echo.
pause