@echo off
echo Starting vulnerable Log4j application with logging...
echo.

cd vulnerable-simple

REM Option 1: If you have wtee.exe installed
REM java -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar" "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true" SimpleVulnerable 2>&1 | wtee app.log

REM Option 2: Using a loop to display and log (native batch)
(
    java -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar" ^
    "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true" ^
    "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true" ^
    "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true" ^
    SimpleVulnerable 2>&1
) | for /f "delims=" %%A in ('findstr "^"') do (
    echo %%A
    echo %%A >> app.log
)