@echo off
echo Starting vulnerable Log4j application with logging...
echo Output will be displayed on screen AND saved to app.log
echo.

cd vulnerable-simple

REM Use PowerShell Tee-Object to output to both console and file
powershell -Command "java -cp '.;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar' '-Dcom.sun.jndi.ldap.object.trustURLCodebase=true' '-Dcom.sun.jndi.rmi.object.trustURLCodebase=true' '-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true' SimpleVulnerable 2>&1 | Tee-Object -FilePath app.log"