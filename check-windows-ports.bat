@echo off
echo Checking port 8081 accessibility...
echo.
echo === Active Listeners ===
netstat -an | findstr :8081
echo.
echo === Windows Firewall Rules ===
netsh advfirewall firewall show rule name=all | findstr /i "8081"
echo.
echo === Docker Port Mappings ===
docker ps --format "table {{.Names}}\t{{.Ports}}" | findstr 8081
echo.
echo === Test Local Access ===
powershell -Command "Test-NetConnection -ComputerName localhost -Port 8081"
echo.
echo To allow port 8081 through Windows Firewall, run as Administrator:
echo netsh advfirewall firewall add rule name="Log4Shell Lab" dir=in action=allow protocol=TCP localport=8081