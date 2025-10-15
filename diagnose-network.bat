@echo off
echo === Check what IP the Java app is actually listening on ===
netstat -an | findstr :8081
echo.
echo === Your network interfaces ===
ipconfig | findstr /i "ipv4"
echo.
echo === Test if port responds locally ===
curl -I http://localhost:8081
echo.
echo === Check if Windows is blocking ===
powershell -Command "Get-NetFirewallProfile | Select Name, Enabled"
echo.
echo === Check if Java is listening on specific interface only ===
echo If netstat shows 127.0.0.1:8081 instead of 0.0.0.0:8081, that's the problem
echo.
echo === Also check: ===
echo 1. Is your router/firewall blocking port 8081?
echo 2. Are you behind NAT? Need port forwarding?
echo 3. Is your ISP blocking uncommon ports?
echo 4. Try a common port like 8080 or 80 instead