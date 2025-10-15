@echo off
echo Run this as Administrator to allow port 8081 through Windows Firewall
echo.

REM Add inbound rule for port 8081
netsh advfirewall firewall add rule name="Log4Shell Lab Port 8081" dir=in action=allow protocol=TCP localport=8081

REM Check if rule was added
netsh advfirewall firewall show rule name="Log4Shell Lab Port 8081"

echo.
echo Rule added. Testing port...
netstat -an | findstr :8081

echo.
echo If still not accessible, also check:
echo 1. Windows Defender Firewall with Advanced Security
echo 2. Any third-party firewall/antivirus software
echo 3. Router/NAT port forwarding if accessing from outside your network