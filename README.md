# Log4Shell Security Research Lab

## Overview
Complete Log4Shell (CVE-2021-44228) vulnerability lab environment with exploitation tools and comprehensive detection rules for YARA, Sigma, and Nuclei.

⚠️ **Status**: Lab is 90% complete - vulnerability confirmed working, final exploitation testing needed.

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/hasamba/ProxyLogonLab.git log4shell-security-lab
cd log4shell-security-lab
```

### 2. Start the Lab (Use Simple Version)
```bash
# Use the working simple version
docker-compose -f docker-compose-simple.yml up -d --build
```

### 3. Verify Setup
```bash
# Check all containers running
docker ps

# Test vulnerability (should expand Java version)
docker exec attacker-machine curl -H "User-Agent: test_\${java:version}" http://log4shell-simple:8080
```

### 4. Run Exploitation
```bash
# Terminal 1: Start listener
docker exec -it attacker-machine /bin/bash
cd /tools
python3 listener.py

# Terminal 2: Run exploit
docker exec -it attacker-machine /bin/bash
cd /tools
python3 exploit.py

# Check success
docker exec log4shell-simple ls -la /tmp/pwned.txt
```

### 5. Run Detection Tools
```bash
docker exec -it attacker-machine /bin/bash
cd /tools
python3 detect.py
```

## Lab Components

### Vulnerable Application (Port 8080)
- Spring Boot app with Log4j 2.14.1 (vulnerable version)
- Endpoints: `/login`, `/api/v1/search`, `/api/v1/callback`
- Logs user input through Log4j

### LDAP/HTTP Exploit Server (Ports 1389, 8888)
- LDAP server redirects to malicious Java class
- HTTP server hosts compiled exploit payload
- Automatically compiles and serves Exploit.class

### Attacker Machine
- Exploitation scripts with multiple payload variants
- Detection tools (YARA, Sigma, Nuclei)
- Callback listener for successful exploits

## Exploitation Steps

1. **Listener Setup**: Start callback listener on port 9999
2. **Send Payloads**: Script injects JNDI strings via:
   - HTTP headers (User-Agent, X-Api-Version, etc.)
   - POST parameters (username, password)
   - GET parameters (query)
   - JSON body (callback)

3. **Exploitation Flow**:
   - App logs JNDI string → Log4j processes lookup
   - Connects to LDAP server → Gets redirect to HTTP
   - Downloads Exploit.class → Executes static block
   - Creates `/tmp/pwned.txt` → Sends callback

## Detection Methods

### YARA Rules
- JNDI lookup patterns
- Obfuscation techniques
- Exploitation artifacts
- Vulnerable Log4j versions
- Webshell indicators

### Sigma Rules
- Web server log patterns
- Process creation anomalies
- Network connections
- File creation events
- Application log analysis

### Nuclei Templates
- Basic JNDI injection
- Obfuscated payloads
- WAF bypass techniques
- Header injection points
- POST/JSON testing

## Verification Commands

```bash
# Check if exploitation succeeded
docker exec log4shell-vulnerable ls -la /tmp/pwned.txt

# View LDAP server logs
docker logs ldap-exploit-server

# Check application logs for JNDI patterns
docker exec log4shell-vulnerable cat /app/logs/application.log | grep jndi

# View all running containers
docker ps

# Access vulnerable app
curl http://localhost:8080
```

## Security Notes

⚠️ **WARNING**: This lab contains actual exploitation code for educational purposes only.
- Run only in isolated environments
- Do not expose to public networks
- Use for security research and training only
- Clean up after testing: `docker-compose down -v`

## Troubleshooting

### Exploitation Not Working?
- Ensure all containers are running: `docker ps`
- Check LDAP server logs: `docker logs ldap-exploit-server`
- Verify network connectivity between containers
- Try different payload variants

### Detection Not Triggering?
- Ensure log files exist before running detection
- Run exploitation first to generate artifacts
- Check detection rule paths are correct
- Verify tools are installed in attacker container

## Clean Up

```bash
# Stop and remove all containers
docker-compose down

# Remove volumes and images
docker-compose down -v --rmi all
```