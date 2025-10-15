# Expected YARA Detections for Log4Shell Lab

When running `log4shell-enhanced.yar` on your Log4Shell lab directory, YARA should detect the following:

## 1. **Exploit.java / Exploit.class Files**

### Files:
- `C:\...\57.07_Log4JLab\ldap-exploit\Exploit.java`
- `C:\...\57.07_Log4JLab\ldap-exploit\Exploit.class`
- `C:\...\57.07_Log4JLab\Exploit.java`
- `C:\...\57.07_Log4JLab\Exploit.class`

### Rules that will trigger:
- `Log4Shell_Exploitation_Artifacts` - Detects "Exploit.class", "Exploit.java", "Runtime.getRuntime().exec"
- `Log4Shell_Post_Exploitation` - If payload contains reverse shell or calc.exe commands

### Sample detection output:
```
Log4Shell_Exploitation_Artifacts C:\...\57.07_Log4JLab\ldap-exploit\Exploit.java
Log4Shell_Exploitation_Artifacts C:\...\57.07_Log4JLab\ldap-exploit\Exploit.class
```

## 2. **Python Exploitation Scripts**

### Files:
- `C:\...\57.07_Log4JLab\attacker\exploit.py`
- `C:\...\57.07_Log4JLab\ldap-exploit\ldap_server.py`
- `C:\...\57.07_Log4JLab\ldap_exploit.py`

### Rules that will trigger:
- `Log4Shell_JNDI_Lookup_Strings` - Contains "${jndi:ldap://" patterns
- `Log4Shell_Callback_Patterns` - Contains LDAP URLs and ports
- `Log4Shell_HTTP_Headers` - If scripts contain User-Agent with JNDI

### Sample detection output:
```
Log4Shell_JNDI_Lookup_Strings C:\...\57.07_Log4JLab\attacker\exploit.py
Log4Shell_Callback_Patterns C:\...\57.07_Log4JLab\attacker\exploit.py
```

## 3. **Documentation and Guide Files**

### Files:
- `C:\...\57.07_Log4JLab\remote-exploitation-guide.md`
- `C:\...\57.07_Log4JLab\network-troubleshooting.md`
- `C:\...\57.07_Log4JLab\CLAUDE.md`
- `C:\...\57.07_Log4JLab\Lab-Startup-Guide.md`

### Rules that will trigger:
- `Log4Shell_JNDI_Lookup_Strings` - Documentation contains JNDI examples
- `Log4Shell_Obfuscation_Advanced` - Examples of obfuscation techniques
- `Log4Shell_HTTP_Headers` - curl command examples with JNDI

### Sample detection output:
```
Log4Shell_JNDI_Lookup_Strings C:\...\57.07_Log4JLab\remote-exploitation-guide.md
Log4Shell_HTTP_Headers C:\...\57.07_Log4JLab\CLAUDE.md
```

## 4. **Shell Scripts**

### Files:
- `C:\...\57.07_Log4JLab\setup-remote-exploit.sh`
- `C:\...\57.07_Log4JLab\test-yara-rules.sh`

### Rules that will trigger:
- `Log4Shell_JNDI_Lookup_Strings` - Contains JNDI patterns
- `Log4Shell_Obfuscation_Advanced` - Contains obfuscation examples
- `Log4Shell_Post_Exploitation` - May contain reverse shell commands

### Sample detection output:
```
Log4Shell_JNDI_Lookup_Strings C:\...\57.07_Log4JLab\setup-remote-exploit.sh
Log4Shell_Post_Exploitation C:\...\57.07_Log4JLab\setup-remote-exploit.sh
```

## 5. **YARA Rule Files Themselves**

### Files:
- `C:\...\57.07_Log4JLab\detection-rules\log4shell.yar`
- `C:\...\57.07_Log4JLab\detection-rules\log4shell-enhanced.yar`

### Rules that will trigger:
- `Log4Shell_JNDI_Lookup_Strings` - Contains JNDI patterns in strings
- Multiple rules due to pattern definitions

### Sample detection output:
```
Log4Shell_JNDI_Lookup_Strings C:\...\57.07_Log4JLab\detection-rules\log4shell.yar
```

## 6. **Docker and Configuration Files**

### Files:
- `C:\...\57.07_Log4JLab\detection-rules\log4shell-nuclei.yaml`
- `C:\...\57.07_Log4JLab\detection-rules\log4shell.sigma`

### Rules that will trigger:
- `Log4Shell_JNDI_Lookup_Strings` - Contains detection patterns

## 7. **If Docker Containers Are Running (Log Files)**

### Potential locations on Windows:
- `C:\ProgramData\Docker\containers\*\*-json.log`
- `%USERPROFILE%\AppData\Local\Docker\log\*`

### Rules that will trigger if exploitation was attempted:
- `Log4Shell_JNDI_Lookup_Strings` - Attack attempts in logs
- `Log4Shell_HTTP_Headers` - User-Agent headers with JNDI
- `Log4Shell_Memory_Artifacts` - Java stack traces
- `Log4Shell_Network_IOCs` - LDAP connection attempts

## Summary of Expected Detections

### Minimum expected detections (clean lab):
- **15-25 detections** across documentation and script files
- Primary rule: `Log4Shell_JNDI_Lookup_Strings`
- Secondary: `Log4Shell_Exploitation_Artifacts`, `Log4Shell_HTTP_Headers`

### Additional detections if exploitation was performed:
- **+10-50 detections** in log files
- Docker container logs
- Temporary files in `%TEMP%`
- Web server logs if IIS/Apache/nginx installed

### False Positives to Expect:
- Documentation files (intentional - contains examples)
- YARA rule files themselves (contains patterns)
- Security scanning tools (contain test patterns)

## Command to Run Full Scan:

```powershell
# PowerShell (recommended)
.\Scan-Log4Shell.ps1 -ScanPath "C:\Users\yaniv\10Root Dropbox\Yaniv Radunsky\Documents\50-59 Projects\57 ClaudeCode\57.07_Log4JLab" -DeepScan -ExportResults

# Or with yara directly
yara64.exe -r "C:\...\57.07_Log4JLab\detection-rules\log4shell-enhanced.yar" "C:\...\57.07_Log4JLab" > detections.txt
```

## What Each Detection Means:

1. **In .java/.py files** - Source code for exploitation/testing (expected)
2. **In .md/.txt files** - Documentation/examples (expected)
3. **In .log files** - Actual exploitation attempts (investigate)
4. **In .class files** - Compiled exploits (high risk)
5. **In web directories** - Potential compromise (critical)

The lab environment should generate detections primarily in categories 1-2 (expected), while categories 3-5 would indicate actual exploitation activity.