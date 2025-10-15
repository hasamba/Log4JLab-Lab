rule Log4Shell_HTTP_Headers
{
    meta:
        description = "Detects Log4Shell attempts in HTTP headers and request logs"
        author = "Security Research Lab"
        date = "2025-01-18"
        severity = "critical"
        cve = "CVE-2021-44228"

    strings:
        // Direct JNDI patterns in headers
        $header1 = "User-Agent: ${jndi:" ascii nocase
        $header2 = "X-Api-Version: ${jndi:" ascii nocase
        $header3 = "X-Forwarded-For: ${jndi:" ascii nocase
        $header4 = "Referer: ${jndi:" ascii nocase
        $header5 = "Authorization: ${jndi:" ascii nocase
        $header6 = "Cookie: ${jndi:" ascii nocase
        $header7 = "Accept: ${jndi:" ascii nocase
        $header8 = "Content-Type: ${jndi:" ascii nocase

        // URL encoded patterns
        $url1 = "%24%7Bjndi" ascii nocase  // ${jndi URL encoded
        $url2 = "%24%7B%6A%6E%64%69" ascii nocase  // ${jndi fully encoded
        $url3 = "%2524%257Bjndi" ascii nocase  // Double encoded

        // Unicode encoded patterns
        $unicode1 = "\\u0024\\u007b\\u006a\\u006e\\u0064\\u0069" ascii  // ${jndi
        $unicode2 = "${\\u006a\\u006e\\u0064\\u0069:" ascii

        // Common exploit URLs
        $exploit_url1 = "/?search=${jndi:" ascii nocase
        $exploit_url2 = "/?q=${jndi:" ascii nocase
        $exploit_url3 = "/?username=${jndi:" ascii nocase
        $exploit_url4 = "/?id=${jndi:" ascii nocase

    condition:
        any of them
}

rule Log4Shell_Obfuscation_Advanced
{
    meta:
        description = "Detects advanced obfuscation techniques used to bypass WAF/filters"
        author = "Security Research Lab"
        date = "2025-01-18"
        severity = "critical"

    strings:
        // Environment variable substitution
        $env1 = "${env:BARFOO:-j}ndi" ascii
        $env2 = "${env:FOOBAR:-$}${env:BARFOO:-{}" ascii
        $env3 = "${${env:ENV_NAME:-j}ndi" ascii

        // System property substitution
        $sys1 = "${sys:PROP:-j}ndi" ascii
        $sys2 = "${${sys:PROP1:-j}${sys:PROP2:-n}di:" ascii

        // Case manipulation
        $case1 = "${${lower:J}NDI:" ascii
        $case2 = "${${upper:j}ndi:" ascii
        $case3 = "${${lower:${upper:j}}ndi:" ascii

        // Substring operations
        $substr1 = "${${::-j}${::-n}${::-d}${::-i}" ascii
        $substr2 = "${${date:'::-j'}ndi:" ascii

        // Mixed obfuscation
        $mixed1 = "${${::-$}${::-{}" ascii
        $mixed2 = "${${env:NaN:-j}ndi" ascii
        $mixed3 = "${jn${lower:D}${lower:I}:" ascii

        // Double/triple encoding
        $double1 = "$%7B%6A%6E%64%69%3A" ascii
        $triple1 = "%2524%257B%256A%256E%2564%2569" ascii

    condition:
        any of them
}

rule Log4Shell_Callback_Patterns
{
    meta:
        description = "Detects callback patterns used in Log4Shell exploitation"
        author = "Security Research Lab"
        date = "2025-01-18"
        severity = "high"

    strings:
        // IP-based callbacks
        $ip_pattern = /\$\{jndi:(ldap|ldaps|rmi|dns|iiop):\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{1,5})?\/[a-zA-Z0-9]+\}/ ascii

        // Domain callbacks
        $domain1 = /\$\{jndi:ldap:\/\/[a-z0-9\-\.]+\.(tk|ml|ga|cf)\// ascii nocase
        $domain2 = "${jndi:ldap://attacker.local" ascii nocase
        $domain3 = "${jndi:ldap://evil.com" ascii nocase

        // Localhost testing
        $local1 = "${jndi:ldap://127.0.0.1" ascii
        $local2 = "${jndi:ldap://localhost" ascii
        $local3 = "${jndi:ldap://0.0.0.0" ascii

        // Common ports
        $port1 = ":1389/" ascii  // Default LDAP
        $port2 = ":1099/" ascii  // RMI
        $port3 = ":8888/" ascii  // Common HTTP callback
        $port4 = ":9999/" ascii  // Common test port

        // Payload class names
        $class1 = "/Exploit}" ascii
        $class2 = "/Evil}" ascii
        $class3 = "/Payload}" ascii
        $class4 = "/Shell}" ascii
        $class5 = "/Calc}" ascii
        $class6 = "/Base}" ascii
        $class7 = "/Touch}" ascii

    condition:
        $ip_pattern or
        (any of ($domain*) and any of ($port*)) or
        (any of ($local*) and any of ($class*))
}

rule Log4Shell_Post_Exploitation
{
    meta:
        description = "Detects post-exploitation activity following successful Log4Shell attack"
        author = "Security Research Lab"
        date = "2025-01-18"
        severity = "critical"

    strings:
        // Reverse shell commands
        $revshell1 = "bash -i >& /dev/tcp/" ascii
        $revshell2 = "nc -e /bin/sh" ascii
        $revshell3 = "python -c 'import socket" ascii
        $revshell4 = "powershell -nop -c" ascii

        // Persistence mechanisms
        $persist1 = "crontab -e" ascii
        $persist2 = "systemctl enable" ascii
        $persist3 = "schtasks /create" ascii
        $persist4 = "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii

        // Lateral movement
        $lateral1 = "ssh-keygen" ascii
        $lateral2 = "psexec" ascii
        $lateral3 = "wmic process call create" ascii

        // Data exfiltration
        $exfil1 = "tar -czf" ascii
        $exfil2 = "zip -r" ascii
        $exfil3 = "curl -F" ascii
        $exfil4 = "wget --post-file" ascii

        // Cryptomining
        $crypto1 = "xmrig" ascii nocase
        $crypto2 = "monero" ascii nocase
        $crypto3 = "stratum+tcp://" ascii

    condition:
        2 of them
}

rule Log4Shell_Detection_Evasion
{
    meta:
        description = "Detects attempts to evade Log4Shell detection"
        author = "Security Research Lab"
        date = "2025-01-18"
        severity = "high"

    strings:
        // Log4j configuration changes
        $config1 = "log4j2.formatMsgNoLookups" ascii
        $config2 = "LOG4J_FORMAT_MSG_NO_LOOKUPS" ascii
        $config3 = "-Dlog4j2.formatMsgNoLookups=true" ascii

        // JndiLookup.class removal attempts
        $remove1 = "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class" ascii
        $remove2 = "find . -name \"JndiLookup.class\" -delete" ascii
        $remove3 = "rm -rf */JndiLookup.class" ascii

        // WAF bypass attempts
        $waf1 = "X-Originating-IP: ${jndi:" ascii
        $waf2 = "X-Real-IP: ${jndi:" ascii
        $waf3 = "CF-Connecting-IP: ${jndi:" ascii
        $waf4 = "True-Client-IP: ${jndi:" ascii

        // Detection tool evasion
        $evade1 = "iptables -A OUTPUT -d" ascii
        $evade2 = "firewall-cmd --add-rich-rule" ascii
        $evade3 = "netsh advfirewall firewall add rule" ascii

    condition:
        any of them
}

rule Log4Shell_Memory_Artifacts
{
    meta:
        description = "Detects Log4Shell artifacts in memory dumps"
        author = "Security Research Lab"
        date = "2025-01-18"
        severity = "high"

    strings:
        // JNDI lookup strings in memory
        $mem1 = "com.sun.jndi.ldap.LdapCtx" ascii
        $mem2 = "com.sun.jndi.url.ldap.ldapURLContext" ascii
        $mem3 = "javax.naming.InitialContext" ascii
        $mem4 = "org.apache.logging.log4j.core.lookup.JndiLookup" ascii

        // Stack traces
        $stack1 = "at org.apache.logging.log4j.core.lookup.JndiLookup.lookup" ascii
        $stack2 = "at com.sun.jndi.ldap.LdapCtx.connect" ascii
        $stack3 = "at javax.naming.InitialContext.lookup" ascii

        // Error messages
        $error1 = "Error looking up JNDI resource" ascii
        $error2 = "javax.naming.CommunicationException" ascii
        $error3 = "javax.naming.NamingException" ascii

        // Successful exploitation markers
        $success1 = "java.lang.Runtime.exec" ascii
        $success2 = "ProcessBuilder.start" ascii
        $success3 = "Exploit.<clinit>" ascii

    condition:
        2 of ($mem*) or
        any of ($stack*) or
        (any of ($error*) and any of ($mem*)) or
        any of ($success*)
}

rule Log4Shell_Comprehensive
{
    meta:
        description = "Comprehensive rule combining all Log4Shell detection patterns"
        author = "Security Research Lab"
        date = "2025-01-18"
        severity = "critical"
        cve = "CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, CVE-2021-44832"

    strings:
        // Basic JNDI patterns
        $basic = /\$\{jndi:(ldap|ldaps|rmi|dns|iiop|http|https):\/\// ascii nocase

        // Any obfuscation attempt
        $obf = /\$\{[^\}]*\$\{[^\}]*\}[^\}]*\}/ ascii

        // URL/Base64/Hex encoded
        $encoded = /(%24%7B|JHtqbmRp|24 7B 6A 6E 64 69)/ ascii nocase

        // Log4j specific classes
        $class = /(JndiLookup|JndiManager|InitialContext)/ ascii

        // Exploitation artifacts
        $artifact = /(Exploit\.class|pwned\.txt|Runtime\.getRuntime)/ ascii

    condition:
        $basic or
        ($obf and $class) or
        $encoded or
        $artifact or
        (filesize < 10MB and 2 of them)
}