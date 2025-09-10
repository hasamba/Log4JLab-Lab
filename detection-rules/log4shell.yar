rule Log4Shell_JNDI_Lookup_Strings
{
    meta:
        description = "Detects Log4Shell JNDI lookup strings in files and logs"
        author = "Security Research Lab"
        date = "2025-01-10"
        severity = "critical"
        cve = "CVE-2021-44228"
        
    strings:
        $jndi1 = "${jndi:ldap://" ascii nocase
        $jndi2 = "${jndi:ldaps://" ascii nocase
        $jndi3 = "${jndi:rmi://" ascii nocase
        $jndi4 = "${jndi:dns://" ascii nocase
        $jndi5 = "${jndi:iiop://" ascii nocase
        $jndi6 = "${jndi:http://" ascii nocase
        $jndi7 = "${jndi:nis://" ascii nocase
        $jndi8 = "${jndi:nds://" ascii nocase
        $jndi9 = "${jndi:corba://" ascii nocase
        
        // Obfuscation patterns
        $obf1 = "${${::-j}ndi:" ascii nocase
        $obf2 = "${${lower:j}ndi:" ascii nocase
        $obf3 = "${${upper:j}ndi:" ascii nocase
        $obf4 = "${${env:" ascii
        $obf5 = "${${sys:" ascii
        $obf6 = "${${::-" ascii
        $obf7 = "${${lower:" ascii
        $obf8 = "${${upper:" ascii
        
        // Nested patterns
        $nested1 = /\$\{[^\}]*\$\{[^\}]*\}[^\}]*\}/ ascii
        
    condition:
        any of ($jndi*) or 
        (any of ($obf*) and ($nested1))
}

rule Log4Shell_Exploitation_Artifacts
{
    meta:
        description = "Detects artifacts from successful Log4Shell exploitation"
        author = "Security Research Lab"
        date = "2025-01-10"
        severity = "critical"
        
    strings:
        $exploit1 = "Log4Shell_Exploited" ascii wide
        $exploit2 = "pwned.txt" ascii wide
        $class1 = "Exploit.class" ascii
        $class2 = "Exploit.java" ascii
        
        // Java deserialization patterns
        $java1 = {AC ED 00 05} // Java serialization header
        $java2 = "java.lang.Runtime" ascii
        $java3 = "getRuntime" ascii
        $java4 = "exec" ascii
        
        // Command execution patterns
        $cmd1 = /Runtime\.getRuntime\(\)\.exec/ ascii
        $cmd2 = "ProcessBuilder" ascii
        $cmd3 = "/bin/sh" ascii
        $cmd4 = "cmd.exe" ascii
        
    condition:
        (any of ($exploit*) or any of ($class*)) or
        ($java1 and any of ($java2, $java3, $java4)) or
        (2 of ($cmd*))
}

rule Log4Shell_Vulnerable_Log4j_Version
{
    meta:
        description = "Detects vulnerable Log4j versions (2.0-2.14.1)"
        author = "Security Research Lab"
        date = "2025-01-10"
        severity = "high"
        
    strings:
        $log4j_jar1 = "log4j-core-2." ascii
        $log4j_jar2 = "log4j-api-2." ascii
        
        // Vulnerable version patterns in JAR manifests
        $version1 = /Implementation-Version: 2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\.[0-9]/ ascii
        $version2 = /log4j-core-2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\.[0-9]/ ascii
        
        // JndiLookup class (the vulnerable component)
        $jndi_class = "JndiLookup.class" ascii
        $jndi_lookup = "org/apache/logging/log4j/core/lookup/JndiLookup" ascii
        
    condition:
        (any of ($log4j_jar*) and any of ($version*)) or
        (any of ($jndi_*))
}

rule Log4Shell_Network_IOCs
{
    meta:
        description = "Detects network-based IOCs related to Log4Shell exploitation"
        author = "Security Research Lab"
        date = "2025-01-10"
        severity = "high"
        
    strings:
        // Common callback domains and patterns
        $callback1 = /ldap:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        $callback2 = "dnslog.cn" ascii nocase
        $callback3 = "interact.sh" ascii nocase
        $callback4 = "burpcollaborator" ascii nocase
        $callback5 = "requestbin" ascii nocase
        $callback6 = "webhook.site" ascii nocase
        
        // Base64 encoded JNDI strings
        $b64_jndi1 = "JHtqbmRp" // ${jndi base64
        $b64_jndi2 = "ke2puZGk6" // ${jndi: base64
        $b64_jndi3 = "amF2YS5sYW5nLlJ1bnRpbWU" // java.lang.Runtime base64
        
        // Hexadecimal encoded patterns
        $hex_jndi = {24 7B 6A 6E 64 69 3A} // ${jndi: in hex
        
    condition:
        any of them
}

rule Log4Shell_Webshell_Indicators
{
    meta:
        description = "Detects potential webshells dropped via Log4Shell"
        author = "Security Research Lab"
        date = "2025-01-10"
        severity = "critical"
        
    strings:
        // Common webshell patterns
        $jsp1 = "<%@page import=\"java.lang.*\"%>" ascii
        $jsp2 = "<%@page import=\"java.io.*\"%>" ascii
        $jsp3 = "request.getParameter" ascii
        $jsp4 = "Runtime.getRuntime().exec" ascii
        
        // ASPX patterns (if targeting IIS/Exchange)
        $aspx1 = "<%@ Page Language=\"C#\"" ascii
        $aspx2 = "System.Diagnostics.Process" ascii
        
        // Generic webshell functions
        $func1 = "eval" ascii
        $func2 = "assert" ascii
        $func3 = "system" ascii
        $func4 = "passthru" ascii
        $func5 = "shell_exec" ascii
        
        // Encoded/obfuscated patterns
        $encoded1 = /eval\(base64_decode\(/ ascii
        $encoded2 = /eval\(gzinflate\(/ ascii
        
    condition:
        (2 of ($jsp*) and $jsp4) or
        (any of ($aspx*) and $aspx2) or
        (filesize < 50KB and 3 of ($func*)) or
        any of ($encoded*)
}