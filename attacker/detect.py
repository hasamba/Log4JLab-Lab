#!/usr/bin/env python3

import os
import subprocess
import json
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.BLUE}╔══════════════════════════════════════╗
║    Log4Shell Detection Runner         ║
║    YARA | Sigma | Nuclei              ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def run_yara_detection(target_path="/logs"):
    print(f"\n{Fore.CYAN}[*] Running YARA Detection...{Style.RESET_ALL}")
    print("="*50)
    
    yara_rules = "/detection-rules/log4shell.yar"
    
    try:
        cmd = f"yara -r {yara_rules} {target_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            print(f"{Fore.RED}[!] YARA Detections Found:{Style.RESET_ALL}")
            for line in result.stdout.splitlines():
                if line.strip():
                    rule, file = line.split(" ", 1)
                    print(f"  {Fore.YELLOW}✗ Rule: {rule}{Style.RESET_ALL}")
                    print(f"    File: {file}")
        else:
            print(f"{Fore.GREEN}[+] No YARA detections found{Style.RESET_ALL}")
            
        if result.stderr:
            print(f"{Fore.RED}[!] YARA Errors: {result.stderr}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[!] Error running YARA: {str(e)}{Style.RESET_ALL}")

def run_sigma_detection(log_file="/logs/application.log"):
    print(f"\n{Fore.CYAN}[*] Running Sigma Detection...{Style.RESET_ALL}")
    print("="*50)
    
    sigma_rules = "/detection-rules/log4shell_sigma.yml"
    
    try:
        # Convert Sigma rules to query format (simplified example)
        print(f"{Fore.YELLOW}[*] Checking log file: {log_file}{Style.RESET_ALL}")
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                log_content = f.read()
                
            # Check for Log4Shell patterns
            patterns = [
                "${jndi:ldap://",
                "${jndi:rmi://",
                "${jndi:dns://",
                "${${::-j}ndi:",
                "${${lower:j}ndi:",
                "${${env:",
                "javax.naming.Context.lookup",
                "Looking up JNDI resource"
            ]
            
            detections = []
            for pattern in patterns:
                if pattern in log_content:
                    detections.append(pattern)
            
            if detections:
                print(f"{Fore.RED}[!] Sigma Pattern Detections:{Style.RESET_ALL}")
                for detection in detections:
                    print(f"  {Fore.YELLOW}✗ Pattern found: {detection}{Style.RESET_ALL}")
                    # Show context
                    for line_num, line in enumerate(log_content.splitlines(), 1):
                        if detection in line:
                            print(f"    Line {line_num}: {line[:100]}...")
                            break
            else:
                print(f"{Fore.GREEN}[+] No Sigma patterns detected in logs{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] Log file not found: {log_file}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[!] Error running Sigma detection: {str(e)}{Style.RESET_ALL}")

def run_nuclei_detection(target="http://vulnerable-app:8080"):
    print(f"\n{Fore.CYAN}[*] Running Nuclei Detection...{Style.RESET_ALL}")
    print("="*50)
    
    nuclei_template = "/detection-rules/log4shell-nuclei.yaml"
    
    try:
        # Update nuclei templates first
        print(f"{Fore.YELLOW}[*] Updating Nuclei templates...{Style.RESET_ALL}")
        subprocess.run("nuclei -update-templates", shell=True, capture_output=True)
        
        # Run nuclei scan
        cmd = f"nuclei -t {nuclei_template} -u {target} -v"
        print(f"{Fore.YELLOW}[*] Scanning target: {target}{Style.RESET_ALL}")
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if "log4shell" in result.stdout.lower() or "[critical]" in result.stdout.lower():
            print(f"{Fore.RED}[!] Nuclei Detection - VULNERABLE:{Style.RESET_ALL}")
            # Parse the output for better formatting
            for line in result.stdout.splitlines():
                if "[critical]" in line.lower() or "log4shell" in line.lower():
                    print(f"  {Fore.YELLOW}✗ {line}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No Nuclei detections (target may not be vulnerable or not reachable){Style.RESET_ALL}")
            
        if result.stderr and "error" in result.stderr.lower():
            print(f"{Fore.RED}[!] Nuclei Errors: {result.stderr}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[!] Error running Nuclei: {str(e)}{Style.RESET_ALL}")

def check_exploitation_artifacts():
    print(f"\n{Fore.CYAN}[*] Checking for Exploitation Artifacts...{Style.RESET_ALL}")
    print("="*50)
    
    # Check if exploitation was successful
    artifacts = [
        ("/tmp/pwned.txt", "Exploitation marker file"),
        ("/app/logs/application.log", "Application logs with JNDI patterns"),
        ("Exploit.class", "Malicious Java class")
    ]
    
    for artifact, description in artifacts:
        if os.path.exists(artifact):
            print(f"{Fore.RED}  ✗ Found: {artifact} - {description}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}  ✓ Not found: {artifact}{Style.RESET_ALL}")

def generate_report():
    print(f"\n{Fore.CYAN}[*] Detection Summary Report{Style.RESET_ALL}")
    print("="*50)
    
    report = {
        "vulnerability": "Log4Shell (CVE-2021-44228)",
        "severity": "Critical (CVSS 10.0)",
        "detection_methods": {
            "YARA": "File and memory pattern matching",
            "Sigma": "Log analysis and event correlation",
            "Nuclei": "Active vulnerability scanning"
        },
        "indicators_of_compromise": [
            "JNDI lookup strings in logs",
            "Outbound LDAP/RMI connections",
            "Java process spawning shells",
            "Suspicious .class files",
            "Webshells in web directories"
        ],
        "mitigation": [
            "Update Log4j to version 2.17.0 or later",
            "Set log4j2.formatMsgNoLookups=true",
            "Remove JndiLookup class from classpath",
            "Implement WAF rules to block JNDI patterns",
            "Monitor for suspicious Java process behavior"
        ]
    }
    
    print(json.dumps(report, indent=2))
    
    # Save report to file
    with open("/detection-rules/detection_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{Fore.GREEN}[+] Report saved to /detection-rules/detection_report.json{Style.RESET_ALL}")

def main():
    print_banner()
    
    print(f"{Fore.BLUE}[+] Starting comprehensive Log4Shell detection...{Style.RESET_ALL}")
    
    # Run all detection methods
    run_yara_detection()
    run_sigma_detection()
    run_nuclei_detection()
    check_exploitation_artifacts()
    
    # Generate report
    generate_report()
    
    print(f"\n{Fore.GREEN}[+] Detection scan completed!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Review the results above to identify potential compromises{Style.RESET_ALL}")

if __name__ == "__main__":
    main()