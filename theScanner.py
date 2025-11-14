#!/usr/bin/python3

import os
import sys
import time
import json
import re
import datetime
import subprocess
from pathlib import Path

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def slowprint(s, speed=1/1000):
    """Print text with a typewriter effect"""
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(speed)

def print_color(text, color=Colors.OKGREEN):
    """Print colored text"""
    print(f"{color}{text}{Colors.ENDC}")

def print_banner():
    """Display the main banner"""
    banner = f"""{Colors.OKCYAN}
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║  _   _           _____                                     ║
║ | | | |         / ____|                                    ║
║ | |_| |__   ___| (___   ___ __ _ _ __  _ __   ___ _ __    ║
║ | __| '_ \ / _ \\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|   ║
║ | |_| | | |  __/____) | (_| (_| | | | | | | |  __/ |      ║
║  \__|_| |_|\___|_____/ \___\__,_|_| |_|_| |_|\___|_|       ║
║                                                            ║
║  theScanner v2.0 - Advanced Network Reconnaissance Tool   ║
║  Coded by $ ./Netrunner_&                                 ║
║  Enhanced with NSE Scripts & Advanced Scanning            ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)

def validate_ip(ip):
    """Validate IP address or range"""
    # Allow IP addresses, ranges, CIDR notation
    patterns = [
        r'^(\d{1,3}\.){3}\d{1,3}$',  # Single IP
        r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$',  # CIDR
        r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$',  # Range
        r'^(\d{1,3}\.){3}\*$',  # Wildcard
    ]
    for pattern in patterns:
        if re.match(pattern, ip.strip()):
            return True
    return False

def validate_ports(ports):
    """Validate port specification"""
    if not ports:
        return True
    # Allow single ports, ranges, and comma-separated lists
    pattern = r'^[\d,\-]+$'
    return bool(re.match(pattern, ports))

def get_target():
    """Get and validate target IP/range"""
    while True:
        target = input(f"\n{Colors.OKBLUE}Enter target IP/range (e.g., 192.168.1.1, 192.168.1.0/24, 192.168.1.1-254): {Colors.ENDC}\n>>> ").strip()
        if validate_ip(target) or target.replace('.', '').replace('-', '').replace('/', '').isalnum():
            return target
        print_color("Invalid IP format. Please try again.", Colors.FAIL)

def get_ports():
    """Get port specification"""
    ports = input(f"\n{Colors.OKBLUE}Enter ports (press Enter for default, or specify like '80,443' or '1-1000'): {Colors.ENDC}\n>>> ").strip()
    if not ports:
        return ""
    if validate_ports(ports):
        return f"-p {ports}"
    print_color("Invalid port specification. Using default ports.", Colors.WARNING)
    return ""

def save_output(command, output_file=None):
    """Generate output file path"""
    if output_file:
        return f"-oA {output_file}"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("scan_results")
    output_dir.mkdir(exist_ok=True)
    return f"-oA scan_results/scan_{timestamp}"

def execute_scan(command, description):
    """Execute scan command with error handling"""
    print_color(f"\n[*] {description}", Colors.OKCYAN)
    print_color(f"[*] Executing: {command}", Colors.OKBLUE)
    print_color("[*] Scanning in progress...\n", Colors.WARNING)

    try:
        result = os.system(command)
        if result == 0:
            print_color(f"\n[✓] Scan completed successfully!", Colors.OKGREEN)
        else:
            print_color(f"\n[!] Scan completed with warnings (exit code: {result})", Colors.WARNING)
    except Exception as e:
        print_color(f"\n[✗] Error executing scan: {str(e)}", Colors.FAIL)

# ==================== SCAN TYPE FUNCTIONS ====================

def quick_scan():
    """Quick scan of most common ports"""
    target = get_target()
    output = save_output("")
    command = f"nmap -T4 -F {target} {output}"
    execute_scan(command, "Quick Scan - Top 100 ports")

def intense_scan():
    """Comprehensive intense scan"""
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap -T4 -A -v {ports} {target} {output}"
    execute_scan(command, "Intense Scan - OS detection, version detection, script scanning, and traceroute")

def stealth_scan():
    """Stealth SYN scan"""
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"sudo nmap -sS -T2 {ports} {target} {output}"
    execute_scan(command, "Stealth SYN Scan - Requires root privileges")

def udp_scan():
    """UDP port scan"""
    target = get_target()
    output = save_output("")
    command = f"sudo nmap -sU -T4 --top-ports 100 {target} {output}"
    execute_scan(command, "UDP Scan - Top 100 UDP ports")

def comprehensive_scan():
    """Scan all 65535 ports"""
    target = get_target()
    output = save_output("")
    print_color("[!] Warning: This scan will take a long time!", Colors.WARNING)
    command = f"nmap -p- -T4 {target} {output}"
    execute_scan(command, "Comprehensive Scan - All 65535 ports")

def version_detection():
    """Aggressive version detection"""
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap -sV --version-intensity 9 {ports} {target} {output}"
    execute_scan(command, "Version Detection - Aggressive service/version detection")

def os_detection():
    """Operating system detection"""
    target = get_target()
    output = save_output("")
    command = f"sudo nmap -O --osscan-guess {target} {output}"
    execute_scan(command, "OS Detection - Requires root privileges")

# ==================== NSE SCRIPT FUNCTIONS ====================

def vuln_scan():
    """Vulnerability scanning using NSE vuln scripts"""
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap --script vuln -sV {ports} {target} {output}"
    execute_scan(command, "Vulnerability Scan - Using NSE vuln category scripts")

def exploit_scan():
    """Check for exploitable vulnerabilities"""
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap --script exploit -sV {ports} {target} {output}"
    execute_scan(command, "Exploit Scan - Checking for known exploits")

def default_scripts():
    """Run default NSE scripts"""
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap -sC -sV {ports} {target} {output}"
    execute_scan(command, "Default Scripts - Running default NSE scripts")

def auth_scan():
    """Authentication and brute force scripts"""
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap --script auth,brute -sV {ports} {target} {output}"
    execute_scan(command, "Authentication Scan - Testing auth mechanisms and weak credentials")

def malware_scan():
    """Check for malware and backdoors"""
    target = get_target()
    output = save_output("")
    command = f"nmap --script malware -sV {target} {output}"
    execute_scan(command, "Malware Scan - Checking for malware and backdoors")

def discovery_scan():
    """Host and service discovery scripts"""
    target = get_target()
    output = save_output("")
    command = f"nmap --script discovery -sV {target} {output}"
    execute_scan(command, "Discovery Scan - Network and service discovery")

def broadcast_scan():
    """Broadcast scripts for network discovery"""
    output = save_output("")
    command = f"nmap --script broadcast {output}"
    execute_scan(command, "Broadcast Scan - Network-wide broadcast discovery")

def custom_nse_script():
    """Run custom NSE script(s)"""
    print_color("\n[*] Available NSE script categories:", Colors.OKCYAN)
    print("    auth, broadcast, brute, default, discovery, dos, exploit,")
    print("    external, fuzzer, intrusive, malware, safe, version, vuln")

    script = input(f"\n{Colors.OKBLUE}Enter NSE script name or category: {Colors.ENDC}\n>>> ").strip()
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap --script {script} -sV {ports} {target} {output}"
    execute_scan(command, f"Custom NSE Script - Running {script}")

# ==================== SERVICE-SPECIFIC SCANS ====================

def smb_scan():
    """SMB/Samba enumeration"""
    target = get_target()
    output = save_output("")
    scripts = "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln*"
    command = f"nmap --script {scripts} -p445 {target} {output}"
    execute_scan(command, "SMB Scan - Comprehensive SMB enumeration and vulnerability checks")

def http_scan():
    """HTTP/HTTPS enumeration"""
    target = get_target()
    output = save_output("")
    scripts = "http-enum,http-headers,http-methods,http-title,http-vuln*"
    command = f"nmap --script {scripts} -p80,443,8080,8443 {target} {output}"
    execute_scan(command, "HTTP Scan - Web server enumeration and vulnerability checks")

def ssl_scan():
    """SSL/TLS security scan"""
    target = get_target()
    output = save_output("")
    scripts = "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params"
    command = f"nmap --script {scripts} -p443,8443 {target} {output}"
    execute_scan(command, "SSL/TLS Scan - Certificate and vulnerability analysis")

def dns_scan():
    """DNS enumeration"""
    target = get_target()
    output = save_output("")
    scripts = "dns-brute,dns-zone-transfer,dns-nsid,dns-recursion"
    command = f"nmap --script {scripts} -p53 {target} {output}"
    execute_scan(command, "DNS Scan - DNS server enumeration and zone transfer attempts")

def ftp_scan():
    """FTP enumeration and vulnerability scan"""
    target = get_target()
    output = save_output("")
    scripts = "ftp-anon,ftp-bounce,ftp-vuln*,ftp-brute"
    command = f"nmap --script {scripts} -p21 {target} {output}"
    execute_scan(command, "FTP Scan - FTP enumeration and vulnerability checks")

def ssh_scan():
    """SSH enumeration and security scan"""
    target = get_target()
    output = save_output("")
    scripts = "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos,ssh-brute"
    command = f"nmap --script {scripts} -p22 {target} {output}"
    execute_scan(command, "SSH Scan - SSH enumeration and security analysis")

def sql_scan():
    """SQL database scanning"""
    target = get_target()
    output = save_output("")
    scripts = "mysql-*,ms-sql-*,oracle-*,pgsql-*"
    command = f"nmap --script {scripts} -p1433,3306,5432,1521 {target} {output}"
    execute_scan(command, "SQL Scan - Database server enumeration")

def rdp_scan():
    """RDP enumeration and security scan"""
    target = get_target()
    output = save_output("")
    scripts = "rdp-enum-encryption,rdp-vuln*"
    command = f"nmap --script {scripts} -p3389 {target} {output}"
    execute_scan(command, "RDP Scan - Remote Desktop Protocol security analysis")

def vnc_scan():
    """VNC enumeration"""
    target = get_target()
    output = save_output("")
    scripts = "vnc-info,vnc-brute,realvnc-auth-bypass"
    command = f"nmap --script {scripts} -p5900-5910 {target} {output}"
    execute_scan(command, "VNC Scan - VNC server enumeration")

# ==================== SPECIALIZED SCANS ====================

def firewall_detection():
    """Detect firewall and IDS/IPS"""
    target = get_target()
    output = save_output("")
    command = f"nmap -sA -T4 --script firewall-bypass {target} {output}"
    execute_scan(command, "Firewall Detection - ACK scan to detect filtering")

def ipv6_scan():
    """IPv6 scanning"""
    target = input(f"\n{Colors.OKBLUE}Enter IPv6 target: {Colors.ENDC}\n>>> ").strip()
    output = save_output("")
    command = f"nmap -6 -sV {target} {output}"
    execute_scan(command, "IPv6 Scan - IPv6 host discovery and scanning")

def script_trace():
    """Run scripts with detailed trace"""
    target = get_target()
    script = input(f"\n{Colors.OKBLUE}Enter script name: {Colors.ENDC}\n>>> ").strip()
    command = f"nmap --script {script} --script-trace {target}"
    execute_scan(command, "Script Trace - Detailed script execution trace")

def timing_scan():
    """Custom timing template scan"""
    print_color("\n[*] Timing templates:", Colors.OKCYAN)
    print("    0 - Paranoid (IDS evasion)")
    print("    1 - Sneaky (IDS evasion)")
    print("    2 - Polite (less bandwidth)")
    print("    3 - Normal (default)")
    print("    4 - Aggressive (fast)")
    print("    5 - Insane (very fast)")

    timing = input(f"\n{Colors.OKBLUE}Select timing (0-5): {Colors.ENDC}\n>>> ").strip()
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap -T{timing} -sV {ports} {target} {output}"
    execute_scan(command, f"Custom Timing Scan - T{timing}")

def fragmentation_scan():
    """Fragment packets to evade firewalls"""
    target = get_target()
    output = save_output("")
    command = f"sudo nmap -f -sS {target} {output}"
    execute_scan(command, "Fragmentation Scan - Packet fragmentation for firewall evasion")

def decoy_scan():
    """Use decoys to hide scan source"""
    target = get_target()
    print_color("\n[*] Using random decoys to mask scan source", Colors.WARNING)
    output = save_output("")
    command = f"nmap -D RND:10 {target} {output}"
    execute_scan(command, "Decoy Scan - Using 10 random decoys")

def zombie_scan():
    """Idle/Zombie scan"""
    target = get_target()
    zombie = input(f"\n{Colors.OKBLUE}Enter zombie host IP: {Colors.ENDC}\n>>> ").strip()
    output = save_output("")
    command = f"sudo nmap -sI {zombie} {target} {output}"
    execute_scan(command, "Zombie Scan - Using idle host for scanning")

# ==================== HOST DISCOVERY ====================

def ping_sweep():
    """ICMP ping sweep"""
    target = get_target()
    output = save_output("")
    command = f"nmap -sn -PE {target} {output}"
    execute_scan(command, "Ping Sweep - ICMP echo request")

def arp_scan():
    """ARP scan for local network"""
    target = get_target()
    output = save_output("")
    command = f"sudo nmap -PR {target} {output}"
    execute_scan(command, "ARP Scan - Local network discovery")

def tcp_ping():
    """TCP ping scan"""
    target = get_target()
    output = save_output("")
    command = f"nmap -sn -PS80,443,22 {target} {output}"
    execute_scan(command, "TCP Ping - SYN ping on common ports")

def no_ping_scan():
    """Scan without host discovery"""
    target = get_target()
    ports = get_ports()
    output = save_output("")
    command = f"nmap -Pn {ports} {target} {output}"
    execute_scan(command, "No Ping Scan - Skip host discovery")

def fping_sweep():
    """Fast ICMP ping using fping"""
    target = input(f"\n{Colors.OKBLUE}Enter IP range (e.g., 192.168.1.0/24 or 192.168.1.1 192.168.1.254): {Colors.ENDC}\n>>> ").strip()
    command = f"fping -a -g {target} 2>/dev/null"
    execute_scan(command, "FPing Sweep - Fast ICMP ping sweep")

# ==================== ADDITIONAL TOOLS ====================

def masscan_fast():
    """Ultra-fast port scanning with masscan"""
    target = get_target()
    rate = input(f"\n{Colors.OKBLUE}Enter packet rate (default 1000): {Colors.ENDC}\n>>> ").strip() or "1000"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("scan_results")
    output_dir.mkdir(exist_ok=True)
    command = f"sudo masscan {target} -p1-65535 --rate={rate} -oL scan_results/masscan_{timestamp}.txt"
    execute_scan(command, f"Masscan - Ultra-fast scanning at {rate} packets/sec")

def banner_grab():
    """Simple banner grabbing"""
    target = input(f"\n{Colors.OKBLUE}Enter target IP: {Colors.ENDC}\n>>> ").strip()
    port = input(f"{Colors.OKBLUE}Enter port: {Colors.ENDC}\n>>> ").strip()

    print_color(f"\n[*] Attempting to grab banner from {target}:{port}", Colors.OKCYAN)
    try:
        command = f"timeout 5 bash -c 'echo \"\" | nc -v -w 2 {target} {port}'"
        os.system(command)
    except Exception as e:
        print_color(f"[✗] Error: {str(e)}", Colors.FAIL)

def whois_lookup():
    """WHOIS information lookup"""
    target = input(f"\n{Colors.OKBLUE}Enter domain or IP: {Colors.ENDC}\n>>> ").strip()
    command = f"whois {target}"
    execute_scan(command, f"WHOIS Lookup - {target}")

def dns_enum():
    """DNS enumeration with dnsenum"""
    domain = input(f"\n{Colors.OKBLUE}Enter domain: {Colors.ENDC}\n>>> ").strip()
    command = f"dnsenum {domain}"
    execute_scan(command, f"DNS Enumeration - {domain}")

def subdomain_enum():
    """Subdomain enumeration"""
    domain = input(f"\n{Colors.OKBLUE}Enter domain: {Colors.ENDC}\n>>> ").strip()
    wordlist = input(f"{Colors.OKBLUE}Enter wordlist path (or press Enter for default): {Colors.ENDC}\n>>> ").strip()

    if wordlist and Path(wordlist).exists():
        command = f"nmap --script dns-brute --script-args dns-brute.hostlist={wordlist} {domain}"
    else:
        command = f"nmap --script dns-brute {domain}"

    execute_scan(command, f"Subdomain Enumeration - {domain}")

# ==================== REPORTING & UTILITIES ====================

def view_scan_results():
    """View previous scan results"""
    output_dir = Path("scan_results")
    if not output_dir.exists() or not list(output_dir.iterdir()):
        print_color("\n[!] No scan results found.", Colors.WARNING)
        return

    print_color("\n[*] Recent scan results:", Colors.OKCYAN)
    files = sorted(output_dir.iterdir(), key=os.path.getmtime, reverse=True)[:10]

    for idx, file in enumerate(files, 1):
        mtime = datetime.datetime.fromtimestamp(file.stat().st_mtime)
        print(f"    {idx}. {file.name} ({mtime.strftime('%Y-%m-%d %H:%M:%S')})")

    choice = input(f"\n{Colors.OKBLUE}Enter number to view (or press Enter to return): {Colors.ENDC}\n>>> ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        file_to_view = files[int(choice) - 1]
        # Try to view .nmap file first (most readable)
        nmap_file = file_to_view.with_suffix('.nmap')
        if nmap_file.exists():
            os.system(f"less {nmap_file}")
        else:
            os.system(f"less {file_to_view}")

def export_scan():
    """Export scan in different formats"""
    print_color("\n[*] Export formats:", Colors.OKCYAN)
    print("    1. Normal output (.nmap)")
    print("    2. XML output (.xml)")
    print("    3. Grepable output (.gnmap)")
    print("    4. All formats")

    choice = input(f"\n{Colors.OKBLUE}Select format (1-4): {Colors.ENDC}\n>>> ").strip()
    target = get_target()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    output_formats = {
        '1': f"-oN scan_results/scan_{timestamp}.nmap",
        '2': f"-oX scan_results/scan_{timestamp}.xml",
        '3': f"-oG scan_results/scan_{timestamp}.gnmap",
        '4': f"-oA scan_results/scan_{timestamp}"
    }

    output = output_formats.get(choice, output_formats['4'])
    command = f"nmap -sV {target} {output}"
    execute_scan(command, "Export Scan")

def scan_from_file():
    """Scan targets from a file"""
    file_path = input(f"\n{Colors.OKBLUE}Enter path to target file: {Colors.ENDC}\n>>> ").strip()

    if not Path(file_path).exists():
        print_color("[!] File not found.", Colors.FAIL)
        return

    output = save_output("")
    command = f"nmap -iL {file_path} -sV {output}"
    execute_scan(command, f"Scanning targets from {file_path}")

def network_info():
    """Display network interface information"""
    print_color("\n[*] Network Interface Information:", Colors.OKCYAN)
    os.system("ip addr show 2>/dev/null || ifconfig")
    print()
    print_color("[*] Routing Table:", Colors.OKCYAN)
    os.system("ip route 2>/dev/null || route -n")

# ==================== MENU FUNCTIONS ====================

def main_menu():
    """Display main menu"""
    print_color("\n╔══════════════════════════════════════════════════════════╗", Colors.OKCYAN)
    print_color("║                      MAIN MENU                           ║", Colors.OKCYAN)
    print_color("╚══════════════════════════════════════════════════════════╝", Colors.OKCYAN)

    menu_items = [
        ("1", "Quick Scans", Colors.OKGREEN),
        ("2", "NSE Script Scans", Colors.WARNING),
        ("3", "Service-Specific Scans", Colors.OKBLUE),
        ("4", "Advanced Scans", Colors.HEADER),
        ("5", "Host Discovery", Colors.OKCYAN),
        ("6", "Additional Tools", Colors.OKGREEN),
        ("7", "Reports & Utilities", Colors.WARNING),
        ("0", "Exit", Colors.FAIL),
    ]

    for num, desc, color in menu_items:
        print(f"    {color}[{num}]{Colors.ENDC} {desc}")

    choice = input(f"\n{Colors.BOLD}>>> {Colors.ENDC}").strip()
    return choice

def quick_scans_menu():
    """Quick scans submenu"""
    print_color("\n╔══════════════════════════════════════════════════════════╗", Colors.OKGREEN)
    print_color("║                    QUICK SCANS                           ║", Colors.OKGREEN)
    print_color("╚══════════════════════════════════════════════════════════╝", Colors.OKGREEN)

    print(f"""
    {Colors.OKGREEN}[1]{Colors.ENDC} Quick Scan (Top 100 ports, fast)
    {Colors.OKGREEN}[2]{Colors.ENDC} Intense Scan (Comprehensive with OS/version detection)
    {Colors.OKGREEN}[3]{Colors.ENDC} Stealth SYN Scan (Requires root)
    {Colors.OKGREEN}[4]{Colors.ENDC} UDP Scan (Top 100 UDP ports)
    {Colors.OKGREEN}[5]{Colors.ENDC} Comprehensive Scan (All 65535 ports)
    {Colors.OKGREEN}[6]{Colors.ENDC} Version Detection (Aggressive)
    {Colors.OKGREEN}[7]{Colors.ENDC} OS Detection (Requires root)
    {Colors.OKGREEN}[0]{Colors.ENDC} Back to Main Menu
    """)

    choice = input(f"{Colors.BOLD}>>> {Colors.ENDC}").strip()
    return choice

def nse_scripts_menu():
    """NSE scripts submenu"""
    print_color("\n╔══════════════════════════════════════════════════════════╗", Colors.WARNING)
    print_color("║                  NSE SCRIPT SCANS                        ║", Colors.WARNING)
    print_color("╚══════════════════════════════════════════════════════════╝", Colors.WARNING)

    print(f"""
    {Colors.WARNING}[1]{Colors.ENDC} Vulnerability Scan (vuln scripts)
    {Colors.WARNING}[2]{Colors.ENDC} Exploit Scan (exploit scripts)
    {Colors.WARNING}[3]{Colors.ENDC} Default Scripts (safe scripts)
    {Colors.WARNING}[4]{Colors.ENDC} Authentication Scan (auth & brute)
    {Colors.WARNING}[5]{Colors.ENDC} Malware Scan (malware detection)
    {Colors.WARNING}[6]{Colors.ENDC} Discovery Scan (network discovery)
    {Colors.WARNING}[7]{Colors.ENDC} Broadcast Scan (broadcast scripts)
    {Colors.WARNING}[8]{Colors.ENDC} Custom NSE Script
    {Colors.WARNING}[0]{Colors.ENDC} Back to Main Menu
    """)

    choice = input(f"{Colors.BOLD}>>> {Colors.ENDC}").strip()
    return choice

def service_scans_menu():
    """Service-specific scans submenu"""
    print_color("\n╔══════════════════════════════════════════════════════════╗", Colors.OKBLUE)
    print_color("║               SERVICE-SPECIFIC SCANS                     ║", Colors.OKBLUE)
    print_color("╚══════════════════════════════════════════════════════════╝", Colors.OKBLUE)

    print(f"""
    {Colors.OKBLUE}[1]{Colors.ENDC} SMB/Samba Scan (Port 445)
    {Colors.OKBLUE}[2]{Colors.ENDC} HTTP/HTTPS Scan (Web servers)
    {Colors.OKBLUE}[3]{Colors.ENDC} SSL/TLS Security Scan
    {Colors.OKBLUE}[4]{Colors.ENDC} DNS Enumeration (Port 53)
    {Colors.OKBLUE}[5]{Colors.ENDC} FTP Scan (Port 21)
    {Colors.OKBLUE}[6]{Colors.ENDC} SSH Scan (Port 22)
    {Colors.OKBLUE}[7]{Colors.ENDC} SQL Database Scan
    {Colors.OKBLUE}[8]{Colors.ENDC} RDP Scan (Port 3389)
    {Colors.OKBLUE}[9]{Colors.ENDC} VNC Scan (Ports 5900-5910)
    {Colors.OKBLUE}[0]{Colors.ENDC} Back to Main Menu
    """)

    choice = input(f"{Colors.BOLD}>>> {Colors.ENDC}").strip()
    return choice

def advanced_scans_menu():
    """Advanced scans submenu"""
    print_color("\n╔══════════════════════════════════════════════════════════╗", Colors.HEADER)
    print_color("║                  ADVANCED SCANS                          ║", Colors.HEADER)
    print_color("╚══════════════════════════════════════════════════════════╝", Colors.HEADER)

    print(f"""
    {Colors.HEADER}[1]{Colors.ENDC} Firewall Detection
    {Colors.HEADER}[2]{Colors.ENDC} IPv6 Scan
    {Colors.HEADER}[3]{Colors.ENDC} Script Trace (Detailed debug)
    {Colors.HEADER}[4]{Colors.ENDC} Custom Timing Scan
    {Colors.HEADER}[5]{Colors.ENDC} Fragmentation Scan (Firewall evasion)
    {Colors.HEADER}[6]{Colors.ENDC} Decoy Scan (Hide source)
    {Colors.HEADER}[7]{Colors.ENDC} Zombie/Idle Scan
    {Colors.HEADER}[0]{Colors.ENDC} Back to Main Menu
    """)

    choice = input(f"{Colors.BOLD}>>> {Colors.ENDC}").strip()
    return choice

def host_discovery_menu():
    """Host discovery submenu"""
    print_color("\n╔══════════════════════════════════════════════════════════╗", Colors.OKCYAN)
    print_color("║                  HOST DISCOVERY                          ║", Colors.OKCYAN)
    print_color("╚══════════════════════════════════════════════════════════╝", Colors.OKCYAN)

    print(f"""
    {Colors.OKCYAN}[1]{Colors.ENDC} Ping Sweep (ICMP)
    {Colors.OKCYAN}[2]{Colors.ENDC} ARP Scan (Local network)
    {Colors.OKCYAN}[3]{Colors.ENDC} TCP Ping
    {Colors.OKCYAN}[4]{Colors.ENDC} No Ping Scan (Skip discovery)
    {Colors.OKCYAN}[5]{Colors.ENDC} FPing Sweep (Fast ICMP)
    {Colors.OKCYAN}[0]{Colors.ENDC} Back to Main Menu
    """)

    choice = input(f"{Colors.BOLD}>>> {Colors.ENDC}").strip()
    return choice

def additional_tools_menu():
    """Additional tools submenu"""
    print_color("\n╔══════════════════════════════════════════════════════════╗", Colors.OKGREEN)
    print_color("║                  ADDITIONAL TOOLS                        ║", Colors.OKGREEN)
    print_color("╚══════════════════════════════════════════════════════════╝", Colors.OKGREEN)

    print(f"""
    {Colors.OKGREEN}[1]{Colors.ENDC} Masscan (Ultra-fast)
    {Colors.OKGREEN}[2]{Colors.ENDC} Banner Grabbing
    {Colors.OKGREEN}[3]{Colors.ENDC} WHOIS Lookup
    {Colors.OKGREEN}[4]{Colors.ENDC} DNS Enumeration (dnsenum)
    {Colors.OKGREEN}[5]{Colors.ENDC} Subdomain Enumeration
    {Colors.OKGREEN}[6]{Colors.ENDC} Network Interface Info
    {Colors.OKGREEN}[0]{Colors.ENDC} Back to Main Menu
    """)

    choice = input(f"{Colors.BOLD}>>> {Colors.ENDC}").strip()
    return choice

def reports_menu():
    """Reports and utilities submenu"""
    print_color("\n╔══════════════════════════════════════════════════════════╗", Colors.WARNING)
    print_color("║                REPORTS & UTILITIES                       ║", Colors.WARNING)
    print_color("╚══════════════════════════════════════════════════════════╝", Colors.WARNING)

    print(f"""
    {Colors.WARNING}[1]{Colors.ENDC} View Scan Results
    {Colors.WARNING}[2]{Colors.ENDC} Export Scan (Custom format)
    {Colors.WARNING}[3]{Colors.ENDC} Scan from File
    {Colors.WARNING}[0]{Colors.ENDC} Back to Main Menu
    """)

    choice = input(f"{Colors.BOLD}>>> {Colors.ENDC}").strip()
    return choice

# ==================== MAIN PROGRAM ====================

def handle_quick_scans(choice):
    """Handle quick scans menu choices"""
    handlers = {
        '1': quick_scan,
        '2': intense_scan,
        '3': stealth_scan,
        '4': udp_scan,
        '5': comprehensive_scan,
        '6': version_detection,
        '7': os_detection,
    }

    handler = handlers.get(choice)
    if handler:
        handler()
    elif choice != '0':
        print_color("Invalid option!", Colors.FAIL)

def handle_nse_scripts(choice):
    """Handle NSE scripts menu choices"""
    handlers = {
        '1': vuln_scan,
        '2': exploit_scan,
        '3': default_scripts,
        '4': auth_scan,
        '5': malware_scan,
        '6': discovery_scan,
        '7': broadcast_scan,
        '8': custom_nse_script,
    }

    handler = handlers.get(choice)
    if handler:
        handler()
    elif choice != '0':
        print_color("Invalid option!", Colors.FAIL)

def handle_service_scans(choice):
    """Handle service-specific scans menu choices"""
    handlers = {
        '1': smb_scan,
        '2': http_scan,
        '3': ssl_scan,
        '4': dns_scan,
        '5': ftp_scan,
        '6': ssh_scan,
        '7': sql_scan,
        '8': rdp_scan,
        '9': vnc_scan,
    }

    handler = handlers.get(choice)
    if handler:
        handler()
    elif choice != '0':
        print_color("Invalid option!", Colors.FAIL)

def handle_advanced_scans(choice):
    """Handle advanced scans menu choices"""
    handlers = {
        '1': firewall_detection,
        '2': ipv6_scan,
        '3': script_trace,
        '4': timing_scan,
        '5': fragmentation_scan,
        '6': decoy_scan,
        '7': zombie_scan,
    }

    handler = handlers.get(choice)
    if handler:
        handler()
    elif choice != '0':
        print_color("Invalid option!", Colors.FAIL)

def handle_host_discovery(choice):
    """Handle host discovery menu choices"""
    handlers = {
        '1': ping_sweep,
        '2': arp_scan,
        '3': tcp_ping,
        '4': no_ping_scan,
        '5': fping_sweep,
    }

    handler = handlers.get(choice)
    if handler:
        handler()
    elif choice != '0':
        print_color("Invalid option!", Colors.FAIL)

def handle_additional_tools(choice):
    """Handle additional tools menu choices"""
    handlers = {
        '1': masscan_fast,
        '2': banner_grab,
        '3': whois_lookup,
        '4': dns_enum,
        '5': subdomain_enum,
        '6': network_info,
    }

    handler = handlers.get(choice)
    if handler:
        handler()
    elif choice != '0':
        print_color("Invalid option!", Colors.FAIL)

def handle_reports(choice):
    """Handle reports menu choices"""
    handlers = {
        '1': view_scan_results,
        '2': export_scan,
        '3': scan_from_file,
    }

    handler = handlers.get(choice)
    if handler:
        handler()
    elif choice != '0':
        print_color("Invalid option!", Colors.FAIL)

def main():
    """Main program loop"""
    os.system('clear' if os.name == 'posix' else 'cls')
    print_banner()

    # Check for required tools
    print_color("[*] Checking for required tools...", Colors.OKCYAN)
    required_tools = ['nmap', 'fping']
    missing_tools = []

    for tool in required_tools:
        result = subprocess.run(['which', tool], capture_output=True, text=True)
        if result.returncode != 0:
            missing_tools.append(tool)

    if missing_tools:
        print_color(f"[!] Warning: Missing tools: {', '.join(missing_tools)}", Colors.WARNING)
        print_color("[*] Some features may not work. Please install missing tools.", Colors.WARNING)
    else:
        print_color("[✓] All required tools found!", Colors.OKGREEN)

    time.sleep(1)

    while True:
        choice = main_menu()

        if choice == '0':
            print_color("\n[*] Exiting theScanner... Stay safe!", Colors.OKCYAN)
            slowprint("Goodbye!", 5/1000)
            break
        elif choice == '1':
            while True:
                sub_choice = quick_scans_menu()
                if sub_choice == '0':
                    break
                handle_quick_scans(sub_choice)
        elif choice == '2':
            while True:
                sub_choice = nse_scripts_menu()
                if sub_choice == '0':
                    break
                handle_nse_scripts(sub_choice)
        elif choice == '3':
            while True:
                sub_choice = service_scans_menu()
                if sub_choice == '0':
                    break
                handle_service_scans(sub_choice)
        elif choice == '4':
            while True:
                sub_choice = advanced_scans_menu()
                if sub_choice == '0':
                    break
                handle_advanced_scans(sub_choice)
        elif choice == '5':
            while True:
                sub_choice = host_discovery_menu()
                if sub_choice == '0':
                    break
                handle_host_discovery(sub_choice)
        elif choice == '6':
            while True:
                sub_choice = additional_tools_menu()
                if sub_choice == '0':
                    break
                handle_additional_tools(sub_choice)
        elif choice == '7':
            while True:
                sub_choice = reports_menu()
                if sub_choice == '0':
                    break
                handle_reports(sub_choice)
        else:
            print_color("\n[!] Invalid option! Please try again.", Colors.FAIL)
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_color("\n\n[!] Scan interrupted by user.", Colors.WARNING)
        print_color("[*] Exiting gracefully...", Colors.OKCYAN)
        sys.exit(0)
    except Exception as e:
        print_color(f"\n[✗] An error occurred: {str(e)}", Colors.FAIL)
        sys.exit(1)
