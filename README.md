# theScanner v2.0

<div align="center">

```
  _   _           _____
 | | | |         / ____|
 | |_| |__   ___| (___   ___ __ _ _ __  _ __   ___ _ __
 | __| '_ \ / _ \\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |_| | | |  __/____) | (_| (_| | | | | | | |  __/ |
  \__|_| |_|\___|_____/ \___\__,_|_| |_|_| |_|\___|_|
```

**Advanced Network Reconnaissance Tool**

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Nmap](https://img.shields.io/badge/Nmap-Required-red.svg)](https://nmap.org/)

</div>

---

## Overview

theScanner is a comprehensive, feature-rich network reconnaissance and vulnerability assessment tool built around Nmap and other security tools. It provides an intuitive menu-driven interface for performing various types of network scans, from basic host discovery to advanced vulnerability assessments using NSE (Nmap Scripting Engine) scripts.

### Key Features

- **50+ Scan Types** across 7 major categories
- **Extensive NSE Script Integration** for vulnerability detection
- **Service-Specific Scanning** for SMB, HTTP, FTP, SSH, SQL, RDP, VNC, DNS, and SSL/TLS
- **Advanced Evasion Techniques** including stealth, fragmentation, and decoy scans
- **Automated Result Saving** with timestamped output files
- **Multiple Export Formats** (Normal, XML, Grepable)
- **Colored Terminal Output** for better readability
- **Input Validation** to prevent command injection
- **Comprehensive Error Handling** for robust operation

---

## Table of Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Usage](#usage)
- [Feature Categories](#feature-categories)
  - [Quick Scans](#1-quick-scans)
  - [NSE Script Scans](#2-nse-script-scans)
  - [Service-Specific Scans](#3-service-specific-scans)
  - [Advanced Scans](#4-advanced-scans)
  - [Host Discovery](#5-host-discovery)
  - [Additional Tools](#6-additional-tools)
  - [Reports & Utilities](#7-reports--utilities)
- [NSE Scripts Reference](#nse-scripts-reference)
- [Output Formats](#output-formats)
- [Examples](#examples)
- [Legal Disclaimer](#legal-disclaimer)

---

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/00xNetrunner/theScanner.git
cd theScanner

# Make executable
chmod +x theScanner.py

# Run
sudo python3 theScanner.py
```

### Docker Installation (Optional)

```bash
# Build Docker image
docker build -t thescanner .

# Run in container
docker run -it --rm --network host thescanner
```

---

## Requirements

### Essential Tools

- **Python 3.6+**
- **Nmap** - Network scanner
- **fping** - Fast ping utility

### Optional Tools

- **masscan** - Ultra-fast port scanner
- **dnsenum** - DNS enumeration tool
- **whois** - Domain information lookup
- **netcat (nc)** - Banner grabbing

### Installation Commands

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nmap fping masscan dnsenum whois netcat
```

#### CentOS/RHEL
```bash
sudo yum install nmap fping masscan bind-utils whois nc
```

#### macOS
```bash
brew install nmap fping masscan
```

#### Arch Linux
```bash
sudo pacman -S nmap fping masscan bind-tools whois gnu-netcat
```

---

## Usage

### Basic Execution

```bash
# Standard user (limited features)
python3 theScanner.py

# Root user (full features including SYN scans, OS detection)
sudo python3 theScanner.py
```

### Navigation

- Use **number keys** to select menu options
- Press **0** to return to previous menu or exit
- Press **Ctrl+C** to interrupt a scan gracefully

### Input Formats

#### IP Addresses
- Single IP: `192.168.1.1`
- CIDR notation: `192.168.1.0/24`
- Range: `192.168.1.1-254`
- Wildcard: `192.168.1.*`

#### Port Specification
- Single port: `80`
- Multiple ports: `80,443,8080`
- Port range: `1-1000`
- Combined: `22,80,443,8000-9000`

---

## Feature Categories

### 1. Quick Scans

Fast and efficient scanning profiles for common scenarios.

| Scan Type | Description | Speed | Privileges |
|-----------|-------------|-------|------------|
| **Quick Scan** | Top 100 most common ports | Fast | User |
| **Intense Scan** | Comprehensive scan with OS/version detection | Medium | User |
| **Stealth SYN Scan** | Half-open TCP SYN scan | Medium | Root |
| **UDP Scan** | Top 100 UDP ports | Slow | Root |
| **Comprehensive Scan** | All 65535 TCP ports | Very Slow | User |
| **Version Detection** | Aggressive service version detection | Medium | User |
| **OS Detection** | Operating system fingerprinting | Fast | Root |

#### Example Commands Generated:
```bash
# Quick Scan
nmap -T4 -F 192.168.1.1

# Intense Scan
nmap -T4 -A -v 192.168.1.1

# Stealth SYN Scan
sudo nmap -sS -T2 192.168.1.1
```

---

### 2. NSE Script Scans

Leverage Nmap's powerful scripting engine for advanced reconnaissance and vulnerability detection.

| Script Category | Purpose | Risk Level | Scripts Used |
|----------------|---------|------------|--------------|
| **Vulnerability Scan** | Detect known vulnerabilities | Safe | vuln category |
| **Exploit Scan** | Check for exploitable services | Intrusive | exploit category |
| **Default Scripts** | Safe, standard reconnaissance | Safe | default category |
| **Authentication Scan** | Test auth mechanisms & brute force | Intrusive | auth, brute |
| **Malware Scan** | Detect backdoors and malware | Safe | malware category |
| **Discovery Scan** | Network and service discovery | Safe | discovery category |
| **Broadcast Scan** | Network-wide broadcast discovery | Safe | broadcast category |
| **Custom NSE Script** | Run specific scripts or categories | Varies | User-specified |

#### NSE Categories Available:
- `auth` - Authentication bypass and testing
- `broadcast` - Network broadcast discovery
- `brute` - Brute force password attacks
- `default` - Default safe scripts (-sC)
- `discovery` - Host and service discovery
- `dos` - Denial of service detection
- `exploit` - Exploitation scripts
- `external` - External resource queries
- `fuzzer` - Fuzzing scripts
- `intrusive` - Potentially harmful scripts
- `malware` - Malware detection
- `safe` - Safe scripts
- `version` - Version detection
- `vuln` - Vulnerability detection

#### Example Commands:
```bash
# Vulnerability Scan
nmap --script vuln -sV 192.168.1.1

# Custom Script
nmap --script http-shellshock -p80 192.168.1.1
```

---

### 3. Service-Specific Scans

Targeted scanning for specific services with relevant NSE scripts.

#### SMB/Samba Scan (Port 445)
- OS discovery
- Share enumeration
- User enumeration
- Vulnerability checks (MS17-010, MS08-067, etc.)

```bash
nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln* -p445 192.168.1.1
```

#### HTTP/HTTPS Scan
- Directory enumeration
- Header analysis
- HTTP methods detection
- Web vulnerabilities (SQLi, XSS, etc.)

```bash
nmap --script http-enum,http-headers,http-methods,http-title,http-vuln* -p80,443,8080,8443 192.168.1.1
```

#### SSL/TLS Security Scan
- Certificate information
- Cipher suite enumeration
- Heartbleed detection
- POODLE vulnerability
- Weak DH parameters

```bash
nmap --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params -p443 192.168.1.1
```

#### DNS Enumeration (Port 53)
- Subdomain brute forcing
- Zone transfer attempts
- DNS recursion testing
- NSID information

```bash
nmap --script dns-brute,dns-zone-transfer,dns-nsid,dns-recursion -p53 192.168.1.1
```

#### FTP Scan (Port 21)
- Anonymous access detection
- FTP bounce attack testing
- Vulnerability checks
- Brute force authentication

```bash
nmap --script ftp-anon,ftp-bounce,ftp-vuln*,ftp-brute -p21 192.168.1.1
```

#### SSH Scan (Port 22)
- Authentication methods
- Host key collection
- Algorithm enumeration
- Weak key detection

```bash
nmap --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -p22 192.168.1.1
```

#### SQL Database Scan
- MySQL (3306)
- MS-SQL (1433)
- PostgreSQL (5432)
- Oracle (1521)

```bash
nmap --script mysql-*,ms-sql-*,oracle-*,pgsql-* -p1433,3306,5432,1521 192.168.1.1
```

#### RDP Scan (Port 3389)
- Encryption enumeration
- BlueKeep (CVE-2019-0708) detection
- Security configuration analysis

```bash
nmap --script rdp-enum-encryption,rdp-vuln* -p3389 192.168.1.1
```

#### VNC Scan (Ports 5900-5910)
- VNC information gathering
- Authentication bypass attempts
- Brute force authentication

```bash
nmap --script vnc-info,vnc-brute,realvnc-auth-bypass -p5900-5910 192.168.1.1
```

---

### 4. Advanced Scans

Sophisticated scanning techniques for firewall evasion and stealth.

#### Firewall Detection
Uses ACK scan to determine firewall rules and packet filtering.
```bash
nmap -sA -T4 --script firewall-bypass 192.168.1.1
```

#### IPv6 Scan
Scan IPv6 addresses and networks.
```bash
nmap -6 -sV fe80::1
```

#### Script Trace
Detailed debugging output for NSE script execution.
```bash
nmap --script http-vuln-cve2017-5638 --script-trace 192.168.1.1
```

#### Custom Timing Scan
Choose from 6 timing templates (0-5):
- **T0 (Paranoid)**: IDS evasion, extremely slow
- **T1 (Sneaky)**: IDS evasion, slow
- **T2 (Polite)**: Less bandwidth intensive
- **T3 (Normal)**: Default timing
- **T4 (Aggressive)**: Fast, parallel scanning
- **T5 (Insane)**: Very fast, may miss hosts

```bash
nmap -T2 -sV 192.168.1.1  # Polite scan
```

#### Fragmentation Scan
Fragment packets to evade firewall inspection.
```bash
sudo nmap -f -sS 192.168.1.1
```

#### Decoy Scan
Use decoy IP addresses to hide scan source.
```bash
nmap -D RND:10 192.168.1.1  # 10 random decoys
```

#### Zombie/Idle Scan
Ultra-stealthy scan using a zombie host.
```bash
sudo nmap -sI zombie_host target_host
```

---

### 5. Host Discovery

Determine which hosts are alive on the network.

| Method | Description | Speed | Privileges | Protocol |
|--------|-------------|-------|------------|----------|
| **Ping Sweep** | ICMP echo requests | Fast | User | ICMP |
| **ARP Scan** | ARP requests (local network) | Very Fast | Root | ARP |
| **TCP Ping** | TCP SYN to common ports | Fast | User | TCP |
| **No Ping Scan** | Skip host discovery | N/A | User | N/A |
| **FPing Sweep** | Fast ICMP with fping | Very Fast | User | ICMP |

#### Examples:
```bash
# Ping Sweep
nmap -sn -PE 192.168.1.0/24

# ARP Scan (local network only)
sudo nmap -PR 192.168.1.0/24

# TCP Ping
nmap -sn -PS80,443,22 192.168.1.0/24

# FPing
fping -a -g 192.168.1.0/24
```

---

### 6. Additional Tools

Complementary tools for comprehensive network reconnaissance.

#### Masscan
Ultra-fast port scanner capable of scanning the entire Internet.
```bash
sudo masscan 192.168.1.0/24 -p1-65535 --rate=1000
```
- Scans all 65535 ports
- Configurable packet rate
- Results saved automatically

#### Banner Grabbing
Connect to services and capture banners.
```bash
nc -v 192.168.1.1 80
```

#### WHOIS Lookup
Domain registration and ownership information.
```bash
whois example.com
```

#### DNS Enumeration (dnsenum)
Comprehensive DNS enumeration including:
- NS records
- MX records
- A records
- Zone transfers
- Subdomain brute forcing

```bash
dnsenum example.com
```

#### Subdomain Enumeration
Discover subdomains using NSE scripts.
```bash
nmap --script dns-brute example.com
```

#### Network Interface Info
Display network configuration, interfaces, and routing.
```bash
ip addr show
ip route
```

---

### 7. Reports & Utilities

Manage and analyze scan results.

#### View Scan Results
Browse and view the 10 most recent scans with timestamps.
- Automatic sorting by date
- Quick preview with `less`
- Support for all output formats

#### Export Scan
Save scans in multiple formats:
1. **Normal (.nmap)** - Human-readable text format
2. **XML (.xml)** - Machine-parseable format
3. **Grepable (.gnmap)** - Easy to grep/parse
4. **All formats (-oA)** - Save in all three formats

```bash
# All formats
nmap -sV 192.168.1.1 -oA scan_results/scan_20231114_153045
```

#### Scan from File
Scan multiple targets from a text file (one target per line).
```bash
nmap -iL targets.txt -sV
```

---

## NSE Scripts Reference

### Most Useful NSE Scripts

#### Vulnerability Detection
```bash
# EternalBlue (MS17-010)
nmap --script smb-vuln-ms17-010 -p445 192.168.1.1

# Heartbleed
nmap --script ssl-heartbleed -p443 192.168.1.1

# Shellshock
nmap --script http-shellshock --script-args uri=/cgi-bin/test.sh -p80 192.168.1.1

# All SMB vulnerabilities
nmap --script smb-vuln* -p445 192.168.1.1
```

#### Web Application Testing
```bash
# SQL injection detection
nmap --script http-sql-injection -p80 192.168.1.1

# Directory traversal
nmap --script http-passwd,http-traversal -p80 192.168.1.1

# WordPress scanning
nmap --script http-wordpress-enum -p80 192.168.1.1
```

#### Brute Force Attacks
```bash
# SSH brute force
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt -p22 192.168.1.1

# FTP brute force
nmap --script ftp-brute -p21 192.168.1.1

# MySQL brute force
nmap --script mysql-brute -p3306 192.168.1.1
```

### Finding Available Scripts
```bash
# List all scripts
ls /usr/share/nmap/scripts/

# Search for specific scripts
ls /usr/share/nmap/scripts/ | grep http

# Get script documentation
nmap --script-help http-vuln-cve2017-5638
```

---

## Output Formats

### Normal Output (.nmap)
Human-readable format, best for manual review.
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

### XML Output (.xml)
Machine-parseable format, best for automation.
```xml
<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1699999999">
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

### Grepable Output (.gnmap)
Optimized for grep/awk parsing.
```
Host: 192.168.1.1 ()    Status: Up
Host: 192.168.1.1 ()    Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
```

### Output Locations
All scan results are automatically saved to:
```
theScanner/
└── scan_results/
    ├── scan_20231114_153045.nmap
    ├── scan_20231114_153045.xml
    └── scan_20231114_153045.gnmap
```

---

## Examples

### Basic Network Reconnaissance
```bash
# 1. Discover live hosts
Select: 5 (Host Discovery) → 1 (Ping Sweep)
Target: 192.168.1.0/24

# 2. Quick scan of discovered hosts
Select: 1 (Quick Scans) → 1 (Quick Scan)
Target: 192.168.1.1-254

# 3. Detailed scan of interesting hosts
Select: 1 (Quick Scans) → 2 (Intense Scan)
Target: 192.168.1.10
```

### Web Server Assessment
```bash
# 1. Scan web ports
Select: 3 (Service-Specific Scans) → 2 (HTTP/HTTPS Scan)
Target: 192.168.1.50

# 2. SSL/TLS security
Select: 3 (Service-Specific Scans) → 3 (SSL/TLS Scan)
Target: 192.168.1.50

# 3. Check for vulnerabilities
Select: 2 (NSE Script Scans) → 1 (Vulnerability Scan)
Target: 192.168.1.50
Ports: 80,443
```

### Vulnerability Assessment
```bash
# 1. Check for SMB vulnerabilities (EternalBlue, etc.)
Select: 3 (Service-Specific Scans) → 1 (SMB/Samba Scan)
Target: 192.168.1.0/24

# 2. Run comprehensive vulnerability scan
Select: 2 (NSE Script Scans) → 1 (Vulnerability Scan)
Target: 192.168.1.0/24

# 3. Check for specific exploits
Select: 2 (NSE Script Scans) → 8 (Custom NSE Script)
Script: smb-vuln-ms17-010
Target: 192.168.1.10
```

### Stealth Scanning
```bash
# 1. Stealth SYN scan
Select: 1 (Quick Scans) → 3 (Stealth SYN Scan)
Target: 192.168.1.100

# 2. Fragmentation for evasion
Select: 4 (Advanced Scans) → 5 (Fragmentation Scan)
Target: 192.168.1.100

# 3. Decoy scan
Select: 4 (Advanced Scans) → 6 (Decoy Scan)
Target: 192.168.1.100
```

---

## Legal Disclaimer

**IMPORTANT: READ BEFORE USING**

### Authorization Required
This tool is designed for **authorized security testing only**. You must have explicit written permission to scan any network or system that you do not own.

### Legal Use Cases
- Your own networks and systems
- Authorized penetration testing engagements
- Security research with written permission
- Educational purposes in lab environments
- CTF (Capture The Flag) competitions
- Bug bounty programs within scope

### Illegal Activities
Unauthorized network scanning may violate:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other jurisdictions

### Disclaimer
The author and contributors:
- Are not responsible for misuse of this tool
- Do not endorse illegal activities
- Provide this tool for educational and authorized testing purposes only
- Assume no liability for damages caused by use or misuse

**USE AT YOUR OWN RISK**

Always ensure you have proper authorization before conducting any security testing.

---

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

### Areas for Contribution
- Additional NSE script integrations
- New scan profiles
- Performance optimizations
- Documentation improvements
- Bug fixes

---

## Changelog

### v2.0 (Current)
- Complete rewrite with 50+ scan types
- Extensive NSE script integration
- Service-specific scanning modules
- Advanced evasion techniques
- Colored output and improved UX
- Automatic result saving with timestamps
- Multiple export formats
- Comprehensive error handling
- Input validation and security improvements

### v1.0
- Basic Nmap scan
- FPing host discovery
- Simple menu interface

---

## Credits

- **Coded by**: ./Netrunner_&
- **Nmap**: Gordon Lyon (Fyodor)
- **Python**: Python Software Foundation

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Submit a pull request
- Contact: [Your Contact Info]

---

<div align="center">

**Stay Ethical. Stay Legal. Stay Secure.**

Made with ❤️ for the security community

</div>
