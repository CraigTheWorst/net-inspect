# net-inspect v1.0.0

**Advanced Network Security Intelligence & Reconnaissance Platform**

A comprehensive, professional-grade network security tool combining automated reconnaissance, vulnerability assessment, threat intelligence, traffic analysis, and spoof detection into a unified platform for penetration testers, security researchers, and network administrators.

---

## ⚠️ LEGAL DISCLAIMER

**READ THIS BEFORE USING THIS TOOL**

This tool is provided for **LEGAL AND AUTHORIZED USE ONLY**. The authors and contributors of net-inspect are **NOT RESPONSIBLE** for any misuse, damage, or illegal activities conducted with this software.

### Authorized Use Cases:
- ✅ Security assessments of networks **you own or have explicit written permission** to test
- ✅ Penetration testing engagements with **proper authorization agreements**
- ✅ Network administration and monitoring of **your own infrastructure**
- ✅ Security research and education in **controlled lab environments**
- ✅ Capture The Flag (CTF) competitions and **authorized training exercises**

### Prohibited Activities:
- ❌ **Unauthorized network scanning** of systems you don't own or control
- ❌ **Malicious activities** including but not limited to: hacking, data theft, service disruption
- ❌ **Privacy violations** or unauthorized interception of network communications
- ❌ **Violation of the Computer Fraud and Abuse Act (CFAA)** or similar laws in your jurisdiction
- ❌ **Corporate espionage** or unauthorized competitive intelligence gathering
- ❌ **Network attacks** including DoS, DDoS, or any destructive activities

### Your Responsibilities:
By using this tool, you agree that:
1. You have **explicit authorization** to scan and test the target networks
2. You will **comply with all applicable laws** in your jurisdiction
3. You accept **full legal responsibility** for your actions
4. You will **use this tool ethically and professionally**
5. You understand that **unauthorized network scanning may be illegal** and result in criminal prosecution

**THE AUTHORS DISCLAIM ALL LIABILITY FOR MISUSE OF THIS SOFTWARE. USE AT YOUR OWN RISK.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Capabilities](#core-capabilities)
- [Command-Line Reference](#command-line-reference)
- [Usage Examples](#usage-examples)
- [Advanced Features](#advanced-features)
- [Output Formats](#output-formats)
- [Integration](#integration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**net-inspect** is a next-generation network security reconnaissance platform that goes far beyond traditional port scanners. Built with modern security operations in mind, it provides comprehensive network visibility, vulnerability intelligence, and threat detection capabilities in a single, easy-to-use tool.

### What Makes net-inspect Different?

- **🎯 Real-Time Vulnerability Intelligence**: Direct integration with NIST NVD and CISA KEV for actual CVE detection
- **🔍 Advanced Spoof Detection**: Multi-layer correlation engine to identify spoofed, cloned, or suspicious devices
- **🌐 Public IP Geolocation**: Locate your network's public IP with detailed ISP and geographic information
- **📊 Traffic Analysis**: Deep packet inspection with credential extraction and protocol analysis
- **🔒 TLS/SSL Security Audits**: Certificate validation, weak cipher detection, and TLS version analysis
- **📈 Network Topology Mapping**: Visual representation of your network infrastructure
- **🎨 Professional Reporting**: Generate executive-ready PDF reports with vulnerability breakdowns
- **🚨 Threat Intelligence**: Integration with threat feeds and exploit databases
- **🌍 Full IPv6 Support**: Dual-stack scanning with automatic IPv6 network detection
- **📦 Modular Architecture**: Clean, maintainable codebase with separate modules for each capability

---

## Key Features

### 🔎 Network Discovery & Reconnaissance
- **Host Discovery**: Fast network-wide device detection using ARP, ICMP, and TCP
- **Service Detection**: Identify running services, versions, and banners
- **OS Fingerprinting**: Accurate operating system detection for all discovered hosts
- **MAC Vendor Lookup**: Identify device manufacturers with enhanced vendor database
- **Hostname Resolution**: Multi-method hostname discovery (DNS, mDNS, NetBIOS, Avahi)
- **Network Topology Mapping**: Visualize your network structure with hierarchical tree views

### 🛡️ Vulnerability Assessment
- **Real-Time CVE Detection**: Query NIST NVD database for 250,000+ known vulnerabilities
- **CISA KEV Integration**: Identify actively exploited vulnerabilities in the wild
- **Service Version Mapping**: Automatic CVE lookup based on detected service versions
- **CVSS Scoring**: Severity ratings and risk scores for all detected vulnerabilities
- **Exploit Database Integration**: Find available exploits via searchsploit
- **Professional Vulnerability Reports**: Tree-style vulnerability analysis with attack vectors and business impact

### 🚨 Threat Detection & Intelligence
- **Spoof Detection**: Multi-layer correlation analysis to detect spoofed or suspicious hosts
  - MAC/Vendor mismatch detection
  - Hostname inconsistency analysis
  - OS fingerprint validation
  - Behavioral anomaly detection
- **Threat Intelligence Feeds**: Integration with external threat databases
- **Baseline Comparison**: Detect rogue devices by comparing against known-good network states
- **Suspicious Protocol Detection**: Identify unencrypted or insecure protocols (RTSP, HTTP, FTP, Telnet)

### 📡 Traffic Analysis & Monitoring
- **Packet Capture**: Automated tcpdump integration for full network traffic capture
- **Deep Packet Inspection**: Protocol analysis and traffic pattern recognition
- **Credential Extraction**: Detect plaintext credentials in network traffic
- **Certificate Analysis**: Extract and validate SSL/TLS certificates
- **Session Analysis**: Track network sessions and connection patterns
- **File Carving**: Extract files from network traffic captures

### 🔐 Security Auditing
- **TLS/SSL Security Audits**:
  - Certificate validation and expiration checks
  - Weak cipher suite detection
  - Protocol version analysis (SSLv3, TLS 1.0/1.1/1.2/1.3)
  - Self-signed certificate detection
- **Firewall Testing**: Identify firewall rules and port filtering
- **Network Segmentation Analysis**: Verify proper network isolation

### 🌍 Geolocation & Network Intelligence
- **Public IP Geolocation**:
  - Geographic location of your public IP (city, region, country)
  - ISP and organization identification
  - AS Number lookup
  - Reverse DNS resolution
  - Google Maps integration
  - Country flag emoji display
- **Individual Host Geolocation**: Locate specific IP addresses globally
- **Timezone and Postal Code**: Additional geographic metadata

### 🔬 Advanced Enumeration
Optional deep-dive enumeration modules for comprehensive reconnaissance:

- **DNS Enumeration**:
  - Zone transfers (AXFR)
  - Reverse DNS lookups
  - Record queries (A, AAAA, MX, TXT, NS, SOA)
  - Subdomain discovery

- **SMB Enumeration**:
  - Null session testing
  - Share enumeration
  - User and group discovery
  - Domain information gathering

- **HTTP/HTTPS Enumeration**:
  - HTTP header analysis
  - SSL certificate extraction
  - Directory enumeration
  - Web technology fingerprinting

- **SNMP Enumeration**:
  - Community string testing
  - System information gathering
  - Network interface enumeration

- **Email Enumeration**:
  - SMTP capability detection
  - TLS/STARTTLS support testing
  - Authentication mechanism discovery

- **Secrets Scanning**:
  - API key detection
  - Private key discovery
  - Credential exposure checking

### 📄 Reporting & Export
- **PDF Report Generation**: Executive-ready professional reports with:
  - Network summary and statistics
  - Vulnerability analysis with CVSS scores
  - Device inventory and risk ratings
  - Threat assessment and recommendations
  - Network topology diagrams

- **Multiple Export Formats**:
  - JSON (machine-readable, perfect for automation)
  - CSV (spreadsheet-compatible)
  - Formatted terminal output (human-readable with Rich library)

- **Customizable Report Formats**:
  - Professional (default)
  - Executive summary
  - Technical deep-dive

### 🎛️ Flexible Scanning Modes

#### Scan Profiles
| Profile | Description | Discovery | OS Detection | Scripts | Use Case |
|---------|-------------|-----------|--------------|---------|----------|
| **quiet** | Minimal network noise | ARP only | No | No | Stealth operations, IDS evasion |
| **balanced** | Default mode *(recommended)* | SYN scan | Yes | Limited | General purpose scanning |
| **aggressive** | Maximum information gathering | Full scan | Yes | Yes | Thorough security assessments |

#### Timing Templates
Control scan speed vs. stealth trade-off:

| Timing | Nmap | Speed | Stealth | Network Impact | Use Case |
|--------|------|-------|---------|----------------|----------|
| **paranoid** | T0 | Slowest | Maximum | Minimal | IDS evasion, ultra-stealth |
| **sneaky** | T1 | Very slow | High | Very Low | Stealth scanning |
| **polite** | T2 | Slow | Moderate | Low | Network-friendly scans |
| **normal** | T3 | Default | Normal | Moderate | Standard assessments |
| **aggressive** | T4 | Fast | Low | High | Quick reconnaissance |
| **insane** | T5 | Fastest | None | Very High | Speed over stealth |

### 🌐 IPv6 Support
- **Full IPv6 Scanning**: Native support for IPv6 networks (fe80::/64, 2001:db8::/32, etc.)
- **Automatic IPv6 Discovery**: Use `--ipv6` flag to auto-detect IPv6 networks
- **Dual-Stack Scanning**: Scan both IPv4 and IPv6 simultaneously
- **IPv6 NDP Support**: Neighbor Discovery Protocol for MAC address resolution
- **Link-Local and Global Unicast**: Support for all IPv6 address types

---

## Installation

### System Requirements

**Operating System:**
- Linux (Arch, Debian, Ubuntu, Kali, Fedora, etc.)
- macOS (with limitations on packet capture)

**Software Requirements:**
- **Python**: 3.8 or higher
- **Privileges**: Root/sudo access (required for raw sockets and packet capture)
- **Disk Space**: ~500MB for full installation with dependencies

### Required Dependencies

**System Tools:**
- `nmap` - Network scanning and service detection (**required**)
- `ip` / `iproute2` - Network interface management (**required**)

**Optional Tools** (enhance functionality):
- `tcpdump` - Packet capture for traffic analysis
- `traceroute` - Network path discovery
- `avahi-resolve` - mDNS hostname resolution
- `nmblookup` - NetBIOS name resolution
- `searchsploit` / `exploitdb` - Exploit database lookups
- `openssl` - SSL/TLS certificate inspection

**Python Packages:**
- `rich` - Enhanced terminal formatting (**recommended**)
- `requests` - HTTP client for NVD API and threat intelligence (**required for CVE checking**)
- `manuf` - MAC address vendor lookup (**recommended**)
- `scapy` - Packet manipulation and traffic analysis (**required for traffic analysis**)
- `reportlab` - PDF report generation (**required for PDF reports**)

### Install from Source

```bash
# Clone or navigate to the repository
cd ~/Documents/net-inspect

# Install Python dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e . --break-system-packages  # Use if on system Python

# Or without --break-system-packages if using venv:
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Install system dependencies
# Arch Linux:
sudo pacman -S nmap tcpdump traceroute avahi samba openssl exploitdb

# Debian/Ubuntu:
sudo apt install nmap tcpdump traceroute avahi-daemon smbclient openssl exploitdb

# Fedora:
sudo dnf install nmap tcpdump traceroute avahi samba-client openssl
```

### Verify Installation

```bash
# Check installation
net-inspect --help

# Verify dependencies
sudo PYTHONPATH=~/Documents/net-inspect python3 -m netinspect --help

# Run dependency check
sudo net-inspect --cidr 127.0.0.1/32
# (will show dependency table at startup)
```

### Post-Installation Configuration

**Optional: Get NVD API Key (Recommended)**

For 10x faster CVE lookups:

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Request a free API key (no credit card required)
3. Set environment variable:
   ```bash
   echo 'export NVD_API_KEY="your-key-here"' >> ~/.bashrc
   source ~/.bashrc
   ```

---

## Quick Start

### Basic Network Scan

```bash
# Simple network discovery
sudo net-inspect --cidr 192.168.1.0/24

# Scan with CVE vulnerability checking
sudo net-inspect --cidr 192.168.1.0/24 --cve-check

# Full security assessment
sudo net-inspect --cidr 192.168.1.0/24 \
  --cve-check \
  --spoof-check \
  --threats \
  --map
```

### Comprehensive Security Scan

```bash
# The works: everything enabled
sudo net-inspect --cidr 192.168.1.0/24 \
  --cve-check \
  --spoof-check \
  --capture \
  --capture-duration 30 \
  --analyze-traffic \
  --geolocate \
  --geolocate-public \
  --tls-audit \
  --threat-intel \
  --show-exploits \
  --enum-all \
  --map \
  --threats \
  --save-baseline \
  --report-pdf ~/network-report.pdf \
  --save
```

### Quick Vulnerability Assessment

```bash
# Fast CVE scan with exploit lookup
sudo net-inspect --cidr 192.168.1.0/24 \
  --profile aggressive \
  --cve-check \
  --show-exploits \
  --save
```

---

## Core Capabilities

### 1. CVE Vulnerability Detection

Integrated real-time vulnerability intelligence from NIST National Vulnerability Database.

**Features:**
- 250,000+ CVE database access
- CISA KEV (Known Exploited Vulnerabilities) integration
- Service version to CVE mapping
- CVSS score calculation
- 7-day intelligent caching for performance
- Optional API key support for 10x faster scans

**Usage:**
```bash
# Basic CVE checking
sudo net-inspect --cidr 192.168.1.0/24 --cve-check

# With NVD API key for faster results
export NVD_API_KEY="your-api-key"
sudo net-inspect --cidr 192.168.1.0/24 --cve-check

# Force fresh CVE lookups (bypass cache)
sudo net-inspect --cidr 192.168.1.0/24 --cve-check --clear-cve-cache

# CVE check with exploit database integration
sudo net-inspect --cidr 192.168.1.0/24 --cve-check --show-exploits
```

**CVE Cache Management:**
- Location: `~/.cache/net-inspect/cve/`
- Duration: 7 days
- Clear cache: `--clear-cve-cache`

### 2. Spoof Detection & Correlation Analysis

Multi-layer correlation engine to detect spoofed, cloned, or suspicious devices on your network.

**Detection Methods:**
- **Layer 2 Analysis**: MAC/Vendor mismatch detection (e.g., iOS device without Apple MAC)
- **DHCP Analysis**: Hostname inconsistency checking (e.g., "iPhone" with Samsung vendor)
- **OS Fingerprinting**: Validate claimed OS matches network behavior
- **Behavioral Analysis**: Detect timing anomalies and unusual traffic patterns
- **Risk Scoring**: 0-100 score for each host with detailed breakdown

**Usage:**
```bash
# Run spoof detection
sudo net-inspect --cidr 192.168.1.0/24 --spoof-check

# Combined with baseline for enhanced detection
sudo net-inspect --cidr 192.168.1.0/24 \
  --spoof-check \
  --compare-baseline baseline.json
```

**Output Example:**
```
📋 Spoof Detection Analysis - 15 Host(s)
═══════════════════════════════════════════════════════════
  🔴 CRITICAL: 1  |  🟠 HIGH: 2  |  🟡 MEDIUM: 3  |  🟢 LOW: 9
═══════════════════════════════════════════════════════════

[1/15] 192.168.1.100 (iPhone-Suspicious)
  MAC Address:    aa:bb:cc:dd:ee:ff
  Vendor:         Samsung
  Spoof Score:    85.0/100 🔴 CRITICAL
  Top Indicators:
    • Layer 2 (MAC/Vendor mismatch): 35.0 (41%)
    • DHCP (Hostname inconsistency): 35.0 (41%)
    • Behavioral (Clock skew/timing): 15.0 (18%)
```

### 3. Public IP Geolocation

Discover the geographic location of your network's public IP address.

**Features:**
- City, region, and country identification
- ISP and organization details
- AS Number lookup
- Reverse DNS resolution
- GPS coordinates with Google Maps link
- Timezone and postal code
- Country flag emoji display
- NAT translation awareness

**Usage:**
```bash
# Geolocate your public IP
sudo net-inspect --cidr 192.168.1.0/24 --geolocate-public

# Geolocate specific IP addresses
sudo net-inspect --cidr 8.8.8.8/32 --geolocate
```

**Output Example:**
```
═══════════════════════════════════════════════════════════
                🌍 PUBLIC IP GEOLOCATION
═══════════════════════════════════════════════════════════

📍 LOCATION DETAILS
  Public IP:      174.109.106.73
  Location:       Durham, North Carolina, United States 🇺🇸
  Coordinates:    96.0229, -93.9464
  Google Maps:    https://maps.google.com/?q=96.0229,-93.9464
  Reverse DNS:    syn-174-109-106-073.res.spectrum.com

🌐 NETWORK PROVIDER
  ISP:            Charter Communications
  Organization:   Spectrum
  AS Number:      AS11426 Charter Communications Inc
  Timezone:       America/New_York
  ZIP Code:       27705

ℹ️  IMPORTANT: All 15 device(s) share this Internet location
             (NAT translates 192.168.1.x → 174.109.106.73)
═══════════════════════════════════════════════════════════
```

### 4. Traffic Analysis & Packet Capture

Deep packet inspection with automated capture and analysis.

**Features:**
- Automated tcpdump packet capture
- Protocol distribution analysis (TCP, UDP, ICMP)
- Credential extraction from plaintext protocols
- File carving from network traffic
- SSL/TLS certificate extraction
- Session analysis and tracking
- Security warning detection

**Usage:**
```bash
# Capture and analyze network traffic
sudo net-inspect --cidr 192.168.1.0/24 \
  --capture \
  --capture-duration 60 \
  --analyze-traffic

# Analyze existing PCAP file
sudo net-inspect --cidr 192.168.1.0/24 \
  --analyze-traffic \
  --pcap-file /path/to/capture.pcap
```

**Captured Data:**
- Location: `data/captures/`
- Format: Standard PCAP (compatible with Wireshark)
- Analysis reports: JSON format in `data/logs/`

### 5. TLS/SSL Security Audits

Comprehensive SSL/TLS security assessment for all HTTPS services.

**Checks:**
- Certificate validation and expiration
- Weak cipher suite detection (RC4, DES, 3DES, etc.)
- Protocol version analysis (SSLv3, TLS 1.0/1.1/1.2/1.3)
- Self-signed certificate detection
- Certificate chain validation
- Key strength analysis

**Usage:**
```bash
# Audit TLS/SSL services
sudo net-inspect --cidr 192.168.1.0/24 --tls-audit

# Combined with CVE checking for complete HTTPS assessment
sudo net-inspect --cidr 192.168.1.0/24 --tls-audit --cve-check
```

### 6. Network Topology Mapping

Visual hierarchical representation of your network structure.

**Features:**
- Tree-style network visualization
- Device type categorization (router, server, workstation, IoT, mobile)
- Risk level color coding (🔴 Critical, 🟠 High, 🟡 Warning, 🟢 OK)
- CIDR-based organization
- Easy-to-read ASCII art format

**Usage:**
```bash
# Generate network map
sudo net-inspect --cidr 192.168.1.0/24 --map
```

**Output Example:**
```
NETWORK TOPOLOGY MAP

192.168.1.0/24
  ├─ [🟢] [ROUTER    ] gateway           192.168.1.1   (risk: 0)
  ├─ [🟢] [SERVER    ] webserver         192.168.1.10  (risk: 15)
  ├─ [🟡] [WORKST.   ] laptop-101        192.168.1.101 (risk: 45)
  ├─ [🟢] [IOT       ] smart-thermostat  192.168.1.50  (risk: 20)
  └─ [🟢] [MOBILE    ] android-phone     192.168.1.200 (risk: 0)
```

### 7. Professional Vulnerability Reports

Tree-style vulnerability analysis with detailed attack vectors and business impact.

**Features:**
- Grouped by device (no repetition)
- Hierarchical vulnerability display
- CVSS scores with color coding
- CWE classifications
- Exploitation difficulty and timeline
- Attack vector breakdown
- Business impact assessment

**Format:**
```
═══════════════════════════════════════════════════════════
         PROFESSIONAL VULNERABILITY ANALYSIS
            🔴 CRITICAL SEVERITY (3 vulnerabilities)
═══════════════════════════════════════════════════════════

🌐 gateway (router) @ 192.168.1.1
Vulnerabilities: 3

  ├─ [VULN-1] OpenSSL Heartbleed (CVE-2014-0160)
  │  ├─ CVSS Score:    9.8/10 (CRITICAL)
  │  ├─ CWE:           CWE-119 Buffer Overflow
  │  ├─ Exploit Time:  ~Minutes (LOW difficulty)
  │  ├─ Attack Vector:
  │  │  ├─ • Remote memory disclosure
  │  │  ├─ • Private key extraction
  │  │  └─ • Session hijacking
  │  └─ Business Impact: Complete device compromise
  │
  ├─ [VULN-2] ...
  └─ [VULN-3] ...

───────────────────────────────────────────────────────────
```

### 8. Baseline Tracking & Rogue Device Detection

Monitor network changes over time and detect unauthorized devices.

**Features:**
- Save network snapshots as baselines
- Compare current state against baseline
- Detect new devices, removed devices, changed configurations
- Track device profile changes (MAC, OS, services)
- Timestamped baseline files

**Usage:**
```bash
# Create baseline
sudo net-inspect --cidr 192.168.1.0/24 \
  --save-baseline data/baselines/office-network.json

# Later, detect changes
sudo net-inspect --cidr 192.168.1.0/24 \
  --compare-baseline data/baselines/office-network.json

# Will show:
# ✓ Known devices: 15
# ⚠️ NEW devices: 2
# ⚠️ MISSING devices: 1
# ⚠️ CHANGED devices: 3
```

**Baseline Storage:**
- Location: `data/baselines/`
- Format: JSON
- Includes: IP, MAC, hostname, OS, services, first seen, last seen

---

## Command-Line Reference

### Network Target Options

```bash
--cidr CIDR                    # Target network in CIDR notation (can specify multiple)
                               # Examples: --cidr 192.168.1.0/24 --cidr 10.0.0.0/8

--ipv6                         # Auto-detect and scan IPv6 networks on interface
```

### Scan Configuration

```bash
--profile {quiet|balanced|aggressive}
                               # Scan profile (default: balanced)
                               # quiet: ARP only, no OS detection
                               # balanced: SYN scan + version detection
                               # aggressive: Full scan + scripts + OS detection

--timing {paranoid|sneaky|polite|normal|aggressive|insane}
                               # Timing template (default: normal)
                               # Maps to nmap -T0 through -T5

--concurrency N                # Number of parallel service probes (default: 4)
```

### Detection & Analysis

```bash
--cve-check                    # Enable real-time CVE vulnerability checking
--spoof-check                  # Enable spoof detection correlation analysis
--threats                      # Enable threat assessment engine
--geolocate                    # Geolocate individual IP addresses
--geolocate-public             # Geolocate your public IP address
--tls-audit                    # Audit TLS/SSL security (certificates, ciphers)
--threat-intel                 # Enable threat intelligence lookups
--show-exploits                # Find exploits for detected CVEs (searchsploit)
```

### Traffic Analysis

```bash
--capture                      # Enable packet capture during scan
--capture-duration SECONDS     # Capture duration in seconds (default: 30)
--analyze-traffic              # Analyze captured traffic for credentials, files, certs
--pcap-file PATH               # Analyze existing PCAP file
```

### Enumeration

```bash
--enum-all                     # Enable ALL enumeration modules
--enum-dns                     # DNS enumeration (zone transfers, records)
--enum-smb                     # SMB enumeration (shares, users)
--enum-http                    # HTTP enumeration (headers, paths)
--enum-snmp                    # SNMP enumeration (community strings)
--enum-email                   # Email enumeration (SMTP capabilities)
--enum-secrets                 # Secrets scanning (API keys, credentials)
```

### Baseline & Comparison

```bash
--save-baseline FILE           # Save current network state as baseline
--compare-baseline FILE        # Compare against existing baseline to detect changes
```

### Reporting & Output

```bash
--save                         # Save results to JSON and CSV files
--save-all                     # Save everything (results + raw nmap XML)
--json-only                    # Output pure JSON (no formatted output)
--report-pdf FILE              # Generate PDF report at specified path
--report-format {professional|executive|technical}
                               # PDF report format (default: professional)
--map                          # Display network topology map
```

### CVE Options

```bash
--nvd-api-key KEY              # NVD API key for 10x faster CVE lookups
--clear-cve-cache              # Clear CVE cache before scanning (force fresh lookups)
```

### Other Options

```bash
--help                         # Show help message and exit
--version                      # Show version information
```

---

## Usage Examples

### Security Assessment Scenarios

#### 1. Quick Network Health Check
```bash
# Fast scan to get network overview
sudo net-inspect --cidr 192.168.1.0/24 --map --threats
```

#### 2. Comprehensive Security Audit
```bash
# Full security assessment with all features
sudo net-inspect --cidr 192.168.1.0/24 \
  --profile aggressive \
  --cve-check \
  --spoof-check \
  --capture \
  --capture-duration 60 \
  --analyze-traffic \
  --geolocate-public \
  --tls-audit \
  --threat-intel \
  --show-exploits \
  --enum-all \
  --map \
  --threats \
  --save-baseline \
  --report-pdf ~/security-audit-$(date +%Y%m%d).pdf \
  --save
```

#### 3. Stealth Reconnaissance
```bash
# Low-noise scan for red team operations
sudo net-inspect --cidr 192.168.1.0/24 \
  --profile quiet \
  --timing paranoid \
  --save
```

#### 4. Vulnerability-Focused Scan
```bash
# Focus on finding vulnerabilities with exploits
sudo net-inspect --cidr 192.168.1.0/24 \
  --profile aggressive \
  --cve-check \
  --show-exploits \
  --tls-audit \
  --report-pdf ~/vuln-report.pdf \
  --save
```

#### 5. Rogue Device Hunting
```bash
# Establish baseline (run during known-good state)
sudo net-inspect --cidr 192.168.1.0/24 \
  --save-baseline data/baselines/corporate-lan.json

# Later, scan for unauthorized devices
sudo net-inspect --cidr 192.168.1.0/24 \
  --compare-baseline data/baselines/corporate-lan.json \
  --spoof-check \
  --map
```

#### 6. Traffic Analysis & Credential Harvesting
```bash
# Capture traffic and extract credentials
sudo net-inspect --cidr 192.168.1.0/24 \
  --capture \
  --capture-duration 120 \
  --analyze-traffic \
  --save
```

#### 7. IPv6 Network Discovery
```bash
# Auto-detect and scan IPv6 networks
sudo net-inspect --ipv6 --profile balanced --map

# Scan specific IPv6 subnet
sudo net-inspect --cidr 2001:db8::/64 --cve-check

# Dual-stack scan (IPv4 + IPv6)
sudo net-inspect --cidr 192.168.1.0/24 --cidr fe80::/64 --map
```

#### 8. IoT Device Security Assessment
```bash
# Scan IoT subnet with focus on security
sudo net-inspect --cidr 192.168.100.0/24 \
  --profile aggressive \
  --cve-check \
  --tls-audit \
  --enum-http \
  --enum-snmp \
  --threat-intel \
  --map \
  --report-pdf ~/iot-security.pdf
```

### Integration Examples

#### With jq (JSON Processing)
```bash
# Find all hosts with CRITICAL vulnerabilities
sudo net-inspect --cidr 192.168.1.0/24 --cve-check --json-only \
  | jq '.hosts[] | select(.cves[].severity == "CRITICAL")'

# Extract only IP addresses and risk scores
sudo net-inspect --cidr 192.168.1.0/24 --json-only \
  | jq -r '.hosts[] | "\(.ip): \(.risk)/100"'

# Find devices with unencrypted protocols
sudo net-inspect --cidr 192.168.1.0/24 --json-only \
  | jq '.hosts[] | select(.flags[] | contains("telnet", "ftp", "http"))'
```

#### Automated Monitoring Script
```bash
#!/bin/bash
# Daily network security monitoring

NETWORK="192.168.1.0/24"
BASELINE="data/baselines/daily-baseline.json"
REPORT_DIR="reports/$(date +%Y-%m-%d)"

mkdir -p "$REPORT_DIR"

sudo net-inspect --cidr "$NETWORK" \
  --cve-check \
  --spoof-check \
  --compare-baseline "$BASELINE" \
  --report-pdf "$REPORT_DIR/security-report.pdf" \
  --save

# Alert if new devices found
if grep -q "NEW devices:" "$REPORT_DIR"/*.log; then
  echo "⚠️ New devices detected!" | mail -s "Network Alert" admin@example.com
fi
```

#### Integration with Splunk/SIEM
```bash
# Output to JSON for SIEM ingestion
sudo net-inspect --cidr 192.168.1.0/24 \
  --cve-check \
  --json-only \
  | curl -X POST https://splunk.example.com/services/collector \
    -H "Authorization: Splunk YOUR-TOKEN" \
    -d @-
```

---

## Advanced Features

### Data Directories

net-inspect organizes data in the following structure:

```
net-inspect/
├── data/
│   ├── baselines/              # Network baseline snapshots
│   │   └── *.json
│   ├── captures/               # Packet capture files
│   │   └── *.pcap
│   ├── logs/                   # Scan logs and results
│   │   ├── *_summary.csv
│   │   └── *_summary.json
│   └── results/                # Detailed scan results (--save-all)
│       └── scan_*/
└── ~/.cache/net-inspect/
    └── cve/                    # CVE cache (7-day expiry)
        └── *.pkl
```

### CVE Detection Deep Dive

**How It Works:**
1. Service detection via nmap extracts version information
2. Service name + version mapped to CPE (Common Platform Enumeration)
3. CPE used to query NVD API for matching CVEs
4. Results cached locally for 7 days
5. CISA KEV database checked for actively exploited vulnerabilities
6. CVSS scores calculated and severity assigned

**Performance:**
- **Without API Key**: ~2 requests/second (rate limited)
- **With API Key**: ~50 requests/second
- **With Cache**: Instant (up to 7 days)

**Getting Better Results:**
```bash
# Use aggressive profile for better version detection
sudo net-inspect --cidr 192.168.1.0/24 \
  --profile aggressive \
  --cve-check

# Get API key for faster scans of large networks
export NVD_API_KEY="your-key"
sudo net-inspect --cidr 10.0.0.0/8 --cve-check
```

### Spoof Detection Algorithm

The correlation engine scores hosts based on multiple factors:

**Scoring Breakdown:**
- **Layer 2 Anomalies** (0-40 points):
  - MAC/Vendor mismatch (e.g., Apple OS with Samsung MAC): +30
  - Missing MAC address: +40

- **DHCP Anomalies** (0-35 points):
  - Suspicious hostname (admin, root, test, localhost): +25
  - Hostname/Vendor conflict (e.g., "Galaxy" with Apple vendor): +35

- **Behavioral Anomalies** (0-25 points):
  - No open ports on active device: +10
  - Abnormally high risk score: +15

**Risk Levels:**
- **0-24**: 🟢 LOW - Appears legitimate
- **25-49**: 🟡 MEDIUM - Minor anomalies, monitor
- **50-74**: 🟠 HIGH - Suspicious, investigate
- **75-100**: 🔴 CRITICAL - Likely spoofed, immediate action required

### PDF Report Customization

**Available Formats:**
- **professional**: Detailed technical report with all findings (default)
- **executive**: High-level summary for management
- **technical**: Deep technical analysis for security teams

```bash
# Executive summary for board meeting
sudo net-inspect --cidr 192.168.1.0/24 \
  --cve-check \
  --report-pdf ~/exec-report.pdf \
  --report-format executive

# Technical deep-dive for incident response
sudo net-inspect --cidr 192.168.1.0/24 \
  --profile aggressive \
  --cve-check \
  --enum-all \
  --report-pdf ~/technical-report.pdf \
  --report-format technical
```

---

## Output Formats

### 1. Terminal Output (Default)

Rich, formatted terminal output with:
- Color-coded severity levels
- Unicode box-drawing for tables
- Progress bars for long operations
- Emoji indicators for quick status recognition
- Tree-style network topology
- Professional vulnerability breakdowns

### 2. JSON Output

```bash
# Pure JSON for automation
sudo net-inspect --cidr 192.168.1.0/24 --cve-check --json-only

# Example output structure:
{
  "scan_id": "scan_20231207_194744",
  "timestamp": "2023-12-07T19:47:44",
  "networks": ["192.168.1.0/24"],
  "hosts": [
    {
      "ip": "192.168.1.100",
      "hostname": "webserver",
      "mac": "aa:bb:cc:dd:ee:ff",
      "vendor": "Dell",
      "os": "Linux 5.10",
      "devtype": "server",
      "risk": 65,
      "ports": [22, 80, 443],
      "services": [
        {
          "port": 443,
          "service": "https",
          "version": "Apache httpd 2.4.41"
        }
      ],
      "cves": [
        {
          "cve_id": "CVE-2021-44790",
          "severity": "CRITICAL",
          "cvss": 9.8,
          "description": "Buffer overflow in Apache HTTP Server"
        }
      ]
    }
  ]
}
```

### 3. CSV Export

Automatically generated when using `--save`:

```csv
ip,hostname,mac,vendor,os,devtype,risk,ports,cves
192.168.1.100,webserver,aa:bb:cc:dd:ee:ff,Dell,Linux 5.10,server,65,"22,80,443",CVE-2021-44790
```

### 4. PDF Reports

Professional PDF reports include:
- Executive summary with key findings
- Network statistics and device inventory
- Vulnerability analysis with CVSS scores
- Network topology diagram
- Risk assessment and prioritization
- Remediation recommendations
- Appendices with technical details

---

## Integration

### CI/CD Pipeline Integration

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - sudo net-inspect --cidr $NETWORK_CIDR --cve-check --json-only > scan.json
    - |
      if jq -e '.hosts[].cves[] | select(.severity == "CRITICAL")' scan.json; then
        echo "❌ CRITICAL vulnerabilities found!"
        exit 1
      fi
  artifacts:
    paths:
      - scan.json
```

### Slack Notifications

```bash
#!/bin/bash
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

RESULT=$(sudo net-inspect --cidr 192.168.1.0/24 --cve-check --json-only)
CRITICAL=$(echo "$RESULT" | jq '[.hosts[].cves[] | select(.severity == "CRITICAL")] | length')

if [ "$CRITICAL" -gt 0 ]; then
  curl -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"text\":\"⚠️ Found $CRITICAL CRITICAL vulnerabilities in network scan!\"}"
fi
```

### REST API Wrapper

```python
from flask import Flask, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route('/scan/<network>')
def scan_network(network):
    result = subprocess.run(
        ['sudo', 'net-inspect', '--cidr', network, '--cve-check', '--json-only'],
        capture_output=True,
        text=True
    )
    return jsonify(json.loads(result.stdout))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

---

## Troubleshooting

### Common Issues

**1. Permission Denied Errors**
```bash
# Problem: "Permission denied" when running net-inspect
# Solution: net-inspect requires root for raw sockets
sudo net-inspect --cidr 192.168.1.0/24
```

**2. nmap Not Found**
```bash
# Problem: "nmap: command not found"
# Solution: Install nmap

# Arch Linux
sudo pacman -S nmap

# Debian/Ubuntu
sudo apt install nmap

# macOS
brew install nmap
```

**3. Slow CVE Lookups**
```bash
# Problem: CVE checking is very slow
# Solution: Get an NVD API key (free, 10x faster)

# 1. Visit: https://nvd.nist.gov/developers/request-an-api-key
# 2. Set environment variable:
export NVD_API_KEY="your-api-key-here"

# Or use with flag:
sudo net-inspect --cidr 192.168.1.0/24 --cve-check --nvd-api-key "your-key"
```

**4. No Hosts Detected**
```bash
# Problem: Scan finds 0 hosts but you know devices exist
# Solution: Try different scan profiles

# ARP-only scan (most reliable for local networks)
sudo net-inspect --cidr 192.168.1.0/24 --profile quiet

# Aggressive scan with multiple techniques
sudo net-inspect --cidr 192.168.1.0/24 --profile aggressive
```

**5. Python Module Import Errors**
```bash
# Problem: "ModuleNotFoundError: No module named 'rich'"
# Solution: Install Python dependencies

pip install -r requirements.txt

# Or install specific missing module
pip install rich requests scapy reportlab manuf
```

**6. tcpdump Permission Denied**
```bash
# Problem: Packet capture fails with permission denied
# Solution: Grant tcpdump capabilities

sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)

# Or run with sudo
sudo net-inspect --cidr 192.168.1.0/24 --capture
```

**7. PDF Generation Fails**
```bash
# Problem: "Failed to generate PDF report"
# Solution: Install reportlab

pip install reportlab

# Verify installation
python3 -c "import reportlab; print('ReportLab OK')"
```

### Debug Mode

```bash
# Enable verbose output for troubleshooting
sudo net-inspect --cidr 192.168.1.0/24 --debug

# Test dependency availability
sudo net-inspect --cidr 127.0.0.1/32
# (Shows dependency check table)
```

### Getting Help

If you encounter issues:

1. **Check Dependencies**: Run a test scan to see dependency table
2. **Read Error Messages**: net-inspect provides detailed error messages
3. **Check Logs**: Review `data/logs/` for detailed scan logs
4. **GitHub Issues**: Report bugs at https://github.com/yourusername/net-inspect/issues

---

## Performance Optimization

### Large Network Scanning

For scanning large networks (>1000 hosts):

```bash
# Use aggressive timing for speed
sudo net-inspect --cidr 10.0.0.0/8 \
  --timing aggressive \
  --concurrency 10 \
  --cve-check \
  --nvd-api-key "your-key"

# Or break into smaller subnets and parallelize
for subnet in 10.0.{0..255}.0/24; do
  sudo net-inspect --cidr "$subnet" --save &
done
wait
```

### Caching Strategy

```bash
# First scan: slow (no cache)
sudo net-inspect --cidr 192.168.1.0/24 --cve-check

# Subsequent scans within 7 days: fast (cached CVEs)
sudo net-inspect --cidr 192.168.1.0/24 --cve-check

# Force fresh lookups (bypass cache)
sudo net-inspect --cidr 192.168.1.0/24 --cve-check --clear-cve-cache
```

---

## Security Considerations

### Operational Security (OpSec)

When conducting security assessments:

1. **Use VPN/Proxy** for external scans to protect your identity
2. **Use Stealth Profiles** to minimize detection:
   ```bash
   sudo net-inspect --cidr TARGET --profile quiet --timing paranoid
   ```
3. **Avoid Aggressive Scans** on production networks during business hours
4. **Monitor IDS/IPS** alerts if you have access to defensive systems
5. **Document Authorization** - keep written permission for all scans

### Legal Compliance

- ✅ **Always get written authorization** before scanning networks
- ✅ **Comply with scope** - only scan approved IP ranges
- ✅ **Follow timing restrictions** - respect blackout windows
- ✅ **Report findings responsibly** - use proper disclosure practices
- ❌ **Never scan** without permission - it's illegal in most jurisdictions

### Ethical Guidelines

1. **Professionalism**: Treat client data with confidentiality
2. **Integrity**: Report all findings, even those outside scope
3. **Responsibility**: Don't exploit vulnerabilities beyond what's authorized
4. **Education**: Use findings to improve security, not for malicious purposes

---

## Contributing

We welcome contributions! Here's how you can help:

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/net-inspect.git
cd net-inspect

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .

# Install development dependencies
pip install pytest black flake8 mypy
```

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Write** tests for new functionality
4. **Follow** PEP 8 style guidelines
5. **Test** thoroughly
6. **Commit** with descriptive messages
7. **Push** to your fork
8. **Submit** a pull request

### Code Style

```bash
# Format code with black
black netinspect/

# Lint with flake8
flake8 netinspect/

# Type check with mypy
mypy netinspect/
```

### Testing

```bash
# Run test suite
pytest tests/

# Run specific test
pytest tests/test_scanner.py

# With coverage
pytest --cov=netinspect tests/
```

---

## Roadmap

### Planned Features (v1.1.0+)

- 🎯 **Active Exploitation Framework**: Validate CVEs with safe exploit attempts
- 🧠 **AI-Powered Anomaly Detection**: Machine learning for behavioral analysis
- 🌐 **Live Web Dashboard**: Real-time network monitoring with WebSocket updates
- 🏠 **IoT Privacy Analysis**: Detect phone-home behavior and data leaks
- 🔐 **Auto-Remediation**: Automated patching and configuration fixes
- 📱 **Mobile App**: iOS/Android companion app for on-the-go scanning
- ☁️ **Cloud Integration**: AWS/Azure/GCP asset discovery
- 🎓 **Training Mode**: Interactive labs and CTF-style challenges

See our [full roadmap](https://github.com/yourusername/net-inspect/wiki/Roadmap) for details.

---

## Version History

### v1.0.0 (2023-12-07) - Current Release

**Major Features:**
- ✅ Complete modular refactoring from monolithic script
- ✅ Real-time CVE detection with NIST NVD integration
- ✅ Advanced spoof detection correlation engine
- ✅ Public IP geolocation with detailed provider info
- ✅ Traffic analysis with packet capture
- ✅ TLS/SSL security auditing
- ✅ Network topology mapping
- ✅ Professional PDF report generation
- ✅ Threat intelligence integration
- ✅ Full IPv6 support with auto-detection
- ✅ 8 specialized enumeration modules
- ✅ Baseline tracking and rogue device detection
- ✅ Exploit database integration (searchsploit)
- ✅ Tree-style vulnerability analysis
- ✅ Enhanced terminal output with Rich library

**Modules Added:**
- `netinspect/analysis/traffic.py` - Traffic analysis engine
- `netinspect/analysis/tls.py` - TLS/SSL auditing
- `netinspect/intelligence/threat.py` - Threat intelligence
- `netinspect/intelligence/geolocation.py` - IP geolocation
- `netinspect/reporting/pdf_report.py` - PDF generation
- `netinspect/enumeration/firewall.py` - Firewall testing
- `netinspect/net-inspect-v2-correlation-engine.py` - Spoof detection
- `netinspect/utils/mac_vendor.py` - MAC vendor lookups

**Improvements:**
- 10x faster CVE lookups with API key support
- Intelligent 7-day CVE caching
- Professional-grade PDF reports
- Color-coded risk levels throughout
- Comprehensive dependency checking
- Better error handling and user feedback

---

## Credits

**Author**: Constantine
**With Development Assistance From**: Claude AI (Anthropic)
**License**: MIT License (see LICENSE file)

**Special Thanks**:
- NIST National Vulnerability Database for CVE data
- CISA for KEV database
- nmap project for network scanning capabilities
- Scapy developers for packet manipulation library
- ReportLab for PDF generation

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

**Summary**: Free to use, modify, and distribute with attribution. No warranty provided.

---

## Support & Contact

**Issues & Bug Reports**:
https://github.com/yourusername/net-inspect/issues

**Feature Requests**:
https://github.com/yourusername/net-inspect/discussions

**Security Vulnerabilities**:
Please report security issues privately to: security@yourdomain.com

**Documentation**:
https://github.com/yourusername/net-inspect/wiki

---

## Disclaimer (Repeated for Emphasis)

**This tool is for AUTHORIZED SECURITY TESTING ONLY.**

By using net-inspect, you acknowledge that:
- You have explicit permission to scan target networks
- You accept full legal responsibility for your actions
- You will comply with all applicable laws and regulations
- The authors are NOT liable for any misuse or damages

**UNAUTHORIZED NETWORK SCANNING IS ILLEGAL AND UNETHICAL.**

Use this tool responsibly and professionally.

---

**Happy (Legal & Authorized) Hunting! 🔍🛡️**
