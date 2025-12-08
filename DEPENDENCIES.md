# net-inspect Dependencies

Complete dependency information and installation instructions for net-inspect.

## System Requirements

### Operating System

- **Supported**: Linux (Arch-based, Debian, Ubuntu, Kali)
- **Kernel**: 3.10+ (for modern networking features)
- **Architecture**: x86_64, ARM64

### Python Version

- **Required**: Python 3.7 or higher
- **Recommended**: Python 3.9+

Check your Python version:

```bash
python3 --version
```

### Privileges

- **Root access required**: Yes
- **Why**: Raw socket access for nmap, packet capture, low-level network operations

## Python Dependencies

### Required Packages

#### 1. requests (>= 2.25.0)

**Purpose**: HTTP requests for NVD API, CISA KEV, CVE lookups, and threat intelligence

**Install**:

```bash
# Arch Linux
sudo pacman -S python-requests

# Debian/Ubuntu
sudo apt install python3-requests

# pip
pip install requests
```

### Optional Packages (v1.0.0 New Features)

#### 2. scapy (>= 2.5.0)

**Purpose**:
- PCAP traffic analysis (credential extraction, file carving)
- Firewall evasion testing
- Advanced packet manipulation

**Features enabled**:
- `--analyze-traffic`: Analyze captured traffic for credentials and files
- `--firewall-test`: Firewall evasion techniques testing

**Install**:

```bash
# Arch Linux
sudo pacman -S python-scapy

# Debian/Ubuntu
sudo apt install python3-scapy

# pip
pip install scapy
```

#### 3. reportlab (>= 3.6.0)

**Purpose**: Professional PDF report generation

**Features enabled**:
- `--report-pdf`: Generate executive, professional, or technical PDF reports

**Install**:

```bash
# pip (recommended)
pip install reportlab

# Arch Linux
sudo pacman -S python-reportlab
```

### All Python Dependencies at Once

**Using pip**:

```bash
pip install -r requirements.txt
```

**Manual installation**:

```bash
# Arch Linux
sudo pacman -S python-requests python-scapy python-reportlab

# Debian/Ubuntu
sudo apt install python3-requests python3-scapy
pip install reportlab  # reportlab not in Debian repos
```

## System Dependencies

### Required System Tools

#### 1. nmap

**Purpose**: Network discovery, port scanning, service detection, OS fingerprinting

**This is the core dependency** - net-inspect will not work without nmap.

**Check if installed**:

```bash
which nmap
nmap --version
```

**Install**:

```bash
# Arch Linux
sudo pacman -S nmap

# Debian/Ubuntu
sudo apt install nmap

# Kali Linux (usually pre-installed)
sudo apt update && sudo apt install nmap
```

**Minimum version**: 7.80+
**Recommended version**: 7.90+

#### 2. ip command (iproute2)

**Purpose**: Network interface information

**Check if installed**:

```bash
which ip
ip --version
```

**Install**:

```bash
# Arch Linux (usually pre-installed)
sudo pacman -S iproute2

# Debian/Ubuntu (usually pre-installed)
sudo apt install iproute2
```

### Optional System Tools

These enhance functionality but are not strictly required:

#### 1. tcpdump

**Purpose**: Packet capture for advanced analysis

**Install**:

```bash
# Arch Linux
sudo pacman -S tcpdump

# Debian/Ubuntu
sudo apt install tcpdump
```

#### 2. traceroute

**Purpose**: Network path tracing

**Install**:

```bash
# Arch Linux
sudo pacman -S traceroute

# Debian/Ubuntu
sudo apt install traceroute
```

#### 3. avahi-resolve

**Purpose**: mDNS/Avahi hostname resolution

**Install**:

```bash
# Arch Linux
sudo pacman -S avahi

# Debian/Ubuntu
sudo apt install avahi-utils
```

#### 4. nmblookup

**Purpose**: NetBIOS name resolution (part of Samba)

**Install**:

```bash
# Arch Linux
sudo pacman -S samba

# Debian/Ubuntu
sudo apt install samba-common-bin
```

#### 5. searchsploit

**Purpose**: Exploit database searching (Exploit-DB)

**Install**:

```bash
# Arch Linux (via AUR)
yay -S exploitdb

# Debian/Ubuntu/Kali
sudo apt install exploitdb
```

#### 6. openssl

**Purpose**: Certificate examination, TLS/SSL analysis

**Install**:

```bash
# Arch Linux (usually pre-installed)
sudo pacman -S openssl

# Debian/Ubuntu (usually pre-installed)
sudo apt install openssl
```

#### 7. fastfetch (or similar)

**Purpose**: System information display

**Install**:

```bash
# Arch Linux
sudo pacman -S fastfetch

# Debian/Ubuntu
# Not in standard repos, optional
```

## API Keys (Optional but Recommended)

### NVD API Key (CVE Database)

**Purpose**: Faster CVE lookups (10x speed increase)

**Cost**: Free

**How to get**:

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the request form (no credit card required)
3. Receive API key via email (usually instant)

**How to use**:

```bash
# Set environment variable
export NVD_API_KEY="your-api-key-here"

# Or pass directly
sudo netinspect --cidr 192.168.1.0/24 --cve-check --nvd-api-key "your-key"
```

**Rate limits**:

- **Without API key**: 5 requests per 30 seconds
- **With API key**: 50 requests per 30 seconds

### Threat Intelligence API Keys (v1.0.0 New)

#### AbuseIPDB API Key

**Purpose**: IP reputation and abuse reports

**Cost**: Free tier available (1,000 checks/day)

**How to get**:

1. Visit: https://www.abuseipdb.com/register
2. Create free account
3. Go to API section: https://www.abuseipdb.com/account/api
4. Copy your API key

**How to use**:

```bash
# Set environment variable
export ABUSEIPDB_API_KEY="your-key-here"

# Or pass directly
sudo netinspect --cidr 192.168.1.0/24 --threat-intel --abuseipdb-key "your-key"
```

**Rate limits**: 1,000 requests/day (free tier)

#### VirusTotal API Key

**Purpose**: Multi-engine malware scanning and IP reputation

**Cost**: Free tier available (4 requests/minute)

**How to get**:

1. Visit: https://www.virustotal.com/gui/join-us
2. Create free account
3. Go to API key section: https://www.virustotal.com/gui/my-apikey
4. Copy your API key

**How to use**:

```bash
# Set environment variable
export VIRUSTOTAL_API_KEY="your-key-here"

# Or pass directly
sudo netinspect --cidr 192.168.1.0/24 --threat-intel --virustotal-key "your-key"
```

**Rate limits**: 4 requests/minute (free tier)

#### Shodan API Key

**Purpose**: Internet-wide device scanning and security insights

**Cost**: Free tier available (limited results)

**How to get**:

1. Visit: https://account.shodan.io/register
2. Create free account
3. Go to account page: https://account.shodan.io/
4. Copy your API key

**How to use**:

```bash
# Set environment variable
export SHODAN_API_KEY="your-key-here"

# Or pass directly
sudo netinspect --cidr 192.168.1.0/24 --threat-intel --shodan-key "your-key"
```

**Rate limits**: 100 query credits/month (free tier)

### API Key Configuration File (Optional)

Create `~/.config/net-inspect/config.json` for persistent API keys:

```json
{
  "nvd_api_key": "your-nvd-key",
  "abuseipdb_api_key": "your-abuseipdb-key",
  "virustotal_api_key": "your-virustotal-key",
  "shodan_api_key": "your-shodan-key"
}
```

**Priority order**: CLI arguments → Environment variables → Config file

## Verification

### Verify All Dependencies

**Check Python packages**:

```bash
# Required
python3 -c "import requests; print('requests:', requests.__version__)"

# Optional (v1.0.0)
python3 -c "import scapy; print('scapy:', scapy.__version__)"
python3 -c "import reportlab; print('reportlab:', reportlab.Version)"
```

**Check system tools**:

```bash
nmap --version
ip --version
which tcpdump
which traceroute
which avahi-resolve
which nmblookup
which searchsploit
```

**Check net-inspect modules**:

```bash
python3 -c "
from netinspect.analysis.traffic import TrafficAnalyzer
from netinspect.monitoring.daemon import MonitorDaemon
from netinspect.intelligence.threat_intel import ThreatIntelChecker
from netinspect.evasion.firewall import FirewallTester
from netinspect.analysis.tls import TLSAnalyzer
from netinspect.reporting.pdf_report import generate_pdf_report
from netinspect.intelligence.exploits import ExploitMapper
from netinspect.intelligence.geolocation import GeoLocator
print('✅ All v1.0.0 modules loaded successfully!')
"
```

### Run a Test Scan

```bash
# Basic functionality test
sudo netinspect --cidr 127.0.0.1/32

# CVE checking test
sudo netinspect --cidr 127.0.0.1/32 --cve-check

# Test new v1.0.0 features
sudo netinspect --cidr 8.8.8.8/32 --geolocate
sudo netinspect --cidr 127.0.0.1/32 --report-pdf test.pdf
```

## Platform-Specific Notes

### Arch Linux

Arch uses rolling releases:

```bash
sudo pacman -Syu
sudo pacman -S python python-requests python-scapy python-reportlab nmap iproute2 tcpdump traceroute avahi samba exploitdb
```

### Debian/Ubuntu

```bash
sudo apt update
sudo apt install python3 python3-pip python3-requests python3-scapy nmap iproute2 tcpdump traceroute avahi-utils samba-common-bin exploitdb
pip install reportlab  # Not in Debian repos
```

### Kali Linux

Kali usually has most tools pre-installed:

```bash
sudo apt update
sudo apt install python3-requests python3-scapy nmap tcpdump traceroute exploitdb
pip install reportlab
```

Most other tools are already included in Kali.

## Troubleshooting

### "nmap: command not found"

Install nmap - this is critical:

```bash
# Arch
sudo pacman -S nmap

# Debian/Ubuntu/Kali
sudo apt install nmap
```

### "ModuleNotFoundError: No module named 'requests'"

Install requests:

```bash
pip install requests
```

### "Permission denied" errors

Ensure you're running with sudo:

```bash
sudo netinspect --cidr 192.168.1.0/24
```

### CVE lookups failing

Check internet connectivity and NVD API availability:

```bash
curl -I https://services.nvd.nist.gov/rest/json/cves/2.0
```

If rate-limited, get an API key or wait and try again.

### Slow scans

Try:

1. Using an NVD API key for faster CVE lookups
2. Using `--profile balanced` instead of aggressive
3. Using `--timing normal` instead of paranoid/sneaky

## Minimum Working Setup

The absolute minimum to run net-inspect:

```bash
# Python
pip install requests

# System tools
sudo apt install nmap  # or pacman -S nmap
```

This gives you basic scanning capability without CVE checking or v1.0.0 advanced features.

## Recommended Setup

For full v1.0.0 functionality:

```bash
# Python packages
pip install requests scapy reportlab

# Core tools
sudo apt install nmap iproute2 tcpdump

# Optional tools
sudo apt install traceroute avahi-utils samba-common-bin openssl exploitdb

# Get API keys (all free):
# NVD API: https://nvd.nist.gov/developers/request-an-api-key
# AbuseIPDB: https://www.abuseipdb.com/register
# VirusTotal: https://www.virustotal.com/gui/join-us
# Shodan: https://account.shodan.io/register
```

## Development Dependencies

For development and testing:

```bash
# Testing frameworks
pip install pytest pytest-cov

# Code quality
pip install pylint black mypy

# Documentation
pip install sphinx sphinx-rtd-theme
```

## Version Compatibility

| Package/Tool | Minimum | Recommended | Tested |
|--------------|---------|-------------|--------|
| Python | 3.7 | 3.9+ | 3.13 |
| requests | 2.25.0 | 2.28+ | 2.32 |
| scapy | 2.5.0 | 2.6+ | 2.6.1 |
| reportlab | 3.6.0 | 4.0+ | 4.4.5 |
| nmap | 7.80 | 7.90+ | 7.94 |

## Network Requirements

### Outbound Connections

For full functionality, net-inspect needs outbound access to:

**CVE/Vulnerability Data:**
- **NVD API**: `services.nvd.nist.gov` (port 443)
- **CISA KEV**: `www.cisa.gov` (port 443)
- **CVE.org**: `cveawg.mitre.org` (port 443)

**Threat Intelligence (v1.0.0):**
- **AbuseIPDB**: `api.abuseipdb.com` (port 443)
- **VirusTotal**: `www.virustotal.com` (port 443)
- **Shodan**: `api.shodan.io` (port 443)

**Geolocation (v1.0.0):**
- **ip-api.com**: `ip-api.com` (port 80/443)

### Firewall Considerations

If running behind a firewall, ensure:

- ICMP (ping) is allowed for host discovery
- TCP/UDP ports you want to scan are accessible
- Outbound HTTPS (443) is allowed for CVE lookups

## Data Storage

net-inspect stores data in:

```
~/.cache/net-inspect/cve/    # CVE cache (managed automatically)
./data/baselines/             # Baseline snapshots
./data/captures/              # Packet captures
./data/logs/                  # Scan logs
./data/results/               # Scan results
```

Ensure adequate disk space:

- **CVE cache**: ~100 MB (grows over time)
- **Results**: Varies by scan size (typically 1-10 MB per scan)

## Performance Tuning

### For Faster Scans

```bash
# Use balanced or quiet profile
--profile balanced

# Use faster timing
--timing aggressive

# Use NVD API key
export NVD_API_KEY="your-key"

# Reduce enumeration
# Don't use --enum-all unless needed
```

### For Stealth Scans

```bash
# Use quiet profile
--profile quiet

# Use slow timing
--timing paranoid

# Minimal probing
# Avoid --enum-all
```

## v1.0.0 New Features and Dependencies

### Feature Matrix

| Feature | Flag | Required Dependencies | Optional Dependencies |
|---------|------|----------------------|----------------------|
| **PCAP Traffic Analysis** | `--analyze-traffic` | scapy | tcpdump (for capture) |
| **Continuous Monitoring** | `--daemon` | None | webhook/email/syslog |
| **Threat Intelligence** | `--threat-intel` | requests | API keys (AbuseIPDB, VT, Shodan) |
| **Firewall Testing** | `--firewall-test` | scapy | None |
| **TLS/SSL Audit** | `--tls-audit` | None | openssl |
| **PDF Reports** | `--report-pdf` | reportlab | None |
| **Exploit Mapping** | `--show-exploits` | None | searchsploit |
| **Geolocation** | `--geolocate` | requests | None |

### Feature Examples

**PCAP Traffic Analysis:**
```bash
# Capture and analyze for credentials/files
sudo netinspect --cidr 192.168.1.0/24 --capture --analyze-traffic
```

**Continuous Monitoring (Daemon Mode):**
```bash
# Run every hour, send alerts to Slack
sudo netinspect --daemon --interval 3600 --webhook https://hooks.slack.com/your-webhook
```

**Threat Intelligence:**
```bash
# Check IPs against threat databases
export ABUSEIPDB_API_KEY="your-key"
sudo netinspect --cidr 8.8.8.8/32 --threat-intel
```

**Firewall Evasion Testing:**
```bash
# Test firewall rules (AUTHORIZED USE ONLY)
sudo netinspect --firewall-test --firewall-target 192.168.1.1
```

**TLS/SSL Security Audit:**
```bash
# Grade HTTPS services (A+ to F)
sudo netinspect --cidr 1.1.1.1/32 --tls-audit
```

**Professional PDF Reports:**
```bash
# Generate executive summary PDF
sudo netinspect --cidr 192.168.1.0/24 --cve-check --report-pdf scan_report.pdf --report-format executive
```

**Exploit Mapping:**
```bash
# Find exploits for detected CVEs
sudo netinspect --cidr 192.168.1.0/24 --cve-check --show-exploits
```

**IP Geolocation:**
```bash
# Identify geographic location of IPs
sudo netinspect --cidr 8.8.8.8/32 --geolocate
```

### Full Integration Example

```bash
# Run all v1.0.0 features together
sudo netinspect --cidr 192.168.1.0/24 \
  --cve-check \
  --capture \
  --analyze-traffic \
  --threat-intel \
  --tls-audit \
  --geolocate \
  --show-exploits \
  --report-pdf full_report.pdf \
  --save
```

## Support

If you encounter dependency issues:

1. Check this document first
2. Verify Python version: `python3 --version`
3. Verify nmap installation: `nmap --version`
4. Check Python packages: `pip list | grep -E "requests|scapy|reportlab"`
5. Run dependency check: `netinspect` (will display missing dependencies)
6. Check internet connectivity for API lookups
7. Open an issue on GitHub with full error output

## Additional Resources

**Core Documentation:**
- **nmap documentation**: https://nmap.org/book/
- **NVD API documentation**: https://nvd.nist.gov/developers
- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**v1.0.0 API Documentation:**
- **AbuseIPDB API**: https://docs.abuseipdb.com/
- **VirusTotal API**: https://docs.virustotal.com/reference/overview
- **Shodan API**: https://developer.shodan.io/api
- **Scapy Documentation**: https://scapy.readthedocs.io/
- **ReportLab Guide**: https://www.reportlab.com/docs/reportlab-userguide.pdf

**Security Best Practices:**
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **CIS Controls**: https://www.cisecurity.org/controls
