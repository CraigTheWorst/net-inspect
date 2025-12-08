#!/usr/bin/env python3
"""
net-inspect.py v1.0.0 — Network Security Intelligence Tool with Real-Time CVE Detection

Usage:
  sudo python3 net-inspect.py --cidr 192.168.1.0/24 --cve-check
  sudo python3 net-inspect.py --cidr fe80::/64 --profile quiet
  sudo python3 net-inspect.py --ipv6  # Auto-detect IPv6 network
  sudo python3 net-inspect.py --cidr 192.168.1.0/24 --cidr fe80::/64  # Dual-stack
  sudo python3 net-inspect.py --cidr 192.168.1.0/24 --profile quiet --timing paranoid
  sudo python3 net-inspect.py --cidr 192.168.1.0/24 --profile aggressive --enum-all --cve-check --save
  sudo python3 net-inspect.py --cidr 192.168.1.0/24 --json-only
  sudo python3 net-inspect.py --cidr 192.168.1.0/24 --cve-check --nvd-api-key "YOUR_KEY"
  sudo python3 net-inspect.py --cidr 192.168.1.0/24 --spoof-check  # v2.0.0 spoof detection

IPv6 Support (NEW in v1.0.0):
 - Full IPv6 scanning support (fe80::/64, 2001:db8::/32, etc.)
 - Automatic IPv6 network detection with --ipv6
 - Dual-stack scanning (scan both IPv4 and IPv6 simultaneously)
 - IPv6 Neighbor Discovery Protocol (NDP) for MAC address resolution
 - Link-local and global unicast address support

Scan Profiles (--profile):
 - quiet:      Minimal noise, passive fingerprinting, ARP discovery only
 - balanced:   Default mode, good mix of speed and stealth (SYN + version detection)
 - aggressive: All bells and whistles, full OS detection + scripts + enumeration

Timing Control (--timing):
 - paranoid:   Ultra-slow, evasion-focused (Nmap T0)
 - sneaky:     Very slow, stealth-focused (Nmap T1)
 - polite:     Slow, network-friendly (Nmap T2)
 - normal:     Default speed (Nmap T3)
 - aggressive: Fast scanning (Nmap T4)
 - insane:     Fastest possible (Nmap T5)

Features:
 - CVE/version awareness (--cve-check): Real-time NVD API integration for actual CVE detection
 - CISA KEV checking: Identifies actively exploited vulnerabilities
 - Intelligent caching: 7-day cache for fast repeated scans
 - Baseline tracking (--save-baseline, --compare-baseline): Detect rogue devices
 - Service version tracking: Automatic extraction from nmap probes
 - Spoof detection (--spoof-check): Multi-layer correlation analysis to detect spoofed/suspicious hosts
   * MAC/vendor mismatch detection
   * DHCP hostname inconsistencies
   * TCP/IP stack fingerprint analysis
   * Behavioral timing anomalies
   * Comprehensive visual scoring and risk assessment
 - Advanced enumeration (--enum-all or --enum-dns/smb/http/snmp/email/secrets):
   * DNS: Zone transfers, reverse DNS, record queries
   * SMB: Null sessions, shares, users
   * HTTP/HTTPS: Headers, certificates, paths
   * SNMP: Community strings, system info
   * Email: SMTP, TLS, auth mechanisms
   * Secrets: API keys, private keys, credentials
 - JSON export (--json-only): Pure JSON output for piping to jq, grep, etc.

CVE Detection (NEW in v1.0.0):
 - Real-time queries to NIST National Vulnerability Database
 - Access to 250,000+ CVEs with actual CVSS scores
 - CISA KEV integration for actively exploited vulnerabilities
 - Optional NVD API key for 10x faster scanning (still free)
 - 7-day intelligent caching for offline/fast repeat scans
 - Clear cache with --clear-cve-cache

KNOWN DEVICES:
 - Add your personal/admin machines to get_mac_vendor_aggressive() known_devices dict
 - Example: "omarchypc.local": "Personal Desktop (omarchypc)"
 - This ensures your own machines display correctly even with privacy features enabled
"""
from __future__ import annotations
import argparse, csv, glob, ipaddress, json, os, re, shutil, socket, subprocess, sys, time, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from xml.etree import ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
import hashlib
import pickle
from pathlib import Path

# Try to import requests - required for CVE checking
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Try to import correlation engine - optional for spoof detection
try:
    # Import from the same directory
    import sys
    from pathlib import Path
    script_dir = Path(__file__).parent
    sys.path.insert(0, str(script_dir))
    # Import by executing the correlation engine file
    correlation_engine_code = (script_dir / "net-inspect-v2-correlation-engine.py").read_text()
    correlation_globals = {}
    exec(correlation_engine_code, correlation_globals)
    CorrelationEngine = correlation_globals.get('CorrelationEngine')
    CORRELATION_AVAILABLE = CorrelationEngine is not None
except Exception:
    CORRELATION_AVAILABLE = False
    CorrelationEngine = None

# New feature imports (v1.0.0)
try:
    from netinspect.analysis.traffic import TrafficAnalyzer, SCAPY_AVAILABLE as TRAFFIC_SCAPY
    TRAFFIC_ANALYSIS_AVAILABLE = TRAFFIC_SCAPY
except ImportError:
    TRAFFIC_ANALYSIS_AVAILABLE = False

try:
    from netinspect.monitoring.daemon import MonitorDaemon
    DAEMON_AVAILABLE = True
except ImportError:
    DAEMON_AVAILABLE = False

try:
    from netinspect.intelligence.threat_intel import ThreatIntelChecker
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False

try:
    from netinspect.evasion.firewall import FirewallTester, SCAPY_AVAILABLE as FIREWALL_SCAPY
    FIREWALL_TEST_AVAILABLE = FIREWALL_SCAPY
except ImportError:
    FIREWALL_TEST_AVAILABLE = False

try:
    from netinspect.analysis.tls import TLSAnalyzer
    TLS_ANALYSIS_AVAILABLE = True
except ImportError:
    TLS_ANALYSIS_AVAILABLE = False

try:
    from netinspect.reporting.pdf_report import generate_pdf_report, REPORTLAB_AVAILABLE
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from netinspect.intelligence.exploits import ExploitMapper
    EXPLOIT_MAPPING_AVAILABLE = True
except ImportError:
    EXPLOIT_MAPPING_AVAILABLE = False

try:
    from netinspect.intelligence.geolocation import GeoLocator, get_public_ip
    GEOLOCATION_AVAILABLE = True
except ImportError:
    GEOLOCATION_AVAILABLE = False

try:
    from netinspect.utils.config import load_api_key
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

# Handle sudo: use original user's home, not root's
SUDO_USER = os.environ.get("SUDO_USER")
if SUDO_USER:
    HOME = f"/home/{SUDO_USER}"
else:
    HOME = os.path.expanduser("~")

# Use package-relative data directories
from pathlib import Path as _Path
_PACKAGE_ROOT = _Path(__file__).parent.parent
_DATA_DIR = _PACKAGE_ROOT / "data"
BASE = str(_DATA_DIR)
LOGS = str(_DATA_DIR / "logs")
CAPTURES = str(_DATA_DIR / "captures")
BASELINES = str(_DATA_DIR / "baselines")
RESULTS = str(_DATA_DIR / "results")
for d in [LOGS, CAPTURES, BASELINES, RESULTS]: os.makedirs(d, exist_ok=True)

# CVE API Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_API_BASE = "https://cveawg.mitre.org/api/cve"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Rate limiting (NVD: 5 requests per 30 seconds without API key, 50 with key)
NVD_RATE_LIMIT_DELAY = 6  # seconds between requests without API key
NVD_RATE_LIMIT_WITH_KEY = 0.6  # seconds between requests with API key
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # Optional: user can set this

# Caching
CVE_CACHE_DIR = os.path.join(HOME, ".cache", "net-inspect", "cve")
CVE_CACHE_DURATION_DAYS = 7  # Refresh cache after 7 days

os.makedirs(CVE_CACHE_DIR, exist_ok=True)

REQUIRED_BINS = ["nmap", "ip"]
OPTIONAL_BINS = ["tcpdump", "traceroute", "avahi-resolve", "nmblookup", "searchsploit", "openssl", "fastfetch"]
DEFAULT_CONCURRENCY, TOP_PORTS_DEFAULT, NMAP_TIMEOUT, CIDR_DISCOVERY_CONCURRENCY = 4, 200, 180, 3

# Scan Profiles: Define the behavior for quiet, balanced, and aggressive scans
SCAN_PROFILES = {
    "quiet": {
        "description": "Minimal noise, passive fingerprinting",
        "discovery_method": "-sn",           # Ping scan, no port scan
        "probe_method": "-sV",                # Service version detection only
        "os_detection": False,                # No OS detection
        "scripts": False,                     # No NSE scripts
        "enumeration_enabled": False,         # Skip aggressive enumeration
        "banner_grabbing": False,
        "warnings": "⚠️  QUIET mode: No OS detection, minimal service probing. Results may be incomplete but generates minimal noise."
    },
    "balanced": {
        "description": "Good mix of speed and stealth (DEFAULT)",
        "discovery_method": "-sn",           # Ping scan
        "probe_method": "-sS",                # SYN stealth scan
        "os_detection": False,                # No aggressive OS detection
        "scripts": False,                     # No NSE scripts
        "enumeration_enabled": True,          # Allow selective enumeration
        "banner_grabbing": False,
        "warnings": "ℹ️  BALANCED mode: Standard scan with version detection. Will appear in logs if IDS active."
    },
    "aggressive": {
        "description": "Full OS detection + scripts + enumeration",
        "discovery_method": "-sn",           # Ping scan to find hosts
        "probe_method": "-sS",                # SYN stealth scan
        "os_detection": True,                 # Full OS detection (-O)
        "scripts": True,                      # NSE scripts (-sC)
        "enumeration_enabled": True,          # Full enumeration
        "banner_grabbing": True,
        "warnings": "⚠️  AGGRESSIVE mode: Full OS detection, NSE scripts, extensive enumeration. WILL trigger IDS/alerts."
    }
}

# Nmap timing profiles
TIMING_PROFILES = {
    "paranoid": {"value": "T0", "description": "Ultra-slow, maximum evasion"},
    "sneaky":   {"value": "T1", "description": "Very slow, stealth-focused"},
    "polite":   {"value": "T2", "description": "Slow, network-friendly"},
    "normal":   {"value": "T3", "description": "Default speed"},
    "aggressive": {"value": "T4", "description": "Fast scanning"},
    "insane":   {"value": "T5", "description": "Fastest possible"}
}

# Vulnerability Risk Service Database
# Maps services to their attack vectors, CVSS info, and business impact
RISKY_SERVICES = {
    "rtsp": {
        "service_name": "RTSP (Real-Time Streaming Protocol)",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cwe": "CWE-295",  # Improper Certificate Validation
        "attack_vectors": [
            "Man-in-the-middle stream interception",
            "Plaintext credential capture",
            "Unauthorized device access via stream URL",
            "Stream URL hijacking"
        ],
        "exploitation_difficulty": "LOW",
        "timeline_to_exploit": "Minutes",
        "business_impact": "Media device compromise, unauthorized access to streams, credential exposure",
        "remediation": [
            "Enable RTSP over TLS (RTSP+TLS/SRTP)",
            "Use strong authentication credentials",
            "Restrict RTSP to internal network only",
            "Disable RTSP if not needed"
        ]
    },
    "telnet": {
        "service_name": "Telnet",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cwe": "CWE-319",  # Cleartext Transmission of Sensitive Information
        "attack_vectors": [
            "Plaintext password interception",
            "Session hijacking",
            "Man-in-the-middle attacks",
            "Device takeover after authentication"
        ],
        "exploitation_difficulty": "VERY_LOW",
        "timeline_to_exploit": "Seconds",
        "business_impact": "Complete device compromise, credentials exposed, potential network pivot point",
        "remediation": [
            "Disable Telnet immediately",
            "Enable SSH instead",
            "Use strong authentication",
            "Restrict access to admin networks only"
        ]
    },
    "http": {
        "service_name": "HTTP (Unencrypted Web)",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "cwe": "CWE-295",
        "attack_vectors": [
            "Session cookie interception",
            "Plaintext credential capture",
            "Man-in-the-middle attacks",
            "Web application data exposure"
        ],
        "exploitation_difficulty": "LOW",
        "timeline_to_exploit": "Minutes",
        "business_impact": "Credential exposure, session hijacking, unauthorized access to web services",
        "remediation": [
            "Enable HTTPS/TLS encryption",
            "Use HTTP Strict-Transport-Security (HSTS)",
            "Require authentication over HTTPS only",
            "Use secure cookies (httponly, secure flags)"
        ]
    },
    "snmp": {
        "service_name": "SNMP (Simple Network Management Protocol)",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cwe": "CWE-200",  # Information Exposure
        "attack_vectors": [
            "Community string bruteforce",
            "Device information gathering",
            "Network topology exposure",
            "Configuration modification with write access"
        ],
        "exploitation_difficulty": "LOW",
        "timeline_to_exploit": "Minutes",
        "business_impact": "Network topology exposure, device configuration access, potential for device manipulation",
        "remediation": [
            "Disable SNMP if not needed",
            "Use SNMPv3 with authentication and encryption",
            "Change default community strings (public/private)",
            "Restrict SNMP to trusted networks"
        ]
    },
    "ftp": {
        "service_name": "FTP (File Transfer Protocol)",
        "severity": "CRITICAL",
        "cvss_score": 8.1,
        "cwe": "CWE-319",
        "attack_vectors": [
            "Plaintext credential interception",
            "Session hijacking",
            "Unauthorized file access",
            "Malware upload/download"
        ],
        "exploitation_difficulty": "VERY_LOW",
        "timeline_to_exploit": "Minutes",
        "business_impact": "File system compromise, credential exposure, malware propagation vector",
        "remediation": [
            "Disable FTP immediately",
            "Use SFTP (SSH File Transfer Protocol) instead",
            "If FTP required, use FTPS (FTP over TLS)",
            "Restrict to trusted networks only"
        ]
    },
    "smtp": {
        "service_name": "SMTP (Unencrypted Email)",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cwe": "CWE-319",
        "attack_vectors": [
            "Email interception",
            "Plaintext credential capture",
            "Email spoofing",
            "Spam relay abuse"
        ],
        "exploitation_difficulty": "LOW",
        "timeline_to_exploit": "Minutes",
        "business_impact": "Email compromise, credential exposure, spam/phishing relay vector",
        "remediation": [
            "Require TLS encryption (STARTTLS)",
            "Use SMTP over TLS (port 465)",
            "Require authentication",
            "Implement SPF, DKIM, DMARC"
        ]
    },
    "dns": {
        "service_name": "DNS (Unencrypted)",
        "severity": "MEDIUM",
        "cvss_score": 5.9,
        "cwe": "CWE-300",  # Channel Accessible by Non-Endpoint
        "attack_vectors": [
            "DNS cache poisoning",
            "Man-in-the-middle attacks",
            "DNS hijacking",
            "Traffic interception via DNS"
        ],
        "exploitation_difficulty": "MEDIUM",
        "timeline_to_exploit": "Hours",
        "business_impact": "Potential redirection to malicious sites, credentials exposure via phishing",
        "remediation": [
            "Enable DNSSEC",
            "Use DNS over TLS (DoT) or DNS over HTTPS (DoH)",
            "Restrict DNS access to trusted networks",
            "Monitor for unusual DNS queries"
        ]
    },
    "ssh": {
        "service_name": "SSH (may have old version)",
        "severity": "MEDIUM",  # Varies by version
        "cvss_score": 6.5,
        "cwe": "CWE-327",  # Use of Broken/Risky Cryptographic Algorithm
        "attack_vectors": [
            "SSH user enumeration",
            "Brute force attacks",
            "Key exchange vulnerabilities",
            "Version-specific exploits"
        ],
        "exploitation_difficulty": "MEDIUM",
        "timeline_to_exploit": "Hours to days",
        "business_impact": "Unauthorized SSH access, privilege escalation, persistent access",
        "remediation": [
            "Update to latest SSH version",
            "Disable password authentication (use keys only)",
            "Change default SSH port",
            "Restrict SSH access by IP",
            "Use strong key sizes (4096-bit RSA or ED25519)"
        ]
    }
}

# Tcpdump process tracking
tcpdump_processes = {}  # {capture_id: {"process": Popen, "host_ip": str, "file": str, "start": datetime, "stats": dict}}

# ============================================================================
# CVE CHECKER CLASS - Real-time NVD API Integration
# ============================================================================

class CVEChecker:
    """
    Multi-source CVE vulnerability checker with intelligent caching.
    
    Features:
    - Queries NVD API for real CVE data
    - Falls back to CVE.org if NVD is down
    - Checks CISA KEV for actively exploited vulnerabilities
    - Caches results for 7 days
    - Handles rate limiting automatically
    - Works offline if cache is populated
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.cache_dir = Path(CVE_CACHE_DIR)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or NVD_API_KEY
        
        # Check if requests is available
        if not REQUESTS_AVAILABLE:
            if USE_RICH:
                console.print("[yellow]⚠️  'requests' library not available. CVE checking disabled.[/yellow]")
                console.print("[yellow]   Install with: pip install requests --break-system-packages[/yellow]")
            else:
                print("⚠️  'requests' library not available. CVE checking disabled.")
                print("   Install with: pip install requests --break-system-packages")
            self.enabled = False
            return
        
        self.enabled = True
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'net-inspect/1.0.0 (Network Security Scanner)'
        })
        
        # Add API key if available
        if self.api_key:
            self.session.headers.update({'apiKey': self.api_key})
        
        # Load CISA KEV list
        self.kev_cves = self._load_kev_list()
        
        # Track API calls for rate limiting
        self.last_api_call = 0
        self.rate_limit_delay = NVD_RATE_LIMIT_WITH_KEY if self.api_key else NVD_RATE_LIMIT_DELAY
    
    def _load_kev_list(self) -> set:
        """Load CISA Known Exploited Vulnerabilities list"""
        kev_cache = self.cache_dir / "cisa_kev.json"
        
        # Use cache if recent (less than 1 day old)
        if kev_cache.exists():
            age_seconds = time.time() - kev_cache.stat().st_mtime
            if age_seconds < 86400:  # 24 hours
                try:
                    with open(kev_cache, 'r') as f:
                        data = json.load(f)
                        return {v['cveID'] for v in data.get('vulnerabilities', [])}
                except:
                    pass
        
        # Fetch fresh KEV list
        try:
            response = self.session.get(CISA_KEV_URL, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Cache it
                with open(kev_cache, 'w') as f:
                    json.dump(data, f)
                
                return {v['cveID'] for v in data.get('vulnerabilities', [])}
        except Exception as e:
            pass  # Fail silently, KEV is optional enhancement
        
        return set()
    
    def _get_cache_key(self, product: str, version: str) -> str:
        """Generate cache filename for product+version"""
        key = f"{product.lower()}_{version.lower()}"
        hash_key = hashlib.md5(key.encode()).hexdigest()
        return f"cve_{hash_key}.pkl"
    
    def _read_cache(self, product: str, version: str) -> Optional[List[Dict]]:
        """Read CVE data from cache if fresh"""
        cache_file = self.cache_dir / self._get_cache_key(product, version)
        
        if not cache_file.exists():
            return None
        
        # Check age
        age_seconds = time.time() - cache_file.stat().st_mtime
        cache_max_age = CVE_CACHE_DURATION_DAYS * 86400  # days to seconds
        
        if age_seconds > cache_max_age:
            return None
        
        # Load cached data
        try:
            with open(cache_file, 'rb') as f:
                return pickle.load(f)
        except:
            return None
    
    def _write_cache(self, product: str, version: str, cve_data: List[Dict]):
        """Write CVE data to cache"""
        cache_file = self.cache_dir / self._get_cache_key(product, version)
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(cve_data, f)
        except Exception as e:
            pass  # Non-critical if cache write fails
    
    def _rate_limit(self):
        """Enforce NVD API rate limiting"""
        elapsed = time.time() - self.last_api_call
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_api_call = time.time()
    
    def check_product_version(self, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Check for CVEs affecting a specific product version.
        
        Args:
            product: Service name (e.g., "Apache", "OpenSSH", "nginx")
            version: Version string (e.g., "2.4.49", "8.2p1")
        
        Returns:
            List of CVE dictionaries
        """
        if not self.enabled:
            return []
        
        # Check cache first
        cached = self._read_cache(product, version)
        if cached is not None:
            return cached
        
        # Query APIs
        cves = []
        
        # Try NVD first
        try:
            cves = self._query_nvd(product, version)
        except Exception as e:
            pass  # Fail silently
        
        # Enrich with KEV status
        for cve in cves:
            cve['exploited'] = cve['cve_id'] in self.kev_cves
        
        # Cache results (even if empty, to avoid repeated failed queries)
        self._write_cache(product, version, cves)
        
        return cves
    
    def _query_nvd(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Query NIST NVD API"""
        self._rate_limit()
        
        # Build search query
        keyword = f"{product} {version}"
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 20
        }
        
        try:
            response = self.session.get(NVD_API_BASE, params=params, timeout=15)
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            return self._parse_nvd_response(data)
        except:
            return []
    
    def _parse_nvd_response(self, data: dict) -> List[Dict[str, Any]]:
        """Parse NVD API JSON response"""
        vulnerabilities = []
        
        if 'vulnerabilities' not in data:
            return []
        
        for vuln_item in data['vulnerabilities']:
            cve_data = vuln_item.get('cve', {})
            
            # Extract CVE ID
            cve_id = cve_data.get('id', 'Unknown')
            
            # Extract CVSS score and severity
            cvss_score = 0
            severity = "UNKNOWN"
            cwe = "Unknown"
            
            metrics = cve_data.get('metrics', {})
            
            # Try CVSS v3.1 first (preferred)
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            # Fall back to CVSS v3.0
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            # Fall back to CVSS v2.0
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0)
                severity = self._cvss2_to_severity(cvss_score)
            
            # Extract CWE
            weaknesses = cve_data.get('weaknesses', [])
            if weaknesses:
                for weakness in weaknesses:
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            cwe = desc.get('value', 'Unknown')
                            break
            
            # Extract description
            description = ""
            descriptions = cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract references
            references = []
            refs = cve_data.get('references', [])
            for ref in refs[:3]:  # Limit to 3 references
                references.append(ref.get('url', ''))
            
            # Published date
            published = cve_data.get('published', 'Unknown')
            if published != 'Unknown':
                published = published.split('T')[0]  # Just date, not time
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'cvss_score': cvss_score,
                'severity': severity,
                'description': description,
                'published': published,
                'references': references,
                'cwe': cwe,
                'exploited': False  # Will be set later
            })
        
        return vulnerabilities
    
    def _cvss2_to_severity(self, score: float) -> str:
        """Convert CVSS 2.0 score to severity label"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def clear_cache(self):
        """Clear all cached CVE data"""
        import shutil
        shutil.rmtree(self.cache_dir, ignore_errors=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)


def normalize_service_name(service: str) -> str:
    """Normalize service names to match CVE database conventions"""
    service_map = {
        'httpd': 'Apache',
        'apache2': 'Apache',
        'ssh': 'OpenSSH',
        'openssh': 'OpenSSH',
        'mysql': 'MySQL',
        'mariadb': 'MariaDB',
        'postgresql': 'PostgreSQL',
        'postgres': 'PostgreSQL',
        'http': 'nginx',
        'https': 'nginx'
    }
    
    service_lower = service.lower()
    
    for key, value in service_map.items():
        if key in service_lower:
            return value
    
    return service.capitalize()


def clean_version_string(version: str) -> str:
    """Clean and normalize version strings"""
    # Remove common prefixes
    version = re.sub(r'^v\.?', '', version, flags=re.IGNORECASE)
    
    # Extract just the version number
    match = re.search(r'(\d+\.\d+\.?\d*[a-z]?\d*)', version)
    if match:
        return match.group(1)
    
    return version

USE_RICH = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Prompt
    USE_RICH = True
    console = Console()
except: console = None

# ============================================================================
# ENUMERATION MODULES (v1.5.0 - NEW)
# ============================================================================

class EnumDNS:
    """DNS enumeration: zone transfers, reverse DNS, records"""
    @staticmethod
    def zone_transfer(host_ip: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
        try:
            result = subprocess.run(["dig", f"@{host_ip}", "axfr", "example.com"], capture_output=True, text=True, timeout=timeout)
            if result.returncode == 0 and "example.com" in result.stdout:
                return {"zone_transfer_possible": True, "raw": result.stdout[:200]}
            return {"zone_transfer_possible": False}
        except: return None

class EnumSMB:
    """SMB enumeration: shares, users, null sessions"""
    @staticmethod
    def null_session_check(host_ip: str, timeout: int = 10) -> Optional[bool]:
        try:
            result = subprocess.run(["smbclient", "-N", "-L", host_ip], capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0
        except: return None
    
    @staticmethod
    def enum_shares(host_ip: str, timeout: int = 10) -> Optional[List[str]]:
        try:
            result = subprocess.run(["smbclient", "-N", "-L", host_ip], capture_output=True, text=True, timeout=timeout)
            shares = []
            for line in result.stdout.split("\n"):
                if "\t" in line and "IPC$" not in line and "$" not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        shares.append(parts[0])
            return shares if shares else None
        except: return None

class EnumHTTP:
    """HTTP enumeration: headers, certs, paths"""
    @staticmethod
    def grab_headers(url: str, timeout: int = 10) -> Optional[Dict[str, str]]:
        try:
            result = subprocess.run(["curl", "-I", "-s", "-m", str(timeout), url], capture_output=True, text=True, timeout=timeout + 2)
            headers = {}
            for line in result.stdout.split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            return headers if headers else None
        except: return None
    
    @staticmethod
    def parse_certificate(host_ip: str, port: int = 443, timeout: int = 10) -> Optional[Dict[str, str]]:
        try:
            result = subprocess.run(["openssl", "s_client", "-connect", f"{host_ip}:{port}", "-servername", host_ip], input=b"", capture_output=True, timeout=timeout + 2)
            cert_data = {}
            stdout_text = result.stdout.decode('utf-8', errors='ignore')
            for line in stdout_text.split("\n"):
                if "subject=" in line:
                    cert_data["subject"] = line.split("subject=")[-1].strip()
                if "notAfter=" in line:
                    cert_data["expiry"] = line.split("notAfter=")[-1].strip()
            return cert_data if cert_data else None
        except: return None

class EnumSNMP:
    """SNMP enumeration: community strings, system info"""
    @staticmethod
    def community_brute(host_ip: str, wordlist: List[str], timeout: int = 10) -> Optional[Dict[str, Any]]:
        results = {}
        for community in wordlist[:5]:  # Limit to first 5 for speed
            try:
                result = subprocess.run(["snmpget", "-v", "2c", "-c", community, "-t", str(timeout), host_ip, "1.3.6.1.2.1.1.1.0"], capture_output=True, text=True, timeout=timeout + 2)
                if result.returncode == 0 and "Timeout" not in result.stderr:
                    results[community] = {"version": "2c", "info": result.stdout.strip()[:100]}
                    return results
            except: pass
        return results if results else None

class EnumEmail:
    """Email enumeration: SMTP, TLS, auth"""
    @staticmethod
    def smtp_enum(host_ip: str, port: int = 25, timeout: int = 10) -> Optional[Dict[str, Any]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host_ip, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.send(b"STARTTLS\r\n")
            tls_resp = sock.recv(1024).decode('utf-8', errors='ignore')
            tls_supported = "220" in tls_resp or "250" in tls_resp
            sock.close()
            return {"banner": banner[:50], "tls_supported": tls_supported}
        except: return None

class EnumSecrets:
    """Secrets scanning in responses"""
    SECRET_PATTERNS = {
        "AWS_API_KEY": r"AKIA[0-9A-Z]{16}",
        "PRIVATE_KEY": r"-----BEGIN (?:RSA|DSA|EC)? ?PRIVATE KEY",
        "DB_PASSWORD": r"(?:password|passwd)\s*[=:]\s*['\"]?([^'\"]{8,})['\"]?",
        "JWT_TOKEN": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+",
        "API_KEY": r"(?:api[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
    }
    
    @staticmethod
    def scan_text(text: str) -> Optional[List[Dict[str, str]]]:
        secrets_found = []
        try:
            for secret_type, pattern in EnumSecrets.SECRET_PATTERNS.items():
                if re.search(pattern, text, re.IGNORECASE):
                    secrets_found.append({"type": secret_type})
        except: pass
        return secrets_found if secrets_found else None

def check_dependencies() -> List[Tuple[str,bool,bool,str]]:
    """
    Check all dependencies and return organized list.
    Returns: List of (name, installed, required, category)
    """
    deps = []
    
    # REQUIRED dependencies
    for b in REQUIRED_BINS: 
        deps.append((b, shutil.which(b) is not None, True, "required"))
    
    # NETWORK TOOLS (optional)
    network_tools = ["tcpdump", "traceroute", "avahi-resolve", "nmblookup"]
    for b in network_tools:
        if b in OPTIONAL_BINS:
            deps.append((b, shutil.which(b) is not None, False, "network"))
    
    # SECURITY TOOLS (optional)
    security_tools = ["searchsploit", "openssl"]
    for b in security_tools:
        if b in OPTIONAL_BINS:
            deps.append((b, shutil.which(b) is not None, False, "security"))
    
    # PYTHON PACKAGES (optional)
    deps.append(("rich (python)", USE_RICH, False, "python"))
    deps.append(("requests (python)", REQUESTS_AVAILABLE, False, "python"))
    try:
        import manuf
        deps.append(("manuf (python)", True, False, "python"))
    except:
        deps.append(("manuf (python)", False, False, "python"))

    # NEW v1.0.0 Python packages
    deps.append(("scapy (python)", TRAFFIC_ANALYSIS_AVAILABLE or FIREWALL_TEST_AVAILABLE, False, "python"))
    deps.append(("reportlab (python)", REPORTLAB_AVAILABLE, False, "python"))
    
    # SYSTEM TOOLS (optional)
    system_tools = ["fastfetch"]
    for b in system_tools:
        if b in OPTIONAL_BINS:
            deps.append((b, shutil.which(b) is not None, False, "system"))
    
    return deps

def print_dependency_check():
    deps = check_dependencies()
    
    # Organize by category
    categories = {
        "required": [],
        "network": [],
        "security": [],
        "python": [],
        "system": []
    }
    
    for name, ok, required, category in deps:
        categories[category].append((name, ok, required))
    
    if USE_RICH:
        t = Table(title="Dependency Check", show_header=True, header_style="bold magenta")
        t.add_column("Dependency")
        t.add_column("Status", justify="center")
        t.add_column("Notes")
        
        # REQUIRED section
        if categories["required"]:
            t.add_row("[bold magenta]REQUIRED[/bold magenta]", "", "")
            for name, ok, required in categories["required"]:
                s = "[green]✅[/green]" if ok else "[red]❌[/red]"
                t.add_row(name, s, "required")
        
        # NETWORK TOOLS section
        if categories["network"]:
            t.add_row("", "", "")  # Spacer
            t.add_row("[bold blue]NETWORK TOOLS[/bold blue]", "", "")
            for name, ok, required in categories["network"]:
                s = "[green]✅[/green]" if ok else "[yellow]⚠[/yellow]"
                note = "optional"
                if "avahi" in name: note = "optional (hostname resolution)"
                elif "nmblookup" in name: note = "optional (NetBIOS lookup)"
                elif "tcpdump" in name: note = "optional (packet capture)"
                elif "traceroute" in name: note = "optional (network mapping)"
                t.add_row(name, s, note)
        
        # SECURITY TOOLS section
        if categories["security"]:
            t.add_row("", "", "")  # Spacer
            t.add_row("[bold red]SECURITY TOOLS[/bold red]", "", "")
            for name, ok, required in categories["security"]:
                s = "[green]✅[/green]" if ok else "[yellow]⚠[/yellow]"
                note = "optional"
                if "searchsploit" in name: note = "optional (CVE/exploit lookup)"
                elif "openssl" in name: note = "optional (SSL/TLS inspection)"
                t.add_row(name, s, note)
        
        # PYTHON PACKAGES section
        if categories["python"]:
            t.add_row("", "", "")  # Spacer
            t.add_row("[bold yellow]PYTHON PACKAGES[/bold yellow]", "", "")
            for name, ok, required in categories["python"]:
                s = "[green]✅[/green]" if ok else "[yellow]⚠[/yellow]"
                note = "optional"
                if "requests" in name: note = "optional (NVD API for CVE checking)"
                elif "rich" in name: note = "optional (enhanced formatting)"
                elif "manuf" in name: note = "optional (MAC vendor lookup)"
                elif "scapy" in name: note = "optional (traffic analysis, firewall testing)"
                elif "reportlab" in name: note = "optional (PDF report generation)"
                t.add_row(name, s, note)
        
        # SYSTEM TOOLS section
        if categories["system"]:
            t.add_row("", "", "")  # Spacer
            t.add_row("[bold green]SYSTEM TOOLS[/bold green]", "", "")
            for name, ok, required in categories["system"]:
                s = "[green]✅[/green]" if ok else "[yellow]⚠[/yellow]"
                note = "optional (system information)"
                t.add_row(name, s, note)
        
        console.print(t)
        console.print("[bold]Notes:[/bold] [green]✅[/green] installed  [red]❌[/red] required missing  [yellow]⚠[/yellow] optional missing\n")
    else:
        print("\nDEPENDENCY CHECK\n")
        print(f"{'Dependency':30} {'Status':8} Notes")
        print("-" * 80)
        
        # Print organized sections
        print("REQUIRED:")
        for name, ok, required in categories["required"]:
            s = "✅" if ok else "❌"
            print(f"  {name:28} {s:8} required")
        
        if categories["network"]:
            print("\nNETWORK TOOLS:")
            for name, ok, required in categories["network"]:
                s = "✅" if ok else "⚠"
                note = "optional"
                if "tcpdump" in name: note = "optional (packet capture)"
                print(f"  {name:28} {s:8} {note}")
        
        if categories["security"]:
            print("\nSECURITY TOOLS:")
            for name, ok, required in categories["security"]:
                s = "✅" if ok else "⚠"
                note = "optional"
                if "searchsploit" in name: note = "optional (CVE/exploit lookup)"
                print(f"  {name:28} {s:8} {note}")
        
        if categories["python"]:
            print("\nPYTHON PACKAGES:")
            for name, ok, required in categories["python"]:
                s = "✅" if ok else "⚠"
                note = "optional"
                if "requests" in name: note = "optional (NVD API for CVE checking)"
                elif "rich" in name: note = "optional (enhanced formatting)"
                elif "manuf" in name: note = "optional (MAC vendor lookup)"
                elif "scapy" in name: note = "optional (traffic analysis, firewall testing)"
                elif "reportlab" in name: note = "optional (PDF report generation)"
                print(f"  {name:28} {s:8} {note}")
        
        if categories["system"]:
            print("\nSYSTEM TOOLS:")
            for name, ok, required in categories["system"]:
                s = "✅" if ok else "⚠"
                print(f"  {name:28} {s:8} optional")
        
        print()

# ============================================================================
# IPv6 SUPPORT FUNCTIONS (NEW in v1.5.0)
# ============================================================================

def validate_and_normalize_cidr(cidr_str: str) -> Tuple[str, int]:
    """
    Validate and normalize CIDR input for both IPv4 and IPv6.
    Returns (normalized_cidr, ip_version) where ip_version is 4 or 6.
    
    Examples:
      "192.168.1.1" -> ("192.168.1.1/32", 4)
      "2001:db8::1" -> ("2001:db8::1/128", 6)
      "10.0.0.0/24" -> ("10.0.0.0/24", 4)
    """
    cidr_str = cidr_str.strip()
    try:
        if '/' in cidr_str:
            net = ipaddress.ip_network(cidr_str, strict=False)
            return (str(net), net.version)
        else:
            # Single IP - auto-add /32 or /128
            ip = ipaddress.ip_address(cidr_str)
            prefix = "/32" if ip.version == 4 else "/128"
            return (str(ip) + prefix, ip.version)
    except Exception as e:
        return None

def format_url_for_ip_version(host: str, ip_version: int, port: int = 80) -> str:
    """
    Format URL correctly for IPv4 or IPv6.
    IPv6 addresses need brackets in URLs.
    """
    if ip_version == 6:
        return f"http://[{host}]:{port}/"
    return f"http://{host}:{port}/"

def detect_iface_and_cidr(prefer_ipv6: bool = False) -> Tuple[str,str]:
    """Detect network interface and CIDR.
    
    Args:
        prefer_ipv6: If True, try to detect IPv6 CIDR instead of IPv4
    """
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        m = re.search(r"dev\s+(\S+)", out)
        if not m: raise RuntimeError("Couldn't parse default route (no dev).")
        iface = m.group(1)
        
        if prefer_ipv6:
            # Try to get IPv6 address
            out2 = subprocess.check_output(["ip", "-o", "-f", "inet6", "addr", "show", iface], text=True)
            # Look for global unicast or ULA addresses (not link-local fe80::)
            for line in out2.splitlines():
                m2 = re.search(r"((?:2[0-9a-fA-F]{3}|fd[0-9a-fA-F]{2}):[0-9a-fA-F:]+/\d+)", line)
                if m2:
                    return iface, m2.group(1)
            # Fallback to link-local if no global address
            m2 = re.search(r"(fe80:[0-9a-fA-F:]+/\d+)", out2)
            if m2:
                return iface, m2.group(1)
            # If no IPv6, fall back to IPv4
        
        # IPv4 detection (default)
        out2 = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show", iface], text=True)
        m2 = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", out2)
        if not m2: raise RuntimeError("Couldn't determine CIDR for interface.")
        return iface, m2.group(1)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"'ip' command failed: {e}")

def parse_cidr_input(cidr_arg, cidrs_arg, cidr_file) -> List[str]:
    cidrs = []
    # Handle cidr_arg which is now a list from action='append'
    if cidr_arg:
        for c in (cidr_arg if isinstance(cidr_arg, list) else [cidr_arg]):
            c = c.strip()
            if c:
                # Validate and normalize CIDR (IPv4/IPv6)
                result = validate_and_normalize_cidr(c)
                if result:
                    normalized_cidr, ip_version = result
                    cidrs.append(normalized_cidr)
                    # Warn about large IPv6 subnets
                    if ip_version == 6:
                        prefix = int(normalized_cidr.split('/')[-1])
                        if prefix <= 64:
                            if USE_RICH: 
                                console.print(f"[yellow]⚠️  Warning: IPv6 /{prefix} subnet is very large. Discovery may be slow or incomplete.[/yellow]")
                                console.print(f"[yellow]   Recommendation: Scan specific hosts (e.g., fe80::1) or use smaller subnets.[/yellow]")
                            else: 
                                print(f"⚠️  Warning: IPv6 /{prefix} subnet is very large. Discovery may be slow or incomplete.")
                                print(f"   Recommendation: Scan specific hosts (e.g., fe80::1) or use smaller subnets.")
                else:
                    if USE_RICH: console.print(f"[yellow]Warning: Invalid CIDR '{c}' (IPv4 or IPv6)[/yellow]")
                    else: print(f"Warning: Invalid CIDR '{c}' (IPv4 or IPv6)")
    if cidrs_arg:
        for c in cidrs_arg.split(','): 
            c = c.strip()
            if c:
                result = validate_and_normalize_cidr(c)
                if result:
                    normalized_cidr, ip_version = result
                    cidrs.append(normalized_cidr)
                    # Warn about large IPv6 subnets
                    if ip_version == 6:
                        prefix = int(normalized_cidr.split('/')[-1])
                        if prefix <= 64:
                            if USE_RICH: 
                                console.print(f"[yellow]⚠️  Warning: IPv6 /{prefix} subnet is very large. Discovery may be slow or incomplete.[/yellow]")
                            else: 
                                print(f"⚠️  Warning: IPv6 /{prefix} subnet is very large. Discovery may be slow or incomplete.")
                else:
                    if USE_RICH: console.print(f"[yellow]Warning: Invalid CIDR '{c}' (IPv4 or IPv6)[/yellow]")
                    else: print(f"Warning: Invalid CIDR '{c}' (IPv4 or IPv6)")
    if cidr_file:
        try:
            with open(cidr_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        result = validate_and_normalize_cidr(line)
                        if result:
                            normalized_cidr, ip_version = result
                            cidrs.append(normalized_cidr)
                        else:
                            if USE_RICH: console.print(f"[yellow]Warning: Invalid CIDR '{line}' in file (IPv4 or IPv6)[/yellow]")
                            else: print(f"Warning: Invalid CIDR '{line}' in file (IPv4 or IPv6)")
        except Exception as e:
            if USE_RICH: console.print(f"[yellow]Warning: Could not read CIDR file {cidr_file}: {e}[/yellow]")
            else: print(f"Warning: Could not read CIDR file {cidr_file}: {e}")
    seen = set()
    unique_cidrs = []
    for c in cidrs:
        if c not in seen:
            seen.add(c)
            unique_cidrs.append(c)
    return unique_cidrs

def extract_vendors_from_pcap(pcap_file: str) -> Dict[str, str]:
    """Extract vendor info from PCAP file by analyzing packet headers and DHCP/mDNS data."""
    vendors_found = {}
    
    try:
        import dpkt
    except ImportError:
        return vendors_found
    
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    src_mac = ':'.join(['%02x' % b for b in eth.src])
                    dst_mac = ':'.join(['%02x' % b for b in eth.dst])
                    
                    # Try to extract from various packet types
                    # DHCP packets often contain hostname and vendor class info
                    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                        ip = eth.data
                        if isinstance(ip, dpkt.ip.IP):
                            # Check for DHCP (UDP port 67/68)
                            if hasattr(ip, 'data') and isinstance(ip.data, dpkt.udp.UDP):
                                udp = ip.data
                                if udp.dport == 68 or udp.sport == 68:
                                    try:
                                        dhcp = dpkt.dhcp.DHCP(udp.data)
                                        # Extract vendor class identifier
                                        for opt_type, opt_val in dhcp.opts:
                                            if opt_type == 60:  # Vendor Class Identifier
                                                vendor_str = opt_val.decode('utf-8', errors='ignore').lower()
                                                # Parse common vendor strings
                                                if 'dhcp' in vendor_str or 'client' in vendor_str:
                                                    src_mac_upper = src_mac.upper()
                                                    if 'apple' in vendor_str or 'darwin' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Apple"
                                                    elif 'samsung' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Samsung"
                                                    elif 'roku' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Roku"
                                                    elif 'google' in vendor_str or 'chromecast' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Google"
                                                    elif 'amazon' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Amazon"
                                                    elif 'philips' in vendor_str or 'hue' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Philips"
                                                    elif 'sonos' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Sonos"
                                                    elif 'nest' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Google Nest"
                                                    elif 'echo' in vendor_str or 'alexaconnect' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Amazon Alexa"
                                                    elif 'xbox' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Microsoft"
                                                    elif 'playstation' in vendor_str or 'sony' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Sony"
                                                    elif 'nintendo' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Nintendo"
                                                    elif 'windows' in vendor_str or 'msdhcp' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Microsoft"
                                                    elif 'linux' in vendor_str or 'android' in vendor_str:
                                                        vendors_found[src_mac_upper] = "Linux/Android Device"
                                    except: pass
                    
                    # mDNS packets (.local hostnames) can reveal device type
                    elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                        pass  # Could add IPv6 support later
                        
                except: pass
    except Exception as e:
        pass
    
    return vendors_found

def get_mac_vendor_enhanced(mac: Optional[str], hostname: Optional[str] = None, pcap_vendors: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Enhanced vendor lookup with PCAP data support."""
    if not mac: return None
    mac_parts = mac.replace('-', ':').replace('.', ':').split(':')
    if len(mac_parts) < 3: return None
    oui = ':'.join(mac_parts[:3]).upper()
    mac_full = mac.replace(':', '').replace('-', '').upper()
    mac_upper = mac.upper()
    
    # Strategy 0: Check PCAP-extracted vendors first (most network-aware)
    if pcap_vendors:
        if mac_upper in pcap_vendors:
            return pcap_vendors[mac_upper]
        if mac_full in pcap_vendors:
            return pcap_vendors[mac_full]
    
    # Strategy 1: Try Python manuf library (fastest local lookup)
    try:
        import manuf
        p = manuf.MacParser()
        vendor = p.get_manuf(mac)
        if vendor: return vendor
    except: pass
    
    # Strategy 2: Check nmap OUI database (local, fast, reliable)
    nmap_db_paths = ['/usr/share/nmap/nmap-mac-prefixes', '/usr/local/share/nmap/nmap-mac-prefixes', '/opt/nmap/nmap-mac-prefixes']
    for db_path in nmap_db_paths:
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as f:
                    for line in f:
                        if line.startswith(oui):
                            parts = line.split(None, 1)
                            if len(parts) > 1: return parts[1].strip()
            except: pass
    
    # Strategy 3: Built-in comprehensive MAC OUI patterns (no network needed - FAST)
    builtin_patterns = {
        # Apple
        r"^A4:5E:60": "Apple", r"^EC:F4:BB": "Apple", r"^00:1C:14": "Apple",
        r"^00:25:86": "Apple", r"^38:C0:EB": "Apple", r"^5A:F3:FC": "Apple",
        r"^D8:96:95": "Apple", r"^AC:DE:48": "Apple", r"^34:AB:95": "Apple",
        # Cisco
        r"^00:1A:2B": "Cisco", r"^00:1D:45": "Cisco", r"^00:1E:F7": "Cisco",
        r"^00:21:1E": "Cisco", r"^00:23:04": "Cisco", r"^00:24:97": "Cisco",
        # Intel
        r"^00:11:22": "Intel", r"^00:23:6C": "Intel", r"^1C:B1:D7": "Intel",
        r"^54:E6:FC": "Intel", r"^78:45:C4": "Intel",
        # Microsoft
        r"^00:50:F2": "Microsoft", r"^7C:ED:8D": "Microsoft", r"^D8:BB:C1": "Microsoft",
        # Nintendo
        r"^20:0B:CF": "Nintendo", r"^00:17:AB": "Nintendo", r"^9C:D9:9E": "Nintendo",
        # Valve (Steam Deck)
        r"^2C:3B:70": "Valve", r"^98:B8:E3": "Valve",
        # VMware / Virtualization
        r"^00:0C:29": "VMware", r"^00:05:69": "VMware", r"^52:54:00": "QEMU",
        r"^08:00:27": "VirtualBox", r"^54:52:00": "Xensource", r"^EC:10:12": "Xen",
        r"^02:42:AC": "Docker", r"^00:16:3E": "Xen", r"^FA:16:3E": "OpenStack",
        # Networking
        r"^00:13:10": "Linksys", r"^00:1F:3A": "D-Link", r"^00:04:9F": "Netgate",
        r"^00:26:62": "ASUS", r"^00:16:B0": "Juniper", r"^00:04:96": "Juniper",
        r"^3C:4A:92": "Arista", r"^2C:9D:FA": "Broadcom", r"^BC:5A:B0": "Ralink",
        r"^C8:9E:43": "Netgear", r"^00:22:B0": "Netgear", r"^A0:21:95": "Netgear",
        # Consumer Electronics
        r"^98:8E:94": "Samsung", r"^E0:55:3D": "Samsung", r"^40:F4:38": "Samsung",
        r"^A4:A5:83": "LG Electronics", r"^80:3F:5D": "Sony", r"^A0:26:F0": "GoPro",
        # Google
        r"^1C:BD:B9": "Google", r"^54:27:58": "Google",
        # Consumer TV / Media
        r"^C4:8B:66": "ONN", r"^00:1D:7E": "LG Smart TV", r"^D4:6E:0E": "Roku",
        # Networking/Telecom
        r"^00:E0:4C": "Realtek", r"^F8:8F:CA": "Realtek", r"^D8:27:88": "HP",
        r"^CC:C0:8E": "HP", r"^2C:C2:60": "HP", r"^04:F1:30": "Polycom",
        # Other
        r"^00:0A:95": "Netscreen", r"^78:A1:06": "Netgate", r"^3E:1A:8A": "Fortinet",
        r"^00:30:05": "Linksys", r"^00:11:5F": "D-Link",
    }
    for pat, vendor in builtin_patterns.items():
        if re.match(pat, mac_upper): return vendor
    
    # Strategy 4: Try online MAC APIs (with generous timeouts)
    try:
        import urllib.request
        url = f"https://api.macaddress.io/?output=json&search={mac_full}"
        req = urllib.request.Request(url, headers={'User-Agent': 'net-inspect/1.5'})
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                if data.get("vendorDetails", {}).get("vendorName"):
                    return data["vendorDetails"]["vendorName"]
        except urllib.error.URLError: pass
        except socket.timeout: pass
        except Exception: pass
    except: pass
    
    # Strategy 5: Try alternative MAC API (maclookup.app)
    try:
        import urllib.request
        url = f"https://api.maclookup.app/v2/macs/{mac_full}"
        req = urllib.request.Request(url, headers={'User-Agent': 'net-inspect/1.5'})
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                if data.get("vendorName"):
                    return data["vendorName"]
        except urllib.error.URLError: pass
        except socket.timeout: pass
        except Exception: pass
    except: pass
    
    # Strategy 6: Try to extract vendor from hostname (if available)
    if hostname and hostname != "unknown" and hostname != "-":
        hostname_lower = hostname.lower()
        hostname_patterns = {
            # Platforms & Services
            r"steam": "Valve", r"airtunes": "Apple", r"x029": "ONN",
            r"cisco": "Cisco", r"juniper": "Juniper", r"arista": "Arista",
            # Networking
            r"netgear": "Netgear", r"tp-link|tplink": "TP-Link", r"linksys": "Linksys",
            r"ubiquiti": "Ubiquiti", r"mikrotik": "Mikrotik", r"fortinet": "Fortinet",
            r"paloalto|palo": "Palo Alto Networks", r"checkpoint": "CheckPoint",
            # Cloud & CDN
            r"akamai": "Akamai", r"cloudflare": "Cloudflare", r"fastly": "Fastly",
            r"amazon": "Amazon AWS", r"google": "Google Cloud", r"microsoft|azure": "Microsoft",
            # Devices
            r"apple|iphone|ipad|macbook": "Apple", r"samsung": "Samsung",
            r"lg|lge": "LG Electronics", r"xerox": "Xerox", r"hp|hewlett": "HP",
            r"dell": "Dell", r"lenovo": "Lenovo", r"asus": "ASUS",
            r"netease": "Netease", r"baidu": "Baidu", r"alibaba": "Alibaba",
            r"tencent": "Tencent", r"dji": "DJI", r"tesla": "Tesla",
            r"raspberrypi|rpi": "Raspberry Pi", r"nvidia": "NVIDIA",
            r"android": "Android Device",
        }
        for pattern, vendor in hostname_patterns.items():
            if re.search(pattern, hostname_lower):
                return vendor
    
    return None

def parse_etc_hosts() -> Dict[str, str]:
    hosts_map = {}
    try:
        with open('/etc/hosts', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split()
                if len(parts) >= 2: hosts_map[parts[0]] = parts[1]
    except: pass
    return hosts_map

def parse_dhcp_leases() -> Dict[str, str]:
    lease_map = {}
    lease_paths = ['/var/lib/misc/dnsmasq.leases', '/var/lib/dhcp/dhcpd.leases', '/var/lib/dhcpd/dhcpd.leases']
    for path in lease_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[0].isdigit():
                            ip, hostname = parts[2], parts[3]
                            if hostname != '*': lease_map[ip] = hostname
            except: continue
    return lease_map

def try_mdns_resolve(ip: str) -> Optional[str]:
    if shutil.which("avahi-resolve"):
        try:
            result = subprocess.run(["avahi-resolve", "-a", ip], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1]
                    if hostname.endswith('.local'): hostname = hostname[:-6]
                    return hostname
        except: pass
    return None

def try_netbios_resolve(ip: str) -> Optional[str]:
    if not shutil.which("nmblookup"): return None
    try:
        result = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if '<00>' in line and 'ACTIVE' in line:
                    parts = line.split()
                    if parts:
                        hostname = parts[0].strip()
                        if hostname and hostname != ip: return hostname
    except: pass
    return None

def reverse_dns(ip: str) -> Optional[str]:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except: return None

def resolve_hostname_comprehensive(ip: str, mac: Optional[str] = None, nmap_hostname: Optional[str] = None) -> str:
    if nmap_hostname and nmap_hostname not in (None, "", "-", "unknown"): return nmap_hostname
    hosts_map = parse_etc_hosts()
    if ip in hosts_map: return hosts_map[ip]
    lease_map = parse_dhcp_leases()
    if ip in lease_map: return lease_map[ip]
    mdns_name = try_mdns_resolve(ip)
    if mdns_name: return mdns_name
    netbios_name = try_netbios_resolve(ip)
    if netbios_name: return netbios_name
    dns_name = reverse_dns(ip)
    if dns_name: return dns_name
    if mac:
        mac_clean = mac.replace(':', '').replace('-', '').upper()
        mac_suffix = mac_clean[-6:]
        return f"device-{mac_suffix}"
    last_octet = ip.split('.')[-1]
    return f"unknown-{last_octet}"

def run_nmap_discovery(cidr: str) -> str:
    # Detect if IPv6 CIDR
    is_ipv6 = ':' in cidr
    
    if is_ipv6:
        # For IPv6, we need a smarter approach due to huge address space
        # Use ICMPv6 echo with reasonable timeouts
        # Note: IPv6 discovery is best effort due to address space size
        cmd = ["nmap", "-6", "-sn", "-PE", "-PP", 
               "--max-retries", "1",
               "--host-timeout", "10s",
               "--min-rate", "1000",
               "-oG", "-", cidr]
    else:
        cmd = ["nmap", "-sn", "-oG", "-", cidr]
    
    # Add overall timeout to prevent infinite hangs
    timeout = 180 if is_ipv6 else 120  # 3 minutes for IPv6, 2 minutes for IPv4
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout
    except subprocess.TimeoutExpired:
        # Return empty result if discovery times out
        return ""
    except Exception:
        return ""

def parse_nmap_grepable(nmap_out: str, cidr: str) -> List[Dict[str,Any]]:
    devices = []
    is_ipv6 = ':' in cidr
    
    for line in nmap_out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("Host:"):
            # Try to match IPv4 or IPv6
            if is_ipv6:
                # IPv6 pattern - matches addresses like fe80::1, 2001:db8::1, etc.
                m = re.match(r"Host:\s+([0-9a-fA-F:]+)\s+\(([^)]*)\)\s+Status:\s+(\S+)", line)
                if m:
                    ip, hostname = m.group(1), m.group(2) or None
                    mac = vendor = None
                    mac_m = re.search(r"MAC Address:\s*([0-9A-Fa-f:]+)\s*\((.*?)\)", line)
                    if mac_m: mac, vendor = mac_m.group(1), mac_m.group(2)
                    devices.append({"ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor, "cidr": cidr})
                else:
                    # Try without hostname
                    m2 = re.match(r"Host:\s+([0-9a-fA-F:]+)", line)
                    if m2: devices.append({"ip": m2.group(1), "hostname": None, "mac": None, "vendor": None, "cidr": cidr})
            else:
                # IPv4 pattern
                m = re.match(r"Host:\s+(\d+\.\d+\.\d+\.\d+)\s+\(([^)]*)\)\s+Status:\s+(\S+)", line)
                if m:
                    ip, hostname = m.group(1), m.group(2) or None
                    mac = vendor = None
                    mac_m = re.search(r"MAC Address:\s*([0-9A-Fa-f:]+)\s*\((.*?)\)", line)
                    if mac_m: mac, vendor = mac_m.group(1), mac_m.group(2)
                    devices.append({"ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor, "cidr": cidr})
                else:
                    m2 = re.match(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if m2: devices.append({"ip": m2.group(1), "hostname": None, "mac": None, "vendor": None, "cidr": cidr})
    seen = set()
    uniq = []
    for d in devices:
        if d["ip"] not in seen:
            seen.add(d["ip"])
            uniq.append(d)
    return uniq

def augment_from_arp(devices: List[Dict[str,Any]]) -> List[Dict[str,Any]]:
    """Augment devices from ARP cache (IPv4) and NDP cache (IPv6)"""
    # Get IPv4 ARP cache
    try:
        out = subprocess.check_output(["ip", "neigh", "show"], text=True)
    except: 
        out = ""
    
    # Get IPv6 NDP cache
    try:
        out_v6 = subprocess.check_output(["ip", "-6", "neigh", "show"], text=True)
        out += "\n" + out_v6
    except:
        pass
    
    if not out:
        return devices
        
    arp = {}
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) >= 5 and "lladdr" in parts:
            try:
                ip = parts[0]
                idx = parts.index("lladdr")
                mac = parts[idx+1]
                arp[ip] = mac
            except: continue
    for d in devices:
        if not d.get("mac") and d["ip"] in arp: d["mac"] = arp[d["ip"]]
    return devices

def discover_cidr(cidr: str) -> List[Dict[str,Any]]:
    nmap_out = run_nmap_discovery(cidr)
    devices = parse_nmap_grepable(nmap_out, cidr)
    devices = augment_from_arp(devices)
    return devices

def discover_multiple_cidrs(cidrs: List[str], concurrency: int = CIDR_DISCOVERY_CONCURRENCY, json_only: bool = False) -> Tuple[List[Dict[str,Any]], Dict[str, List[Dict[str,Any]]]]:
    all_devices = []
    cidr_devices_map = {cidr: [] for cidr in cidrs}
    if USE_RICH and not json_only:
        with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task(f"Discovery: scanning {len(cidrs)} network(s)", total=len(cidrs))
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                futures = {ex.submit(discover_cidr, cidr): cidr for cidr in cidrs}
                for fut in as_completed(futures):
                    cidr = futures[fut]
                    try:
                        devices = fut.result()
                        cidr_devices_map[cidr] = devices
                        all_devices.extend(devices)
                    except Exception as e:
                        if USE_RICH: console.print(f"[yellow]Warning: Failed to scan {cidr}: {e}[/yellow]")
                    progress.update(task, advance=1)
    elif not json_only:
        print(f"\nDiscovery: scanning {len(cidrs)} network(s)...")
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(discover_cidr, cidr): cidr for cidr in cidrs}
            for fut in as_completed(futures):
                cidr = futures[fut]
                try:
                    devices = fut.result()
                    cidr_devices_map[cidr] = devices
                    all_devices.extend(devices)
                    print(f"  ✓ {cidr}: {len(devices)} host(s)")
                except Exception as e:
                    print(f"  ✗ {cidr}: failed ({e})")
    else:
        # Silent mode for json_only
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(discover_cidr, cidr): cidr for cidr in cidrs}
            for fut in as_completed(futures):
                cidr = futures[fut]
                try:
                    devices = fut.result()
                    cidr_devices_map[cidr] = devices
                    all_devices.extend(devices)
                except:
                    pass  # Silent failure in json_only mode
    return all_devices, cidr_devices_map

def run_nmap_probe(ip: str, top_ports: int, timeout: int, profile: str = "balanced", timing: str = "normal") -> Dict[str,Any]:
    """Run nmap probe with configurable profile and timing.
    
    Args:
        ip: Target IP address (IPv4 or IPv6)
        top_ports: Number of top ports to scan
        timeout: Timeout in seconds
        profile: Scan profile (quiet/balanced/aggressive)
        timing: Timing template (paranoid/sneaky/polite/normal/aggressive/insane)
    """
    # Get profile config
    profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES["balanced"])
    timing_val = TIMING_PROFILES.get(timing, TIMING_PROFILES["normal"])["value"]
    
    # Detect if IPv6
    is_ipv6 = ':' in ip
    
    # Build command based on profile
    cmd = ["nmap"]
    
    # Add IPv6 flag if needed
    if is_ipv6:
        cmd.append("-6")
    
    # Add timing flag
    cmd.append(f"-{timing_val}")
    
    # Add scan type based on profile
    probe_method = profile_cfg["probe_method"]
    cmd.append(probe_method)
    
    # Add service detection
    cmd.extend(["-sV", f"--top-ports", str(top_ports)])
    
    # Add OS detection if aggressive profile (note: may not work well with IPv6)
    if profile_cfg["os_detection"] and not is_ipv6:
        cmd.append("-O")
    
    # Add NSE scripts if aggressive profile
    if profile_cfg["scripts"]:
        cmd.append("-sC")
    
    # Other standard flags
    cmd.extend(["-Pn", "-oX", "-", ip])
    
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        xml = p.stdout
    except (subprocess.TimeoutExpired, Exception): 
        xml = ""
    
    info = {"ip": ip, "hostname": None, "ports": [], "os": None, "nmap_xml": xml}
    if not xml: return info
    try:
        root = ET.fromstring(xml)
        host = root.find("host")
        if host is None: return info
        hn = host.find("hostnames/hostname")
        if hn is not None and "name" in hn.attrib: info["hostname"] = hn.attrib.get("name")
        for port in host.findall(".//port"):
            portid, proto = port.get("portid"), port.get("protocol")
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else None
            svc = port.find("service")
            svcname = svc.get("name") if svc is not None and "name" in svc.attrib else None
            version = None
            if svc is not None:
                parts = []
                for k in ("product", "version", "extrainfo"):
                    if k in svc.attrib and svc.attrib[k]: parts.append(svc.attrib[k])
                if parts: version = " ".join(parts)
            try: pnum = int(portid)
            except: pnum = portid
            info["ports"].append({"port": pnum, "proto": proto, "state": state, "service": svcname, "version": version})
        osmatch = host.find("os/osmatch")
        if osmatch is not None and "name" in osmatch.attrib: info["os"] = osmatch.attrib.get("name")
    except: pass
    return info

def get_local_machine_info() -> Dict[str, str]:
    """Get MAC address and device info from local machine using fastfetch or system tools."""
    info = {
        "mac": None,
        "vendor": None,
        "device_type": "workstation",
        "hostname": socket.gethostname(),
    }
    
    # Try fastfetch first (if available)
    if shutil.which("fastfetch"):
        try:
            result = subprocess.run(["fastfetch", "--json"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    
                    # Extract device info from fastfetch
                    if "Chassis" in data:
                        chassis = data.get("Chassis", "").lower()
                        if "laptop" in chassis:
                            info["device_type"] = "laptop"
                        elif "desktop" in chassis:
                            info["device_type"] = "workstation"
                        elif "server" in chassis:
                            info["device_type"] = "server"
                    
                    # Try to get system info for vendor
                    if "System" in data:
                        system = data.get("System", "").lower()
                        if "apple" in system or "macbook" in system:
                            info["vendor"] = "Apple"
                            info["device_type"] = "workstation"
                        elif "dell" in system:
                            info["vendor"] = "Dell"
                        elif "hp" in system or "hewlett" in system:
                            info["vendor"] = "HP"
                        elif "lenovo" in system:
                            info["vendor"] = "Lenovo"
                        elif "asus" in system:
                            info["vendor"] = "ASUS"
                    
                    if "OS" in data:
                        os_info = data.get("OS", "").lower()
                        if "ubuntu" in os_info or "debian" in os_info or "linux" in os_info:
                            if not info["vendor"]:
                                info["vendor"] = "Linux Workstation"
                        elif "macos" in os_info or "darwin" in os_info:
                            info["vendor"] = "Apple"
                except: pass
        except: pass
    
    # Try to get MAC address from system
    try:
        # Get the default interface's MAC
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Parse ip link output for MAC
            for line in result.stdout.split('\n'):
                if 'link/ether' in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1]
                        if re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac.lower()):
                            info["mac"] = mac
                            break
    except: pass
    
    # If MAC still not found, try ifconfig
    if not info["mac"]:
        try:
            result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Look for HWaddr or lladdr patterns
                match = re.search(r'(?:HWaddr|lladdr)\s+([0-9a-f:]+)', result.stdout.lower())
                if match:
                    mac = match.group(1)
                    if re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
                        info["mac"] = mac
        except: pass
    
    # Try to get vendor info from MAC if we got it
    if info["mac"] and not info["vendor"]:
        info["vendor"] = get_mac_vendor_enhanced(info["mac"], info["hostname"], {})
    
    # Fallback vendor naming
    if not info["vendor"]:
        if "omarchypc" in info["hostname"].lower():
            info["vendor"] = "Personal Workstation (omarchypc_Desktop)"
        else:
            info["vendor"] = "Local Machine"
    
    return info
    """Try to infer vendor from multiple contextual clues when direct lookup fails."""
    vendor_hints = {}
    
    if not mac and not hostname and not ip:
        return vendor_hints
    
    # Clue 1: MAC address patterns
    if mac:
        mac_upper = mac.upper()
        # Locally administered MAC addresses (bit 1 of first octet = 1)
        if mac_upper[1] in '13579BDF':  # Odd first digit = locally administered
            vendor_hints["locally_admin"] = 0.3
    
    # Clue 2: Hostname patterns
    if hostname and hostname != "unknown" and hostname != "-":
        hostname_lower = hostname.lower()
        
        # Pattern: device-HEXCODE (common for phones/tablets)
        if re.match(r"^device-[0-9a-f]{6}$", hostname_lower):
            vendor_hints["hexcode_device"] = 0.6
            
            # Specific MAC patterns in hex names
            if "ec33" in hostname_lower:  # device-EC3389 pattern
                vendor_hints["likely_mobile"] = 0.7
            elif "ad08" in hostname_lower:  # device-AD08FE pattern
                vendor_hints["likely_mobile"] = 0.7
        
        # Pattern: hostname.local (mDNS)
        if hostname_lower.endswith(".local"):
            vendor_hints["mdns_device"] = 0.5
    
    # Clue 3: Service analysis
    if services:
        open_ports = [s.get("port") for s in services if s.get("state") == "open"]
        
        if not open_ports:
            vendor_hints["no_open_services"] = 0.6  # Personal device, likely phone/tablet
        else:
            # Check service patterns
            for service in services:
                port = service.get("port")
                name = service.get("name", "").lower()
                
                if port == 5353 or "mdns" in name:
                    vendor_hints["mdns_service"] = 0.5
    
    return vendor_hints


def extract_vendor_from_hostname_clues(hostname: Optional[str]) -> Optional[str]:
    """Try to extract vendor from hostname patterns."""
    if not hostname:
        return None
    
    hostname_lower = hostname.lower()
    
    # Model-based patterns
    patterns = {
        r"iphone|ipad|macbook": "Apple",
        r"galaxy|sm-": "Samsung",
        r"pixel|nexus": "Google",
        r"oneplus": "OnePlus",
        r"moto": "Motorola",
    }
    
    for pattern, vendor in patterns.items():
        if re.search(pattern, hostname_lower):
            return vendor
    
    return None


def get_mac_vendor_aggressive(mac: Optional[str], hostname: Optional[str] = None) -> Optional[str]:
    """Last-resort vendor lookup - try very hard to find SOMETHING."""
    if not mac:
        return None
    
    # KNOWN DEVICES - Add your personal/admin machines here for quick lookup
    # Format: "hostname.lower()": "Vendor/Description"
    known_devices = {
        "omarchypc.local": "Personal Desktop (omarchypc)",
        "constantine-mac": "Personal Mac",
        # Add more as needed!
    }
    
    if hostname:
        hostname_lower = hostname.lower()
        if hostname_lower in known_devices:
            return known_devices[hostname_lower]
    
    # CRITICAL: Check hostname FIRST for device type detection
    # This is the most reliable signal for Android/iOS/privacy-mode devices
    if hostname:
        hostname_lower = hostname.lower()
        
        # Android hostname pattern
        if hostname_lower.startswith("android"):
            return "Android Device"
        
        # iPhone/iPad
        if re.search(r"iphone|ipad", hostname_lower):
            return "Apple"
        
        # Android patterns (manufacturer names)
        if re.search(r"samsung galaxy|google pixel|oneplus|motorola", hostname_lower):
            return "Android Device"
        
        # The mysterious "device-HEXCODE" pattern usually indicates:
        # - Privacy mode enabled (randomized MAC)
        # - Personal device (phone/tablet)
        # These are TYPICALLY mobile devices trying to hide their identity
        if re.match(r"device-[0-9a-f]{6}", hostname_lower):
            # Return "Android Device" as default for privacy-mode devices
            # since most are Android phones/tablets with randomized MACs
            return "Android Device"
    
    # Check MAC address patterns for locally-administered addresses
    if mac:
        mac_upper = mac.upper()
        # If second character is odd, it's locally administered (often means personal device)
        if mac_upper[1] in '13579BDF':
            # This is a strong indicator of privacy mode or randomized MAC
            # Most commonly seen on Android devices in privacy mode
            if hostname and re.match(r"device-[0-9a-f]{6}", hostname.lower()):
                return "Android Device"
            # Fallback for other locally-administered addresses
            return "Personal Device (Randomized MAC)"
    
    # Last resort: try the normal enhanced lookup (which has all the strategies)
    vendor = get_mac_vendor_enhanced(mac, hostname, {})
    if vendor:
        return vendor
    
    return None
    """Enhanced device type inference that handles unknown vendors better."""
    
    hostname = (info.get("hostname") or "").lower()
    ports = info.get("ports", [])
    vendor_lower = (vendor or "").lower()
    
    # First try the standard inference
    standard_type = infer_devtype(info, vendor)
    if standard_type != "unknown":
        return standard_type
    
    # If standard inference failed, use contextual clues
    vendor_hints = infer_vendor_from_clues(
        info.get("mac"),
        info.get("hostname"),
        info.get("ip"),
        ports
    )
    
    # Strong mobile device indicators
    if vendor_hints.get("likely_mobile", 0) > 0.6 or vendor_hints.get("hexcode_device", 0) > 0.5:
        return "mobile"
    
    # No open services + locally admin MAC + unclear hostname = likely mobile
    if (vendor_hints.get("no_open_services", 0) > 0.5 and 
        vendor_hints.get("locally_admin", 0) > 0.2):
        return "mobile"
    
    # mDNS registered device with no services = likely media device
    if vendor_hints.get("mdns_device", 0) > 0.4:
        return "media_device"
    
    return "unknown"


def infer_os(info: Dict[str,Any], hostname: str, vendor: str) -> str:
    """
    Detect operating system from hostname, vendor, nmap OS detection, and services.
    Comprehensive detection for common and uncommon network devices.
    """
    hostname_lower = (hostname or "").lower()
    vendor_lower = (vendor or "").lower()
    os_info = (info.get("os") or "").lower()
    
    # ========================================================================
    # MOBILE OS / SMARTPHONES / TABLETS
    # ========================================================================
    if "iphone" in hostname_lower or "ios" in hostname_lower or "apple_phone" in hostname_lower:
        return "iOS"
    if "ipad" in hostname_lower or "apple_tablet" in hostname_lower:
        return "iPadOS"
    if "android" in hostname_lower or "aphone" in hostname_lower:
        return "Android"
    
    # ========================================================================
    # DESKTOP OS / WORKSTATIONS
    # ========================================================================
    # macOS variants
    if "macbook" in hostname_lower or "imac" in hostname_lower or "mac" in hostname_lower or "macmini" in hostname_lower or "macstudio" in hostname_lower or "macpro" in hostname_lower:
        return "macOS"
    
    # Windows variants
    if "windows" in hostname_lower or "win" in hostname_lower or "pc-" in hostname_lower or "desktop" in hostname_lower:
        return "Windows"
    
    # ========================================================================
    # LINUX DISTRIBUTIONS - UBUNTU-BASED
    # ========================================================================
    if "mint" in hostname_lower or "linuxmint" in hostname_lower:
        return "Linux (Mint)"
    if "pop" in hostname_lower or "pop_os" in hostname_lower or "popos" in hostname_lower:
        return "Linux (Pop!_OS)"
    if "zorin" in hostname_lower or "zorinos" in hostname_lower:
        return "Linux (Zorin)"
    if "elementary" in hostname_lower or "elementaryos" in hostname_lower:
        return "Linux (Elementary)"
    if "ubuntu" in hostname_lower or "xubuntu" in hostname_lower or "kubuntu" in hostname_lower or "lubuntu" in hostname_lower or "budgie" in hostname_lower:
        return "Linux (Ubuntu)"
    
    # ========================================================================
    # LINUX DISTRIBUTIONS - DEBIAN-BASED
    # ========================================================================
    if "kali" in hostname_lower or "kalilinux" in hostname_lower:
        return "Linux (Kali)"
    if "parrot" in hostname_lower or "parrotos" in hostname_lower or "parrotsec" in hostname_lower:
        return "Linux (Parrot)"
    if "debian" in hostname_lower or "raspbian" in hostname_lower or "raspberry" in hostname_lower or "rpi" in hostname_lower:
        return "Linux (Debian)"
    if "mx" in hostname_lower or "mxlinux" in hostname_lower:
        return "Linux (MX)"
    if "devuan" in hostname_lower:
        return "Linux (Devuan)"
    
    # ========================================================================
    # LINUX DISTRIBUTIONS - ARCH-BASED
    # ========================================================================
    if "manjaro" in hostname_lower:
        return "Linux (Manjaro)"
    if "arch" in hostname_lower or "omarchy" in hostname_lower or "archlinux" in hostname_lower:
        return "Linux (Arch)"
    if "endeavouros" in hostname_lower or "endeavour" in hostname_lower:
        return "Linux (EndeavourOS)"
    if "garuda" in hostname_lower:
        return "Linux (Garuda)"
    
    # ========================================================================
    # LINUX DISTRIBUTIONS - FEDORA-BASED
    # ========================================================================
    if "fedora" in hostname_lower:
        return "Linux (Fedora)"
    if "nobara" in hostname_lower:
        return "Linux (Nobara)"
    if "ultramarine" in hostname_lower:
        return "Linux (Ultramarine)"
    
    # ========================================================================
    # LINUX DISTRIBUTIONS - RHEL/CENTOS/ROCKY
    # ========================================================================
    if "centos" in hostname_lower or "rhel" in hostname_lower or "rocky" in hostname_lower or "almalinux" in hostname_lower or "alma" in hostname_lower:
        return "Linux (RHEL/CentOS)"
    
    # ========================================================================
    # LINUX DISTRIBUTIONS - OPENINDIANA/SOLARIS-BASED
    # ========================================================================
    if "solaris" in hostname_lower:
        return "Solaris"
    if "openindiana" in hostname_lower or "illumos" in hostname_lower:
        return "OpenIndiana"
    
    # ========================================================================
    # LINUX DISTRIBUTIONS - OTHER NOTABLE
    # ========================================================================
    if "opensuse" in hostname_lower or "suse" in hostname_lower or "leap" in hostname_lower or "tumbleweed" in hostname_lower:
        return "Linux (openSUSE)"
    if "solus" in hostname_lower:
        return "Linux (Solus)"
    if "void" in hostname_lower or "voidlinux" in hostname_lower:
        return "Linux (Void)"
    if "nixos" in hostname_lower or "nix" in hostname_lower:
        return "Linux (NixOS)"
    if "gentoo" in hostname_lower or "calculate" in hostname_lower:
        return "Linux (Gentoo)"
    if "alpine" in hostname_lower or "alpinelinux" in hostname_lower:
        return "Linux (Alpine)"
    if "slackware" in hostname_lower or "slack" in hostname_lower or "slackel" in hostname_lower:
        return "Linux (Slackware)"
    if "pclinuxos" in hostname_lower or "pclos" in hostname_lower:
        return "Linux (PCLinuxOS)"
    if "mageia" in hostname_lower:
        return "Linux (Mageia)"
    if "openmandriva" in hostname_lower or "mandriva" in hostname_lower:
        return "Linux (Mandriva)"
    if "antix" in hostname_lower or "mepis" in hostname_lower:
        return "Linux (antiX/MEPIS)"
    if "puppylinux" in hostname_lower or "puppy" in hostname_lower:
        return "Linux (Puppy)"
    if "tinycore" in hostname_lower or "tinylinux" in hostname_lower:
        return "Linux (Tiny Core)"
    if "gparted" in hostname_lower or "gpartedlive" in hostname_lower:
        return "Linux (GParted Live)"
    if "knoppix" in hostname_lower:
        return "Linux (Knoppix)"
    if "dban" in hostname_lower or "darik" in hostname_lower:
        return "Linux (DBAN)"
    if "clonezilla" in hostname_lower:
        return "Linux (Clonezilla)"
    if "raspios" in hostname_lower or "raspberrypi_os" in hostname_lower:
        return "Linux (Raspberry Pi OS)"
    
    # ========================================================================
    # GAMING & ENTERTAINMENT OS
    # ========================================================================
    # Nintendo
    if "switch" in hostname_lower or "nintendo" in hostname_lower or "switchxyz" in hostname_lower:
        return "Nintendo Switch OS"
    if "wii" in hostname_lower or "wiiu" in hostname_lower:
        return "Nintendo Wii U OS"
    if "3ds" in hostname_lower or "3dsxl" in hostname_lower:
        return "Nintendo 3DS OS"
    
    # PlayStation
    if "playstation" in hostname_lower or "ps5" in hostname_lower or "ps4" in hostname_lower or "ps3" in hostname_lower:
        return "PlayStation OS"
    if "vita" in hostname_lower or "psvita" in hostname_lower:
        return "PlayStation Vita OS"
    
    # Xbox
    if "xbox" in hostname_lower or "xbox_" in hostname_lower or "xbone" in hostname_lower:
        return "Xbox OS"
    
    # Valve/Steam
    if "steamdeck" in hostname_lower or "steam-deck" in hostname_lower or "steamos" in hostname_lower or "valve" in hostname_lower:
        return "SteamOS"
    
    # Other Gaming
    if "atari" in hostname_lower:
        return "Atari OS"
    if "sega" in hostname_lower or "dreamcast" in hostname_lower:
        return "Sega OS"
    if "retropie" in hostname_lower or "recalbox" in hostname_lower or "batocera" in hostname_lower or "lakka" in hostname_lower:
        return "Retro Gaming OS"
    
    # Media Centers / Set-top boxes
    if "kodi" in hostname_lower:
        return "Kodi"
    if "libreelec" in hostname_lower or "openelec" in hostname_lower:
        return "LibreELEC"
    if "roku" in hostname_lower or "rokuos" in hostname_lower:
        return "Roku OS"
    if "appletv" in hostname_lower or "apple_tv" in hostname_lower:
        return "tvOS"
    if "chromecast" in hostname_lower or "googletv" in hostname_lower:
        return "Google TV / Chromecast OS"
    if "firestick" in hostname_lower or "fireTV" in hostname_lower or "amazon_tv" in hostname_lower:
        return "Fire OS (Amazon)"
    if "onn" in hostname_lower or "walmart" in hostname_lower:
        return "Walmart Onn OS"
    if "vizio" in hostname_lower:
        return "SmartCast (Vizio)"
    if "lg_tv" in hostname_lower or "lgtv" in hostname_lower or "lg-webos" in hostname_lower:
        return "webOS (LG)"
    if "samsung_tv" in hostname_lower or "samsungtv" in hostname_lower or "tizen" in hostname_lower:
        return "Tizen (Samsung)"
    if "sony_tv" in hostname_lower or "sonybravia" in hostname_lower or "bravia" in hostname_lower:
        return "Android TV (Sony Bravia)"
    if "tcl_tv" in hostname_lower or "tclroku" in hostname_lower:
        return "TCL Roku OS"
    if "hisense" in hostname_lower:
        return "Hisense Android TV"
    if "philips_tv" in hostname_lower or "philips" in hostname_lower or "ambilight" in hostname_lower:
        return "Android TV (Philips)"
    if "panasonic" in hostname_lower or "viera" in hostname_lower:
        return "My Home Screen (Panasonic)"
    
    # ========================================================================
    # STORAGE / NAS / MEDIA SYSTEMS
    # ========================================================================
    if "synology" in hostname_lower or "dsm" in hostname_lower or "diskstation" in hostname_lower:
        return "Synology DSM"
    if "qnap" in hostname_lower or "qts" in hostname_lower or "qnap_qts" in hostname_lower:
        return "QNAP QTS"
    if "truenas" in hostname_lower or "freenas" in hostname_lower or "truepool" in hostname_lower:
        return "TrueNAS"
    if "unraid" in hostname_lower or "unraid-server" in hostname_lower:
        return "Unraid"
    if "openmediavault" in hostname_lower or "omv" in hostname_lower:
        return "OpenMediaVault"
    if "nextcloud" in hostname_lower:
        return "Nextcloud"
    if "owncloud" in hostname_lower:
        return "Owncloud"
    if "plex" in hostname_lower or "plexmediaserver" in hostname_lower:
        return "Plex Media Server"
    if "jellyfin" in hostname_lower:
        return "Jellyfin"
    if "emby" in hostname_lower:
        return "Emby"
    
    # ========================================================================
    # NETWORKING / ROUTING / FIREWALL
    # ========================================================================
    if "pfsense" in hostname_lower or "pf-sense" in hostname_lower:
        return "pfSense"
    if "opnsense" in hostname_lower or "opn-sense" in hostname_lower:
        return "OPNsense"
    if "vyos" in hostname_lower or "edgeos" in hostname_lower or "vyatta" in hostname_lower:
        return "VyOS"
    if "mikrotik" in hostname_lower or "routeros" in hostname_lower or "winbox" in hostname_lower:
        return "Mikrotik RouterOS"
    if "ubiquiti" in hostname_lower or "edgemax" in hostname_lower or "edgerouter" in hostname_lower:
        return "Ubiquiti EdgeOS"
    if "cumulus" in hostname_lower:
        return "Cumulus Linux"
    if "nighthawk" in hostname_lower or "netgear" in hostname_lower or "r7000" in hostname_lower or "r9000" in hostname_lower or "r8000" in hostname_lower:
        return "Netgear Firmware (Linux)"
    if "asus_router" in hostname_lower or "asuswrt" in hostname_lower:
        return "ASUS AiMesh / AsuswRT"
    if "linksys" in hostname_lower or "velop" in hostname_lower:
        return "Linksys Firmware"
    if "tp-link" in hostname_lower or "tplink" in hostname_lower or "omada" in hostname_lower:
        return "TP-Link Firmware"
    if "d-link" in hostname_lower or "dlink" in hostname_lower:
        return "D-Link Firmware"
    if "belkin" in hostname_lower or "eero" in hostname_lower:
        return "Belkin/Eero OS"
    if "cisco" in hostname_lower or "ios_xe" in hostname_lower or "ios_xr" in hostname_lower:
        return "Cisco IOS"
    if "juniper" in hostname_lower or "junos" in hostname_lower:
        return "Juniper JunOS"
    if "arista" in hostname_lower:
        return "Arista EOS"
    if "openwrt" in hostname_lower or "dd-wrt" in hostname_lower or "tomato" in hostname_lower or "openwrt-" in hostname_lower:
        return "Linux (OpenWrt / DD-WRT)"
    if "meraki" in hostname_lower:
        return "Meraki Dashboard OS"
    if "fortigate" in hostname_lower or "fortios" in hostname_lower:
        return "FortiOS (Fortinet)"
    if "checkpoint" in hostname_lower or "gaia" in hostname_lower:
        return "Gaia OS (Check Point)"
    if "paloalto" in hostname_lower or "panorama" in hostname_lower:
        return "PAN-OS (Palo Alto)"
    
    # ========================================================================
    # VIRTUALIZATION / HYPERVISORS / CONTAINER
    # ========================================================================
    if "proxmox" in hostname_lower or "pve" in hostname_lower:
        return "Proxmox VE"
    if "esxi" in hostname_lower or "vmware" in hostname_lower or "vsphere" in hostname_lower:
        return "VMware ESXi"
    if "hyperv" in hostname_lower or "hyper-v" in hostname_lower:
        return "Hyper-V"
    if "kvm" in hostname_lower or "libvirt" in hostname_lower:
        return "KVM/Libvirt"
    if "xen" in hostname_lower:
        return "Xen Hypervisor"
    if "openstack" in hostname_lower:
        return "OpenStack"
    
    # Container Orchestration
    if "kubernetes" in hostname_lower or "k8s" in hostname_lower or "k3s" in hostname_lower or "rancher" in hostname_lower:
        return "Kubernetes"
    if "docker" in hostname_lower or "docker-" in hostname_lower:
        return "Docker"
    if "containerd" in hostname_lower or "podman" in hostname_lower:
        return "Containerd/Podman"
    if "nomad" in hostname_lower:
        return "HashiCorp Nomad"
    
    # ========================================================================
    # BSD VARIANTS
    # ========================================================================
    if "freebsd" in hostname_lower or "freebsd-" in hostname_lower:
        return "FreeBSD"
    if "openbsd" in hostname_lower or "openbsd-" in hostname_lower:
        return "OpenBSD"
    if "netbsd" in hostname_lower or "netbsd-" in hostname_lower:
        return "NetBSD"
    if "dragonfly" in hostname_lower or "dflybsd" in hostname_lower:
        return "DragonFly BSD"
    
    # ========================================================================
    # EMBEDDED / IoT / SINGLE-BOARD COMPUTERS
    # ========================================================================
    if "armbian" in hostname_lower:
        return "Armbian"
    if "dietpi" in hostname_lower:
        return "DietPi"
    if "osmc" in hostname_lower:
        return "OSMC"
    if "balena" in hostname_lower or "balenaos" in hostname_lower:
        return "balenaOS"
    if "tinycorelinux" in hostname_lower or "tinycoreos" in hostname_lower:
        return "Tiny Core Linux"
    if "openwrt" in hostname_lower or "lede" in hostname_lower:
        return "OpenWrt / LEDE"
    if "tasmota" in hostname_lower or "esphome" in hostname_lower:
        return "Tasmota / ESPHome"
    if "micropython" in hostname_lower:
        return "MicroPython"
    if "circuitpython" in hostname_lower:
        return "CircuitPython"
    if "rtos" in hostname_lower or "freertos" in hostname_lower or "rtlinux" in hostname_lower:
        return "RTOS"
    if "threadx" in hostname_lower or "embos" in hostname_lower or "vxworks" in hostname_lower:
        return "RTOS (Commercial)"
    if "tinyos" in hostname_lower:
        return "TinyOS"
    if "contiki" in hostname_lower:
        return "Contiki OS"
    if "zephyr" in hostname_lower:
        return "Zephyr OS"
    
    # ========================================================================
    # SPECIALIZED SYSTEMS / APPLIANCES
    # ========================================================================
    if "proxmox" in hostname_lower:
        return "Proxmox VE"
    if "esxi" in hostname_lower:
        return "VMware ESXi"
    if "vcenter" in hostname_lower:
        return "VMware vCenter"
    if "netapp" in hostname_lower or "ontap" in hostname_lower:
        return "NetApp ONTAP"
    if "emc" in hostname_lower or "isilon" in hostname_lower or "powerstore" in hostname_lower:
        return "EMC Storage OS"
    if "hitachi" in hostname_lower or "hus" in hostname_lower:
        return "Hitachi Storage OS"
    if "pure" in hostname_lower or "flasharray" in hostname_lower:
        return "Pure Storage FlashArray"
    if "dell" in hostname_lower or "vmax" in hostname_lower:
        return "Dell EMC Vmax"
    
    # ========================================================================
    # SPECIALIZED LINUX (CATCH-ALL AT LOWER PRIORITY)
    # ========================================================================
    if "linux" in hostname_lower:
        return "Linux"
    
    # ========================================================================
    # VENDOR-BASED OS INFERENCE (higher priority now with more vendors)
    # ========================================================================
    if "apple" in vendor_lower:
        return "Apple (iOS/macOS)"
    
    # Android vendors
    if any(v in vendor_lower for v in ["samsung", "google", "motorola", "oneplus", "xiaomi", "htc", "nokia", "sony", "lg", "huawei", "oppo", "vivo", "realme", "nothing"]):
        return "Android"
    
    if "valve" in vendor_lower:
        return "SteamOS"
    
    if "synology" in vendor_lower:
        return "Synology DSM"
    
    if "qnap" in vendor_lower:
        return "QNAP QTS"
    
    if "roku" in vendor_lower or "onn" in vendor_lower:
        return "Roku OS"
    
    if "netgear" in vendor_lower:
        return "Netgear Firmware (Linux)"
    
    if "asus" in vendor_lower:
        return "ASUS (AiMesh/AsuswRT)"
    
    if "linksys" in vendor_lower:
        return "Linksys Firmware"
    
    if "tp-link" in vendor_lower:
        return "TP-Link Firmware"
    
    if "nintendo" in vendor_lower:
        return "Nintendo Switch OS"
    
    if "microsoft" in vendor_lower:
        return "Windows/Xbox OS"
    
    if "sony" in vendor_lower:
        return "PlayStation/Android TV OS"
    
    if "cisco" in vendor_lower:
        return "Cisco IOS"
    
    if "juniper" in vendor_lower:
        return "Juniper JunOS"
    
    if "paloalto" in vendor_lower or "fortinet" in vendor_lower:
        return "Enterprise Firewall OS"
    
    # ========================================================================
    # NMAP OS DETECTION (most reliable when available)
    # ========================================================================
    if os_info:
        if "android" in os_info:
            return "Android"
        if "iphone" in os_info or "ipad" in os_info or "ios" in os_info:
            return "iOS/iPadOS"
        if "mac os" in os_info or "osx" in os_info or "darwin" in os_info:
            return "macOS"
        if "windows" in os_info:
            return "Windows"
        if "ubuntu" in os_info:
            return "Linux (Ubuntu)"
        if "debian" in os_info:
            return "Linux (Debian)"
        if "mint" in os_info:
            return "Linux (Mint)"
        if "fedora" in os_info:
            return "Linux (Fedora)"
        if "arch" in os_info:
            return "Linux (Arch)"
        if "centos" in os_info or "rhel" in os_info or "rocky" in os_info:
            return "Linux (RHEL/CentOS)"
        if "steamos" in os_info:
            return "SteamOS"
        if "alpine" in os_info:
            return "Linux (Alpine)"
        if "opensuse" in os_info or "suse" in os_info:
            return "Linux (openSUSE)"
        if "freebsd" in os_info:
            return "FreeBSD"
        if "openbsd" in os_info:
            return "OpenBSD"
        if "netbsd" in os_info:
            return "NetBSD"
        if "roku" in os_info:
            return "Roku OS"
        if "netgear" in os_info or "nighthawk" in os_info:
            return "Netgear Firmware (Linux)"
        if "linux" in os_info:
            return "Linux"
    
    # ========================================================================
    # SERVICE-BASED OS INFERENCE (fallback)
    # ========================================================================
    ports = info.get("ports", [])
    services = [(p.get("service") or "").lower() for p in ports]
    
    if any("smb" in s or "netbios" in s for s in services):
        return "Windows"
    if any("afp" in s or "appletalk" in s or "bonjour" in s for s in services):
        return "macOS/Apple"
    if any("ssh" in s for s in services):
        return "Linux/Unix"
    if any("http" in s or "https" in s for s in services):
        return "Web Server (OS Unknown)"
    
    return "Unknown"


def infer_devtype(info: Dict[str,Any], vendor: str) -> str:
    hostname, vendor_lower = (info.get("hostname") or "").lower(), (vendor or "").lower()
    ports = info.get("ports", [])
    services = [(p.get("service") or "").lower() for p in ports]
    portnums = [p.get("port") for p in ports]
    os_info = (info.get("os") or "").lower()
    
    hostname_patterns = {
        "router": ["gateway", "router", "gw-", "rt-", "edge"],
        "tv": ["tv", "television", "roku", "chromecast", "firestick", "appletv", "onn", "samsung", "lg", "vizio"],
        "camera": ["camera", "cam-", "ipcam", "nvr", "dvr", "webcam"],
        "printer": ["printer", "print"],
        "gaming_console": ["xbox", "playstation", "ps4", "ps5", "nintendo", "steamdeck", "steam"],
        "mobile": ["iphone", "android", "mobile", "phone", "tablet", "ipad"],
        "workstation": ["desktop", "workstation", "ws-", "pc-"],
        "server": ["server", "srv-", "host-"],
    }
    for devtype, patterns in hostname_patterns.items():
        if any(pattern in hostname for pattern in patterns): return devtype
    
    vendor_patterns = {
        "router": ["netgear", "linksys", "asus", "tp-link"],
        "tv": ["roku", "amazon", "onn", "samsung", "lg", "vizio", "toshiba"],  # Removed "sony" to avoid conflict with PlayStation
        "camera": ["hikvision", "dahua", "axis", "wyze", "reolink"],
        "printer": ["hp", "canon", "epson", "brother"],
        "gaming_console": ["nintendo", "playstation", "xbox", "sony"],
    }
    for devtype, patterns in vendor_patterns.items():
        if any(pattern in vendor_lower for pattern in patterns): return devtype
    
    # Improved heuristics: distinguish cameras from TVs by port patterns
    # Cameras: typically ONLY have RTSP, maybe HTTP
    # TVs: have multiple streaming ports, often HTTP/HTTPS for UI
    open_ports = {p.get("port") for p in ports if p.get("state") == "open"}
    rtsp_services = any("rtsp" in s for s in services)
    has_http = any(p in open_ports for p in [80, 8080, 8888])
    has_https = any(p in open_ports for p in [443, 8443])
    has_airplay = any("airplay" in s or "airtunes" in s for s in services)
    port_554 = 554 in open_ports
    
    # If has RTSP but also has web UI ports (HTTP/HTTPS) → likely TV
    if rtsp_services and (has_http or has_https):
        return "tv"
    
    # If has AirTunes/AirPlay → likely TV or media device (not security camera)
    if has_airplay:
        return "tv"
    
    # If ONLY has RTSP on port 554 → likely camera
    if port_554 and rtsp_services and len(open_ports) == 1:
        return "camera"
    
    # Generic RTSP detection (fallback)
    if rtsp_services:
        return "media_device"  # Could be TV, media server, etc.
    
    if 53 in portnums and any(p in [80, 443] for p in portnums): return "router"
    if 22 in portnums and "linux" in os_info: return "server"
    
    # Enhanced unknown handling: try to infer from device-HEXCODE pattern
    if hostname.startswith("device-") and len(hostname) == 13:  # device-XXXXXX pattern
        # These are typically phones/tablets with randomized/privacy-enabled MACs
        hex_part = hostname[7:]  # Extract XXXXXX part
        
        # Check if all chars are hex
        if all(c in "0123456789abcdef" for c in hex_part):
            # Common mobile device hex patterns
            if hex_part.startswith(("ec", "ad", "ca", "8a")):  # Known mobile patterns in your network
                return "mobile"
            else:
                # Unknown but device-HEXCODE usually = mobile device
                return "mobile"
    
    # Check for .local suffix (mDNS registered device with no identified services)
    if hostname.endswith(".local") and not open_ports:
        return "media_device"  # Likely a media/IoT device
    
    return "unknown"

def compute_risk(info: Dict[str,Any], mac: Optional[str]) -> Tuple[int,List[str],List[Tuple[str,int]]]:
    score, flags, breakdown = 0, [], []
    for p in info.get("ports", []):
        portnum, svc = p.get("port"), (p.get("service") or "").lower() if p.get("service") else ""
        if portnum == 23: score += 50; flags.append("telnet-open"); breakdown.append(("telnet open",50))
        if svc == "rtsp": score += 20; flags.append("rtsp"); breakdown.append(("rtsp",20))
        if isinstance(portnum, int) and portnum > 49150: score += 5; flags.append("high-ephemeral"); breakdown.append(("high ephemeral port",5))
    if not mac: score += 30; flags.append("no-mac"); breakdown.append(("no mac",30))
    if score < 0: score = 0
    if score > 100: score = 100
    return score, sorted(set(flags)), breakdown

def check_known_cves(info: Dict[str, Any], cve_checker: CVEChecker) -> List[Dict[str, Any]]:
    """
    Check for known CVEs in detected services using real-time NVD API.
    
    Args:
        info: Host information dictionary
        cve_checker: CVEChecker instance
    
    Returns:
        List of CVE findings
    """
    findings = []
    ports = info.get("ports", [])
    
    for port in ports:
        service_name = (port.get("service") or "").strip()
        version = (port.get("version") or "").strip()
        port_num = port.get("port")
        
        if not service_name or not version:
            continue
        
        # Normalize service names
        service_name = normalize_service_name(service_name)
        
        # Skip version strings that are too generic
        if version.lower() in ["?", "unknown", "-", ""]:
            continue
        
        # Clean version string
        version = clean_version_string(version)
        
        # Query CVE database
        try:
            cves = cve_checker.check_product_version(service_name, version)
            
            if cves:
                findings.append({
                    'service': service_name,
                    'version': version,
                    'port': port_num,
                    'cves': cves
                })
        except Exception as e:
            # Don't let CVE lookup failures break the scan
            pass
    
    return findings

def assess_threats(info: Dict[str,Any]) -> List[Tuple[str, str]]:
    threats = []
    ports = info.get("ports", [])
    services = {(p.get("service") or "").lower(): p for p in ports if p.get("service")}
    portnums = [p.get("port") for p in ports]
    devtype = info.get("devtype", "").lower()
    if 21 in portnums: threats.append(("unencrypted_protocol", "FTP (port 21) - use SFTP instead"))
    if 23 in portnums: threats.append(("unencrypted_protocol", "Telnet (port 23) - critically dangerous"))
    if any(p in portnums for p in [80] if p not in [8080]):
        if "http" in services and devtype not in ["router", "camera", "printer"]:
            threats.append(("unencrypted_web", f"HTTP detected on non-web device ({devtype})"))
    open_ports = {p.get("port") for p in ports if p.get("state") == "open"}
    if all(p in open_ports for p in [22, 445, 139]): threats.append(("suspicious_combo", "SMB + SSH detected - possible compromised workstation"))
    if all(p in open_ports for p in [3389, 22]): threats.append(("suspicious_combo", "RDP + SSH - unusual combination, possible lateral movement"))
    if devtype == "camera" and 80 in open_ports: threats.append(("device_specific", "Camera with unencrypted HTTP - credentials at risk"))
    if devtype == "printer" and any(p in open_ports for p in [23, 21]): threats.append(("device_specific", "Printer with legacy protocols (Telnet/FTP) - privilege escalation risk"))
    if devtype == "router" and not any(p in open_ports for p in [443]): threats.append(("device_specific", "Router without HTTPS management interface detected"))
    if len(open_ports) > 10: threats.append(("high_exposure", f"Unusually high number of open ports ({len(open_ports)}) - possible honeypot or compromised"))
    if "rtsp" in services: threats.append(("unencrypted_protocol", "RTSP streaming detected - credentials may be transmitted in plaintext"))
    if not ports or len(ports) == 0: threats.append(("dark_device", "No services detected - verify device identity"))
    return threats

def format_ports(ports: List[Dict[str,Any]]) -> str:
    if not ports: return "-"
    opens = [p for p in ports if p.get("state") == "open"]
    opens = sorted(opens, key=lambda x: (x.get("port") or 0))[:6]
    parts = []
    for p in opens:
        s = f"{p.get('port')}/{p.get('service') or ''}"
        if p.get("version"): s += f" ({p.get('version')})"
        parts.append(s)
    return ", ".join(parts) if parts else "-"

def show_summary_table(scan_id: str, iface: str, cidrs: List[str], rows: List[Tuple[int,Dict[str,Any]]]):
    cidrs_display = ", ".join(cidrs) if len(cidrs) <= 3 else f"{len(cidrs)} networks"
    if USE_RICH:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=3)
        table.add_column("HOSTNAME", overflow="fold")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="magenta")
        table.add_column("OS", style="yellow")
        table.add_column("DEVTYPE", style="green")
        table.add_column("RISK", justify="center")
        table.add_column("FLAGS", overflow="fold")
        for idx, info in rows:
            risk = info.get("risk", 0)
            risk_text = f"[green]{risk}[/green]" if risk < 40 else (f"[yellow]{risk}[/yellow]" if risk < 60 else f"[red]{risk}[/red]")
            os_val = info.get("os") or "-"
            devtype = info.get("devtype") or "-"
            flags = ",".join(info.get("flags",[])) or "-"
            table.add_row(str(idx), info.get("hostname") or "-", info.get("ip"), info.get("mac") or "-", os_val, devtype, risk_text, flags)
        console.print(Panel(f"[bold]net-inspect v1.0.0[/bold]  Scan ID: [magenta]{scan_id}[/magenta]    iface: [cyan]{iface}[/cyan]    networks: [cyan]{cidrs_display}[/cyan]\nMode: quick (ephemeral)   concurrency: {DEFAULT_CONCURRENCY}", title="SUMMARY"))
        console.print(table)
    else:
        print(f"\nScan ID: {scan_id} | Interface: {iface} | Networks: {cidrs_display}\n")
        print(f"{'#':<4} {'HOSTNAME':<20} {'IP':<15} {'OS':<18} {'DEVTYPE':<15} {'RISK':<6}")
        print("-" * 110)
        for idx, info in rows:
            os_val = (info.get('os') or '-')[:17]
            print(f"{idx:<4} {info.get('hostname', '-'):<20} {info.get('ip'):<15} {os_val:<18} {info.get('devtype', '-'):<15} {info.get('risk', 0):<6}")

def show_cidr_summary(cidr_devices_map: Dict[str, List[Dict[str,Any]]], host_infos: Dict[str, Dict[str,Any]]):
    if USE_RICH:
        console.print("\n[bold]NETWORK SUMMARY (Per-CIDR)[/bold]")
        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("CIDR", style="blue")
        t.add_column("Hosts", justify="center", style="green")
        t.add_column("Risk Status", overflow="fold")
        for cidr in sorted(cidr_devices_map.keys()):
            devices = cidr_devices_map[cidr]
            if not devices:
                t.add_row(cidr, "[yellow]0[/yellow]", "[yellow]No live hosts detected[/yellow]")
            else:
                risks = [host_infos.get(d["ip"], {}).get("risk", 0) for d in devices]
                critical = len([r for r in risks if r >= 60])
                warning = len([r for r in risks if 40 <= r < 60])
                ok = len([r for r in risks if r < 40])
                risk_str = f"[green]{ok}✅[/green]"
                if warning > 0: risk_str += f" [yellow]{warning}⚠[/yellow]"
                if critical > 0: risk_str += f" [red]{critical}🔴[/red]"
                t.add_row(cidr, str(len(devices)), risk_str)
        console.print(t)
    else:
        print("\nNETWORK SUMMARY (Per-CIDR)")
        print(f"{'CIDR':<20} {'Hosts':<10} Risk Status")
        print("-" * 60)
        for cidr in sorted(cidr_devices_map.keys()):
            devices = cidr_devices_map[cidr]
            if not devices:
                print(f"{cidr:<20} {'0':<10} No live hosts detected")
            else:
                risks = [host_infos.get(d["ip"], {}).get("risk", 0) for d in devices]
                critical = len([r for r in risks if r >= 60])
                warning = len([r for r in risks if 40 <= r < 60])
                ok = len([r for r in risks if r < 40])
                print(f"{cidr:<20} {len(devices):<10} {ok}✅ {warning}⚠ {critical}🔴")

def show_network_map(cidr_devices_map: Dict[str, List[Dict[str,Any]]], host_infos: Dict[str, Dict[str,Any]]):
    if USE_RICH:
        console.print("\n[bold]NETWORK TOPOLOGY MAP[/bold]")
        for cidr in sorted(cidr_devices_map.keys()):
            devices = cidr_devices_map[cidr]
            if not devices:
                console.print(f"\n[blue]{cidr}[/blue]")
                console.print("  └─ [yellow](no live hosts)[/yellow]")
            else:
                console.print(f"\n[blue]{cidr}[/blue]")
                for idx, device in enumerate(devices):
                    ip = device["ip"]
                    info = host_infos.get(ip, {})
                    hostname = (info.get("hostname", "unknown") or "unknown")[:25]
                    devtype = (info.get("devtype") or "unknown").upper()[:16]
                    risk = info.get("risk", 0)
                    risk_icon = "🔴" if risk >= 60 else ("🟡" if risk >= 40 else "🟢")
                    is_last = (idx == len(devices) - 1)
                    prefix = "  └─ " if is_last else "  ├─ "
                    console.print(f"{prefix}[{risk_icon}] [{devtype:<16}] {hostname:<25} {ip:<15} (risk: {risk})")
    else:
        print("\nNETWORK TOPOLOGY MAP")
        for cidr in sorted(cidr_devices_map.keys()):
            devices = cidr_devices_map[cidr]
            print(f"\n{cidr}")
            if not devices:
                print("  └─ (no live hosts)")
            else:
                for idx, device in enumerate(devices):
                    ip = device["ip"]
                    info = host_infos.get(ip, {})
                    hostname = (info.get("hostname", "unknown") or "unknown")[:25]
                    devtype = (info.get("devtype") or "unknown").upper()[:16]
                    risk = info.get("risk", 0)
                    is_last = (idx == len(devices) - 1)
                    prefix = "└─ " if is_last else "├─ "
                    print(f"  {prefix}[{devtype:<16}] {hostname:<25} {ip:<15} (risk: {risk})")

def show_threat_assessment(cidr_devices_map: Dict[str, List[Dict[str,Any]]], host_infos: Dict[str, Dict[str,Any]]):
    if USE_RICH:
        console.print("\n[bold]THREAT ASSESSMENT[/bold]")
        all_threats = defaultdict(list)
        for cidr in sorted(cidr_devices_map.keys()):
            devices = cidr_devices_map[cidr]
            for device in devices:
                ip = device["ip"]
                info = host_infos.get(ip, {})
                hostname = info.get("hostname", "unknown")
                threats = assess_threats(info)
                for threat_type, description in threats:
                    all_threats[threat_type].append((ip, hostname, description))
        if not all_threats:
            console.print("[green]✅ No threats detected![/green]")
        else:
            threat_categories = {
                "unencrypted_protocol": ("🔴 UNENCRYPTED PROTOCOLS", "red"),
                "unencrypted_web": ("🟠 UNENCRYPTED WEB", "yellow"),
                "suspicious_combo": ("🟡 SUSPICIOUS PORT COMBINATIONS", "yellow"),
                "device_specific": ("🟡 DEVICE-SPECIFIC RISKS", "yellow"),
                "high_exposure": ("🔴 HIGH EXPOSURE", "red"),
                "dark_device": ("⚠️  DARK DEVICES", "blue"),
            }
            for threat_type in sorted(all_threats.keys()):
                if threat_type in threat_categories:
                    title, color = threat_categories[threat_type]
                    threats_list = all_threats[threat_type]
                    console.print(f"\n[{color}][bold]{title}[/bold][/{color}]")
                    for ip, hostname, description in threats_list:
                        console.print(f"  • {ip:<15} ({hostname:<20}) → {description}")
    else:
        print("\nTHREAT ASSESSMENT")
        all_threats = defaultdict(list)
        for cidr in sorted(cidr_devices_map.keys()):
            devices = cidr_devices_map[cidr]
            for device in devices:
                ip = device["ip"]
                info = host_infos.get(ip, {})
                hostname = info.get("hostname", "unknown")
                threats = assess_threats(info)
                for threat_type, description in threats:
                    all_threats[threat_type].append((ip, hostname, description))
        if not all_threats:
            print("✅ No threats detected!")
        else:
            for threat_type in sorted(all_threats.keys()):
                threats_list = all_threats[threat_type]
                print(f"\n{threat_type.upper()}")
                for ip, hostname, description in threats_list:
                    print(f"  • {ip:<15} ({hostname:<20}) → {description}")

def show_cve_check(host_infos: Dict[str, Dict[str, Any]], cve_checker: CVEChecker):
    """Display CVE findings in a formatted table with real NVD data"""
    
    if USE_RICH:
        console.print("\n[bold]CVE/VERSION CHECK (Real-time NVD Data)[/bold]")
        
        # Collect all findings
        all_findings = []
        for ip, info in sorted(host_infos.items()):
            hostname = info.get("hostname", "unknown")
            findings = check_known_cves(info, cve_checker)
            
            for finding in findings:
                for cve in finding['cves']:
                    all_findings.append({
                        'ip': ip,
                        'hostname': hostname,
                        'service': finding['service'],
                        'version': finding['version'],
                        'port': finding['port'],
                        **cve
                    })
        
        if not all_findings:
            console.print("[green]✅ No known CVEs detected in service versions.[/green]")
            console.print("[dim]Scanned services are either up-to-date or have no published vulnerabilities.[/dim]")
        else:
            # Show summary
            critical = len([f for f in all_findings if f['severity'] == 'CRITICAL'])
            high = len([f for f in all_findings if f['severity'] == 'HIGH'])
            medium = len([f for f in all_findings if f['severity'] == 'MEDIUM'])
            low = len([f for f in all_findings if f['severity'] == 'LOW'])
            exploited = len([f for f in all_findings if f.get('exploited', False)])
            
            console.print(f"\n[red]🚨 Found {len(all_findings)} CVE(s) across {len(set(f['ip'] for f in all_findings))} host(s)[/red]")
            console.print(f"   [red]Critical: {critical}[/red]  [red]High: {high}[/red]  [yellow]Medium: {medium}[/yellow]  [green]Low: {low}[/green]")
            if exploited > 0:
                console.print(f"   [bold red]⚠️  {exploited} CVE(s) are actively exploited (CISA KEV)[/bold red]\n")
            else:
                console.print()
            
            # Create detailed table
            t = Table(show_header=True, header_style="bold red", show_lines=True)
            t.add_column("Host", style="cyan", width=18)
            t.add_column("Service", style="magenta", width=12)
            t.add_column("CVE", style="yellow", width=16)
            t.add_column("CVSS", justify="center", width=5)
            t.add_column("Severity", justify="center", width=10)
            t.add_column("Description", overflow="fold")
            
            # Sort by severity, then CVSS score
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
            all_findings.sort(key=lambda x: (
                severity_order.get(x['severity'], 4),
                -x.get('cvss_score', 0)
            ))
            
            for finding in all_findings:
                # Color code severity
                sev = finding['severity']
                if sev == 'CRITICAL':
                    sev_display = "[bold red]CRITICAL[/bold red]"
                elif sev == 'HIGH':
                    sev_display = "[red]HIGH[/red]"
                elif sev == 'MEDIUM':
                    sev_display = "[yellow]MEDIUM[/yellow]"
                else:
                    sev_display = "[green]LOW[/green]"
                
                # Add KEV indicator
                cve_display = finding['cve_id']
                if finding.get('exploited'):
                    cve_display = f"[bold]{cve_display}[/bold] 🔥"
                
                # Truncate description
                desc = finding.get('description', 'No description available')
                if len(desc) > 80:
                    desc = desc[:77] + "..."
                
                # Format host info
                host_info = f"{finding['ip']}\n{finding['hostname']}\n:{finding['port']}"
                service_info = f"{finding['service']}\n{finding['version']}"
                
                t.add_row(
                    host_info,
                    service_info,
                    cve_display,
                    str(finding.get('cvss_score', 'N/A')),
                    sev_display,
                    desc
                )
            
            console.print(t)
            
            # Show legend
            console.print("\n[dim]Legend:[/dim]")
            console.print("[dim]  🔥 = Actively exploited in the wild (CISA KEV)[/dim]")
            console.print("[dim]  Data source: NIST National Vulnerability Database[/dim]")
    
    else:
        # Plain text output
        print("\nCVE/VERSION CHECK (Real-time NVD Data)")
        
        all_findings = []
        for ip, info in sorted(host_infos.items()):
            findings = check_known_cves(info, cve_checker)
            for finding in findings:
                for cve in finding['cves']:
                    all_findings.append({
                        'ip': ip,
                        'service': finding['service'],
                        'cve_id': cve['cve_id'],
                        'cvss': cve.get('cvss_score', 0),
                        'severity': cve['severity'],
                        'exploited': cve.get('exploited', False)
                    })
        
        if not all_findings:
            print("✅ No known CVEs detected.")
        else:
            print(f"\n🚨 Found {len(all_findings)} CVE(s)")
            print(f"{'IP':<15} {'Service':<15} {'CVE':<18} {'CVSS':<6} {'Severity':<10} {'KEV':<5}")
            print("-" * 80)
            for f in all_findings:
                kev = "🔥" if f['exploited'] else ""
                print(f"{f['ip']:<15} {f['service']:<15} {f['cve_id']:<18} {f['cvss']:<6.1f} {f['severity']:<10} {kev:<5}")
            

def save_baseline(scan_id: str, rows: List[Tuple[int,Dict[str,Any]]], cidrs: List[str]):
    baseline_data = {"scan_id": scan_id, "timestamp": datetime.now().isoformat(), "cidrs": cidrs, "hosts": []}
    for _, info in rows:
        baseline_data["hosts"].append({"ip": info.get("ip"), "hostname": info.get("hostname"), "mac": info.get("mac"), "vendor": info.get("vendor"), "devtype": info.get("devtype"), "open_ports": [p for p in info.get("ports", []) if p.get("state") == "open"]})
    baseline_file = os.path.join(BASELINES, f"baseline_{cidrs[0].replace('/', '_')}.json")
    with open(baseline_file, "w") as f:
        json.dump(baseline_data, f, indent=2)
    if USE_RICH:
        console.print(f"\n[green]✅ Baseline saved:[/green] {baseline_file}")
    else:
        print(f"\n✅ Baseline saved: {baseline_file}")

def compare_baseline(rows: List[Tuple[int,Dict[str,Any]]], cidrs: List[str]):
    baseline_file = os.path.join(BASELINES, f"baseline_{cidrs[0].replace('/', '_')}.json")
    if not os.path.exists(baseline_file):
        if USE_RICH:
            console.print(f"\n[yellow]⚠️  No baseline found:[/yellow] {baseline_file}")
        else:
            print(f"\n⚠️  No baseline found: {baseline_file}")
        return
    with open(baseline_file, "r") as f:
        baseline = json.load(f)
    baseline_ips = {h["ip"] for h in baseline.get("hosts", [])}
    current_ips = {info.get("ip") for _, info in rows}
    added = current_ips - baseline_ips
    removed = baseline_ips - current_ips
    common = baseline_ips & current_ips
    if USE_RICH:
        console.print(f"\n[bold]NETWORK DRIFT REPORT[/bold]")
        console.print(f"Baseline from: {baseline.get('timestamp', 'unknown')}\n")
        if added:
            console.print(f"[green]✅ ADDED ({len(added)}):[/green]")
            for ip in sorted(added):
                info = next((i for _, i in rows if i.get("ip") == ip), {})
                hostname, devtype, risk = info.get("hostname", "unknown"), info.get("devtype", "unknown"), info.get("risk", 0)
                console.print(f"  • {ip:<15} {hostname:<20} [{devtype}] risk: {risk}")
        if removed:
            console.print(f"\n[red]❌ REMOVED ({len(removed)}):[/red]")
            for ip in sorted(removed):
                baseline_host = next((h for h in baseline.get("hosts", []) if h["ip"] == ip), {})
                hostname, devtype = baseline_host.get("hostname", "unknown"), baseline_host.get("devtype", "unknown")
                console.print(f"  • {ip:<15} {hostname:<20} [{devtype}]")
        changed_ports = []
        for ip in common:
            baseline_host = next((h for h in baseline.get("hosts", []) if h["ip"] == ip), {})
            current_host = next((i for _, i in rows if i.get("ip") == ip), {})
            baseline_ports = {p["port"] for p in baseline_host.get("open_ports", [])}
            current_ports = {p["port"] for p in current_host.get("ports", []) if p.get("state") == "open"}
            if baseline_ports != current_ports:
                changed_ports.append((ip, current_host.get("hostname"), baseline_ports, current_ports))
        if changed_ports:
            console.print(f"\n[yellow]⚠️  CHANGED ({len(changed_ports)}):[/yellow]")
            for ip, hostname, old_ports, new_ports in changed_ports:
                added_ports = new_ports - old_ports
                removed_ports = old_ports - new_ports
                console.print(f"  • {ip:<15} {hostname:<20}")
                if added_ports: console.print(f"      [green]NEW PORTS:[/green] {', '.join(map(str, sorted(added_ports)))}")
                if removed_ports: console.print(f"      [red]CLOSED PORTS:[/red] {', '.join(map(str, sorted(removed_ports)))}")
    else:
        print(f"\nNETWORK DRIFT REPORT")
        print(f"Baseline from: {baseline.get('timestamp', 'unknown')}\n")
        if added:
            print(f"✅ ADDED ({len(added)}):")
            for ip in sorted(added):
                info = next((i for _, i in rows if i.get("ip") == ip), {})
                hostname, devtype, risk = info.get("hostname", "unknown"), info.get("devtype", "unknown"), info.get("risk", 0)
                print(f"  • {ip:<15} {hostname:<20} [{devtype}] risk: {risk}")
        if removed:
            print(f"\n❌ REMOVED ({len(removed)}):")
            for ip in sorted(removed):
                baseline_host = next((h for h in baseline.get("hosts", []) if h["ip"] == ip), {})
                hostname, devtype = baseline_host.get("hostname", "unknown"), baseline_host.get("devtype", "unknown")
                print(f"  • {ip:<15} {hostname:<20} [{devtype}]")

def show_detailed_host_view(idx: int, total: int, info: Dict[str,Any], scan_id: str, cve_checker: Optional[CVEChecker] = None):
    ip = info.get("ip")
    hostname = info.get("hostname") or "-"
    mac = info.get("mac") or "-"
    vendor = info.get("vendor") or "-"
    devtype = info.get("devtype") or "-"
    os_detected = info.get("os") or "-"
    cidr = info.get("cidr") or "-"
    ports = info.get("ports", [])
    breakdown = info.get("breakdown", [])
    nmap_xml = info.get("nmap_xml")
    title = f"DETAILED HOST VIEW  —  Host {idx}/{total}: {ip}  ({hostname})"
    label = "OK ✅" if info.get("risk",0) < 40 else ("WARNING ⚠" if info.get("risk",0) < 60 else "CRITICAL ⚠️")
    if USE_RICH:
        console.rule(title + "  [" + label + "]")
        console.print(f"\n[bold]Scan meta[/bold]")
        console.print(f" • Scan ID: {scan_id}")
        console.print(f" • Host scanned at: {datetime.now().isoformat()}")
        console.print(f"\n[bold]Identification[/bold]")
        console.print(f" • IP: {ip}")
        console.print(f" • CIDR: {cidr}")
        console.print(f" • Hostname(s): {hostname}")
        console.print(f" • MAC: {mac}   (Vendor: {vendor})")
        console.print(f" • Operating System (detected): {os_detected}")
        console.print(f" • Device type (inferred): {devtype}")
        console.print(f"\n[bold]Open services & banners[/bold]")
        if not ports:
            console.print(" • (none discovered)")
        else:
            for p in ports:
                if p.get("state") == "open":
                    service, version, state = p.get("service") or "-", p.get("version") or "", p.get("state") or "-"
                    console.print(f" └ {p.get('port')}/{p.get('proto')}  {service}  {version}   [{state}]")
        cves = []
        if cve_checker and cve_checker.enabled:
            cves = check_known_cves(info, cve_checker)
        if cves:
            console.print(f"\n[bold]Known CVEs (Service Versions)[/bold]")
            for service, cve_str, severity in cves:
                sev_color = "red" if severity in ["CRITICAL", "HIGH"] else "yellow"
                console.print(f" • [{sev_color}]{severity}[/{sev_color}] {service}: {cve_str}")
        console.print(f"\n[bold]Security & heuristics (score breakdown)[/bold]")
        if not breakdown:
            console.print(" • No heuristics triggered. Risk contributions: 0")
        else:
            for name, pts in breakdown:
                console.print(f" • {name}: +{pts}")
        console.print(f" —\n TOTAL RISK = {info.get('risk',0)}    →  LABEL: {label}")
        if nmap_xml:
            console.print(f"\n[bold]Nmap probe highlights[/bold]")
            console.print(" • (nmap XML captured; save with --save-all to persist raw XML)")
        console.print(f"\n[bold]Suggested actions[/bold]")
        if info.get("risk", 0) >= 60:
            console.print(" [1] Isolate device to guest VLAN / apply ACL")
            console.print(f" [2] Capture traffic: sudo tcpdump -i {{iface}} host {ip} -w /path/to/capture.pcap")
            console.print(" [3] Change default credentials & update firmware")
        else:
            console.print(" • No immediate action suggested (risk low).")
            console.print() # Blank line for spacing between Host Views
    else:
        print(f"\n{'='*80}")
        print(title)
        print(f"IP: {ip} | Hostname: {hostname} | OS: {os_detected} | Device: {devtype}")
        print(f"Risk: {info.get('risk', 0)} - {label}")
        if ports:
            print("Open services:")
            for p in ports:
                if p.get("state") == "open":
                    print(f"  - {p.get('port')}/{p.get('proto')} {p.get('service')} {p.get('version') or ''}")
        cves = []
        if cve_checker and cve_checker.enabled:
            cves = check_known_cves(info, cve_checker)
        if cves:
            print("\nKnown CVEs (Service Versions):")
            for service, cve_str, severity in cves:
                print(f"  - [{severity}] {service}: {cve_str}")
        print(f"{'='*80}")

def save_results(scan_id: str, iface: str, cidrs: List[str], rows: List[Tuple[int,Dict[str,Any]]], save_all: bool=False, quiet: bool=False):
    os.makedirs(LOGS, exist_ok=True)
    csv_path = os.path.join(LOGS, f"{scan_id}_summary.csv")
    json_path = os.path.join(LOGS, f"{scan_id}_summary.json")
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["hostname","ip","cidr","mac","vendor","os","risk","flags","devtype","ports"])
        for _, r in rows:
            w.writerow([r.get("hostname") or "-", r.get("ip"), r.get("cidr") or "-", r.get("mac") or "-", r.get("vendor") or "-", r.get("os") or "-", r.get("risk") or 0, ";".join(r.get("flags",[])), r.get("devtype") or "-", format_ports(r.get("ports",[]))])
    agg = {"scan_id": scan_id, "iface": iface, "cidrs": cidrs, "timestamp": datetime.now().isoformat(), "hosts": []}
    for _, r in rows:
        agg["hosts"].append({"hostname": r.get("hostname") or "-", "ip": r.get("ip"), "cidr": r.get("cidr") or "-", "mac": r.get("mac") or "-", "vendor": r.get("vendor") or "-", "os": r.get("os") or "-", "risk": r.get("risk") or 0, "flags": r.get("flags"), "devtype": r.get("devtype") or "-", "ports": r.get("ports")})
    with open(json_path, "w") as fh:
        json.dump(agg, fh, indent=2)
    if not quiet:
        if USE_RICH:
            console.print(f"\n[green]✅ Results saved:[/green]")
            console.print(f"  → CSV: {csv_path}")
            console.print(f"  → JSON: {json_path}")
        else:
            print(f"\n✅ Results saved:")
            print(f"  → CSV: {csv_path}")
            print(f"  → JSON: {json_path}")

def run_enumeration_phase(host_infos: Dict[str, Dict[str, Any]], args: Any) -> None:
    """Execute enumeration modules on discovered hosts"""
    if not (args.enum_all or args.enum_dns or args.enum_smb or args.enum_http or args.enum_snmp or args.enum_email or args.enum_secrets):
        return
    
    if USE_RICH:
        console.print("\n[cyan]🔍 Running advanced enumeration...[/cyan]")
    else:
        print("\n🔍 Running advanced enumeration...")
    
    snmp_wordlist = ["public", "private", "community", "manager", "monitoring"]
    
    for host_ip, host_info in host_infos.items():
        enum_results = {}
        services = host_info.get("ports", [])
        
        # DNS Enumeration
        if args.enum_all or args.enum_dns:
            if 53 in services:
                try:
                    dns_result = EnumDNS.zone_transfer(host_ip, 5)
                    if dns_result:
                        enum_results["dns"] = dns_result
                except: pass
        
        # SMB Enumeration
        if args.enum_all or args.enum_smb:
            if 139 in services or 445 in services:
                try:
                    smb_result = {
                        "null_session": EnumSMB.null_session_check(host_ip, 5),
                        "shares": EnumSMB.enum_shares(host_ip, 5)
                    }
                    if smb_result["shares"] or smb_result["null_session"]:
                        enum_results["smb"] = smb_result
                except: pass
        
        # HTTP Enumeration
        if args.enum_all or args.enum_http:
            for port in [80, 443, 8080, 8443]:
                if port in services:
                    try:
                        scheme = "https" if port == 443 else "http"
                        url = f"{scheme}://{host_ip}:{port}"
                        headers = EnumHTTP.grab_headers(url, 5)
                        cert = EnumHTTP.parse_certificate(host_ip, port, 5) if port == 443 else None
                        if headers or cert:
                            enum_results["http"] = {"headers": headers, "certificate": cert}
                            # Secrets scanning in headers
                            if headers and (args.enum_all or args.enum_secrets):
                                secrets = EnumSecrets.scan_text(str(headers))
                                if secrets:
                                    enum_results["secrets"] = {"found": secrets}
                        break
                    except: pass
        
        # SNMP Enumeration
        if args.enum_all or args.enum_snmp:
            if 161 in services:
                try:
                    snmp_result = EnumSNMP.community_brute(host_ip, snmp_wordlist, 5)
                    if snmp_result:
                        enum_results["snmp"] = snmp_result
                except: pass
        
        # Email Enumeration
        if args.enum_all or args.enum_email:
            if 25 in services:
                try:
                    email_result = EnumEmail.smtp_enum(host_ip, 25, 5)
                    if email_result:
                        enum_results["email"] = email_result
                except: pass
        
        # Store enumeration results
        if enum_results:
            host_info["enumeration"] = enum_results
            # Flag enumeration findings for risk scoring
            if "secrets" in enum_results:
                host_info["flags"].insert(0, "⚠️ SECRETS_DETECTED")
            if "smb" in enum_results and enum_results["smb"].get("null_session"):
                host_info["flags"].insert(0, "⚠️ SMB_NULL_SESSION")
    
    if USE_RICH:
        console.print("[green]✓ Enumeration complete[/green]")
    else:
        print("✓ Enumeration complete")

def show_progress_and_timers(total_hosts: int, probes_done: int):
    if USE_RICH:
        console.print("\n[bold]PROGRESS / TIMERS[/bold]")
        console.print(f" • Discovery: 100%  (nmap -sn)")
        console.print(f" • Service probes: 100%  ({probes_done}/{total_hosts} hosts)")
    else:
        print("\nPROGRESS / TIMERS")
        print(" • Discovery: 100%  (nmap -sn)")
        print(f" • Service probes: 100%  ({probes_done}/{total_hosts} hosts)")

def show_scan_summary(scan_id: str, rows: List[Tuple[int,Dict[str,Any]]], start_time: datetime):
    total_hosts = len(rows)
    critical = len([r for _,r in rows if r.get("risk",0) >= 60])
    warning = len([r for _,r in rows if 40 <= r.get("risk",0) < 60])
    ok = len([r for _,r in rows if r.get("risk",0) < 40])
    runtime = datetime.now() - start_time
    if USE_RICH:
        console.print("\n" + ("─"*80))
        console.print(f"[bold]SCAN SUMMARY[/bold]")
        console.print(f" • Hosts scanned: {total_hosts}    Critical: {critical}   Warnings: {warning}   OK: {ok}")
        console.print(f" • Scan ID: {scan_id}")
        console.print(f" • Ephemeral run (no files saved). To save: press 's' now or run with --save")
        console.print(f" • Total runtime: {str(runtime).split('.')[0]}")
    else:
        print("\nSCAN SUMMARY")
        print(f" • Hosts scanned: {total_hosts}    Critical: {critical}   Warnings: {warning}   OK: {ok}")
        print(f" • Scan ID: {scan_id}")
        print(" • Ephemeral run (no files saved). To save: pass --save or choose at prompt")
        print(" • Total runtime:", str(runtime).split('.')[0])

def show_risk_legend():
    legend = [("🔴", "90-100", "SEVERE"), ("🟠", "60-89", "CRITICAL"), ("🟡", "40-59", "WARNING"), ("🟢", "0-39", "OK")]
    if USE_RICH:
        t = Table(show_header=False)
        t.add_column("sym", width=3)
        t.add_column("range", width=8)
        t.add_column("meaning")
        for sym, rng, meaning in legend:
            t.add_row(sym, rng, meaning)
        console.print("\n[bold]RISK LEGEND[/bold]")
        console.print(t)
    else:
        print("\nRISK LEGEND")
        for sym, rng, meaning in legend:
            print(f"{sym} {rng} {meaning}")

def show_tips():
    tips = ["Press number of host (e.g., 7) to jump to details in interactive mode", "Press 'd' to dump full JSON to stdout (ephemeral) for piping", "Use --save or --save-all to avoid interactive prompt in scripted runs", "Try --map for network topology visualization", "Try --threats for threat assessment engine", "Try --cve-check to find known vulnerable service versions", "Try --save-baseline and --compare-baseline to detect rogue devices"]
    if USE_RICH:
        console.print("\n[bold]TIPS[/bold]")
        for t in tips:
            console.print(" • " + t)
    else:
        print("\nTIPS")
        for t in tips:
            print(" • " + t)

def start_tcpdump_capture(iface: str, host_ip: Optional[str], scan_id: str, duration: int, custom_filter: Optional[str] = None) -> Optional[str]:
    """Start tcpdump capture for a specific host or all traffic. Returns capture_id on success.
    
    Args:
        iface: Network interface to capture on
        host_ip: Optional specific host IP to capture
        scan_id: Scan identifier
        duration: Capture duration in seconds
        custom_filter: Optional custom tcpdump filter expression (overrides host_ip filter)
    """
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        capture_filename = f"capture_{scan_id}"
        if host_ip:
            capture_filename += f"_{host_ip.replace('.', '_')}"
        capture_filename += f"_{timestamp}.pcap"
        capture_path = os.path.join(CAPTURES, capture_filename)
        
        # Build tcpdump filter
        # Priority: custom_filter > host_ip filter > no filter
        filter_expr = ""
        if custom_filter:
            filter_expr = custom_filter
        elif host_ip:
            filter_expr = f"host {host_ip}"
        
        # Build tcpdump command
        cmd = ["tcpdump", "-i", iface, "-w", capture_path, "-G", str(duration), "-Z", "root"]
        if filter_expr:
            cmd.append(filter_expr)
        
        # Start tcpdump process
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        capture_id = f"cap_{scan_id}_{host_ip or 'all'}_{timestamp}"
        tcpdump_processes[capture_id] = {
            "process": proc,
            "host_ip": host_ip or "all",
            "file": capture_path,
            "start": datetime.now(),
            "stats": {"packets": 0, "bytes": 0}
        }
        
        return capture_id
    except Exception as e:
        if USE_RICH: console.print(f"[red]Failed to start tcpdump: {e}[/red]")
        else: print(f"Failed to start tcpdump: {e}")
        return None

def stop_tcpdump_capture(capture_id: str) -> Optional[Dict[str, Any]]:
    """Stop a tcpdump capture and return statistics."""
    if capture_id not in tcpdump_processes:
        return None
    
    cap_info = tcpdump_processes[capture_id]
    proc = cap_info["process"]
    
    try:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        
        # Parse tcpdump output for statistics
        stats_output = stderr if stderr else stdout
        packets, bytes_captured = 0, 0
        
        # tcpdump outputs something like: "2500 packets captured; 185000 bytes captured"
        match_packets = re.search(r'(\d+)\s+packets? captured', stats_output)
        match_bytes = re.search(r'(\d+)\s+bytes? captured', stats_output)
        if match_packets: packets = int(match_packets.group(1))
        if match_bytes: bytes_captured = int(match_bytes.group(1))
        
        cap_info["stats"] = {"packets": packets, "bytes": bytes_captured}
        cap_info["end"] = datetime.now()
        cap_info["duration"] = (cap_info["end"] - cap_info["start"]).total_seconds()
        
        return cap_info
    except Exception as e:
        if USE_RICH: console.print(f"[red]Error stopping capture {capture_id}: {e}[/red]")
        else: print(f"Error stopping capture {capture_id}: {e}")
        return None

def stop_all_captures() -> List[Dict[str, Any]]:
    """Stop all running tcpdump captures and return their info."""
    results = []
    for capture_id in list(tcpdump_processes.keys()):
        cap_info = stop_tcpdump_capture(capture_id)
        if cap_info:
            results.append(cap_info)
    return results

def show_capture_summary(captures: List[Dict[str, Any]]) -> None:
    """Display a summary of all packet captures."""
    if not captures:
        return
    
    if USE_RICH:
        console.print("\n[bold magenta]📦 Packet Capture Summary[/bold magenta]")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Target", style="cyan")
        table.add_column("File", style="green")
        table.add_column("Packets", style="yellow")
        table.add_column("Bytes", style="yellow")
        table.add_column("Duration (s)", style="magenta")
        
        for cap in captures:
            target = cap.get("host_ip", "unknown")
            file_size_bytes = os.path.getsize(cap["file"]) if os.path.exists(cap["file"]) else 0
            packets = cap.get("stats", {}).get("packets", 0)
            
            # If tcpdump didn't report bytes, use the actual file size
            bytes_captured = cap.get("stats", {}).get("bytes", 0)
            if bytes_captured == 0 and file_size_bytes > 0:
                bytes_captured = file_size_bytes
            
            duration = cap.get("duration", 0)
            
            table.add_row(
                target,
                os.path.basename(cap["file"]),
                str(packets),
                f"{bytes_captured / 1024:.1f} KB" if bytes_captured > 0 else "0 B",
                f"{duration:.1f}"
            )
        
        console.print(table)
    else:
        print("\n📦 Packet Capture Summary")
        print(f"{'Target':<20} {'File':<40} {'Packets':<10} {'Bytes':<15} {'Duration':<10}")
        print("-" * 95)
        for cap in captures:
            target = cap.get("host_ip", "unknown")
            file_size_bytes = os.path.getsize(cap["file"]) if os.path.exists(cap["file"]) else 0
            packets = cap.get("stats", {}).get("packets", 0)
            
            # If tcpdump didn't report bytes, use the actual file size
            bytes_captured = cap.get("stats", {}).get("bytes", 0)
            if bytes_captured == 0 and file_size_bytes > 0:
                bytes_captured = file_size_bytes
            
            duration = cap.get("duration", 0)
            
            bytes_str = f"{bytes_captured / 1024:.1f} KB" if bytes_captured > 0 else "0 B"
            print(f"{target:<20} {os.path.basename(cap['file']):<40} {packets:<10} {bytes_str:<15} {duration:<10.1f}s")

def output_json_only(rows: List[Tuple[int,Dict[str,Any]]], scan_id: str, iface: str, cidrs: List[str]):
    """Output results as pure JSON to stdout for piping (no formatting, no interactive mode)."""
    agg = {
        "scan_id": scan_id, 
        "iface": iface, 
        "cidrs": cidrs, 
        "timestamp": datetime.now().isoformat(),
        "hosts": []
    }
    for _, r in rows:
        agg["hosts"].append({
            "hostname": r.get("hostname") or "-",
            "ip": r.get("ip"),
            "cidr": r.get("cidr") or "-",
            "mac": r.get("mac") or "-",
            "vendor": r.get("vendor") or "-",
            "os": r.get("os") or "-",
            "risk": r.get("risk") or 0,
            "flags": r.get("flags", []),
            "devtype": r.get("devtype") or "-",
            "ports": r.get("ports", [])
        })
    # Output pure JSON to stdout
    print(json.dumps(agg, indent=2))

def build_vulnerability_list(host_infos: Dict[str, Dict[str,Any]], cve_checker: Optional[CVEChecker] = None) -> List[Dict[str,Any]]:
    """Build comprehensive vulnerability list with attack vectors and remediation."""
    vulns = []
    
    for ip, info in host_infos.items():
        hostname = info.get("hostname") or "unknown"
        devtype = info.get("devtype") or "unknown"
        
        # Check for CVEs (only if cve_checker is provided and enabled)
        cves = []
        if cve_checker and cve_checker.enabled:
            cves = check_known_cves(info, cve_checker)
        for svc_name, cve_str, severity in cves:
            vuln_entry = {
                "device": hostname,
                "device_type": devtype,
                "ip": ip,
                "vulnerability": f"{svc_name}",
                "cves": cve_str,
                "severity": severity,
                "category": "CVE/Version",
                "cvss_score": None,
                "cwe": None,
                "attack_vectors": [],
                "exploitation_difficulty": "MEDIUM",
                "timeline_to_exploit": "Hours",
                "business_impact": f"Potential exploitation through {svc_name} vulnerabilities",
                "remediation": [f"Update {svc_name} to latest version", "Apply security patches"]
            }
            
            # Enhance with service-specific data if available
            if svc_name.lower() in RISKY_SERVICES:
                service_data = RISKY_SERVICES[svc_name.lower()]
                vuln_entry["cvss_score"] = service_data.get("cvss_score")
                vuln_entry["cwe"] = service_data.get("cwe")
                vuln_entry["exploitation_difficulty"] = service_data.get("exploitation_difficulty")
                vuln_entry["timeline_to_exploit"] = service_data.get("timeline_to_exploit")
                vuln_entry["business_impact"] = service_data.get("business_impact")
                vuln_entry["remediation"] = service_data.get("remediation", [])
            
            vulns.append(vuln_entry)
        
        # Check for risky services (unencrypted protocols)
        for port in info.get("ports", []):
            # Skip None entries in ports list
            if port is None:
                continue
            # Handle case where service key exists but value is None
            service_raw = port.get("service", "")
            service = (service_raw or "").lower()
            version = port.get("version") or ""
            
            for risky_svc, risky_info in RISKY_SERVICES.items():
                if risky_svc in service or service in risky_svc:
                    vuln_entry = {
                        "device": hostname,
                        "device_type": devtype,
                        "ip": ip,
                        "port": port.get("port"),
                        "vulnerability": f"{risky_info['service_name']} (Unencrypted)",
                        "cves": None,
                        "severity": risky_info.get("severity"),
                        "category": "Unencrypted Protocol",
                        "cvss_score": risky_info.get("cvss_score"),
                        "cwe": risky_info.get("cwe"),
                        "attack_vectors": risky_info.get("attack_vectors", []),
                        "exploitation_difficulty": risky_info.get("exploitation_difficulty"),
                        "timeline_to_exploit": risky_info.get("timeline_to_exploit"),
                        "business_impact": risky_info.get("business_impact"),
                        "remediation": risky_info.get("remediation", [])
                    }
                    vulns.append(vuln_entry)
                    break
    
    # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    vulns.sort(key=lambda x: (severity_order.get(x.get("severity", "LOW"), 99), x.get("cvss_score", 0)), reverse=True)
    
    return vulns

def show_vulnerability_summary_quick(vulns: List[Dict[str,Any]]) -> None:
    """TIER 1: Quick vulnerability summary (simple table)."""
    if not vulns:
        if USE_RICH: console.print("[green]✅ No vulnerabilities detected![/green]")
        else: print("✅ No vulnerabilities detected!")
        return
    
    if USE_RICH:
        console.print("\n[bold red]VULNERABILITY SUMMARY[/bold red]")
        table = Table(title="Discovered Vulnerabilities", show_header=True, header_style="bold red")
        table.add_column("Device", style="cyan")
        table.add_column("IP", style="magenta")
        table.add_column("Vulnerability", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Attack Vectors", style="white")
        
        for v in vulns[:10]:  # Show top 10
            port_str = f":{v['port']}" if v.get("port") else ""
            severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(v.get("severity"), "⚪")
            attacks_summary = ", ".join(v.get("attack_vectors", [])[:2])
            table.add_row(
                v.get("device", "unknown"),
                f"{v.get('ip')}{port_str}",
                v.get("vulnerability", "unknown"),
                f"{severity_emoji} {v.get('severity', 'UNKNOWN')}",
                attacks_summary
            )
        
        console.print(table)
        if len(vulns) > 10:
            console.print(f"[yellow]... and {len(vulns) - 10} more vulnerabilities[/yellow]")
    else:
        print("\n" + "="*120)
        print("VULNERABILITY SUMMARY")
        print("="*120)
        print(f"{'Device':<20} {'IP':<20} {'Vulnerability':<30} {'Severity':<12} {'Attack Vectors':<40}")
        print("-"*120)
        for v in vulns[:10]:
            port_str = f":{v['port']}" if v.get("port") else ""
            attacks_summary = ", ".join(v.get("attack_vectors", [])[:2])[:37]
            print(f"{v.get('device', 'unknown'):<20} {(v.get('ip') + port_str):<20} {v.get('vulnerability', 'unknown'):<30} {v.get('severity', 'UNKNOWN'):<12} {attacks_summary:<40}")
        if len(vulns) > 10:
            print(f"... and {len(vulns) - 10} more vulnerabilities")
        print("="*120)

def show_vulnerability_summary_professional(vulns: List[Dict[str,Any]]) -> None:
    """TIER 2: Professional vulnerability report with attack vectors & CVSS."""
    if not vulns:
        if USE_RICH: console.print("[green]✅ No vulnerabilities detected![/green]")
        else: print("✅ No vulnerabilities detected!")
        return
    
    # Group vulnerabilities by device first, then by severity
    by_device = {}
    for v in vulns:
        device_key = f"{v.get('ip')}||{v.get('device')}||{v.get('device_type')}"
        if device_key not in by_device:
            by_device[device_key] = []
        by_device[device_key].append(v)

    # Determine highest severity across all vulns
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    highest_severity = "LOW"
    for v in vulns:
        if severity_order.get(v.get("severity", "LOW"), 3) < severity_order.get(highest_severity, 3):
            highest_severity = v.get("severity", "LOW")

    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    emoji = severity_emoji.get(highest_severity, "⚪")

    if USE_RICH:
        console.print("\n[bold red]═══════════════════════════════════════════════════════════════════════════[/bold red]")
        console.print(f"[bold red]{'':^19}PROFESSIONAL VULNERABILITY ANALYSIS{'':^19}[/bold red]")
        console.print(f"[bold red]{'':^25}{emoji} {highest_severity} SEVERITY ({len(vulns)} vulnerabilities){'':^25}[/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════════════════════[/bold red]\n")

        # Display each device and its vulnerabilities in tree format
        for device_key, device_vulns in by_device.items():
            ip, device_name, device_type = device_key.split("||")

            # Get device icon
            device_icons = {"tv": "📺", "router": "🌐", "gaming_console": "🎮", "media_device": "💻", "mobile": "📱"}
            icon = device_icons.get(device_type, "🖥️")

            console.print(f"[bold cyan]{icon} {device_name} ({device_type}) @ {ip}[/bold cyan]")
            console.print(f"[dim]Vulnerabilities: {len(device_vulns)}[/dim]\n")

            # Display vulnerabilities in tree format
            for idx, vuln in enumerate(device_vulns, 1):
                is_last = (idx == len(device_vulns))
                prefix = "└─" if is_last else "├─"
                cont_prefix = "   " if is_last else "│  "

                console.print(f"  {prefix} [yellow][VULN-{idx}] {vuln.get('vulnerability')}[/yellow]")

                # CVSS Score
                cvss = vuln.get('cvss_score', 'N/A')
                severity = vuln.get('severity', 'UNKNOWN')
                sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(severity, "white")
                console.print(f"  {cont_prefix}├─ [cyan]CVSS Score:[/cyan]    [{sev_color}]{cvss}/10 ({severity})[/{sev_color}]")

                # CWE
                if vuln.get('cwe'):
                    console.print(f"  {cont_prefix}├─ [cyan]CWE:[/cyan]           {vuln.get('cwe')}")

                # Exploit Difficulty
                exploit_diff = vuln.get('exploitation_difficulty', 'UNKNOWN')
                timeline = vuln.get('timeline_to_exploit', 'Unknown')
                console.print(f"  {cont_prefix}├─ [cyan]Exploit Time:[/cyan]  ~{timeline} ({exploit_diff} difficulty)")

                # Attack Vectors
                attack_vectors = vuln.get('attack_vectors', [])
                if attack_vectors:
                    console.print(f"  {cont_prefix}├─ [cyan]Attack Vector:[/cyan]")
                    for av_idx, attack in enumerate(attack_vectors):
                        is_last_attack = (av_idx == len(attack_vectors) - 1)
                        av_prefix = "└─" if is_last_attack else "├─"
                        console.print(f"  {cont_prefix}│  {av_prefix} • {attack}")

                # Business Impact
                impact = vuln.get('business_impact', 'Unknown')
                console.print(f"  {cont_prefix}└─ [red]Business Impact:[/red] {impact}")

                # Add spacing between vulnerabilities
                if not is_last:
                    console.print(f"  {cont_prefix}")

            console.print("\n[dim]" + "─" * 75 + "[/dim]\n")

    else:
        print("\n" + "="*79)
        print(f"{'':^19}PROFESSIONAL VULNERABILITY ANALYSIS{'':^19}")
        print(f"{'':^25}{emoji} {highest_severity} SEVERITY ({len(vulns)} vulnerabilities){'':^25}")
        print("="*79 + "\n")

        # Display each device and its vulnerabilities in tree format
        for device_key, device_vulns in by_device.items():
            ip, device_name, device_type = device_key.split("||")

            # Get device icon
            device_icons = {"tv": "📺", "router": "🌐", "gaming_console": "🎮", "media_device": "💻", "mobile": "📱"}
            icon = device_icons.get(device_type, "🖥️")

            print(f"{icon} {device_name} ({device_type}) @ {ip}")
            print(f"Vulnerabilities: {len(device_vulns)}\n")

            # Display vulnerabilities in tree format
            for idx, vuln in enumerate(device_vulns, 1):
                is_last = (idx == len(device_vulns))
                prefix = "└─" if is_last else "├─"
                cont_prefix = "   " if is_last else "│  "

                print(f"  {prefix} [VULN-{idx}] {vuln.get('vulnerability')}")

                # Details
                cvss = vuln.get('cvss_score', 'N/A')
                severity = vuln.get('severity', 'UNKNOWN')
                print(f"  {cont_prefix}├─ CVSS Score:    {cvss}/10 ({severity})")

                if vuln.get('cwe'):
                    print(f"  {cont_prefix}├─ CWE:           {vuln.get('cwe')}")

                exploit_diff = vuln.get('exploitation_difficulty', 'UNKNOWN')
                timeline = vuln.get('timeline_to_exploit', 'Unknown')
                print(f"  {cont_prefix}├─ Exploit Time:  ~{timeline} ({exploit_diff} difficulty)")

                attack_vectors = vuln.get('attack_vectors', [])
                if attack_vectors:
                    print(f"  {cont_prefix}├─ Attack Vector:")
                    for av_idx, attack in enumerate(attack_vectors):
                        is_last_attack = (av_idx == len(attack_vectors) - 1)
                        av_prefix = "└─" if is_last_attack else "├─"
                        print(f"  {cont_prefix}│  {av_prefix} • {attack}")

                impact = vuln.get('business_impact', 'Unknown')
                print(f"  {cont_prefix}└─ Business Impact: {impact}")

                if not is_last:
                    print(f"  {cont_prefix}")

            print("\n" + "-"*75 + "\n")

def show_vulnerability_summary_enterprise(vulns: List[Dict[str,Any]]) -> None:
    """TIER 3: Enterprise-grade report with remediation steps & prioritization."""
    if not vulns:
        if USE_RICH: console.print("[green]✅ No vulnerabilities detected![/green]")
        else: print("✅ No vulnerabilities detected!")
        return
    
    # Count by severity
    critical = len([v for v in vulns if v.get("severity") == "CRITICAL"])
    high = len([v for v in vulns if v.get("severity") == "HIGH"])
    medium = len([v for v in vulns if v.get("severity") == "MEDIUM"])
    low = len([v for v in vulns if v.get("severity") == "LOW"])
    
    if USE_RICH:
        console.print("\n[bold white on red]╔══════════════════════════════════════════════════════════════╗[/bold white on red]")
        console.print("[bold white on red]║           EXECUTIVE VULNERABILITY REPORT (v1.0.0)            ║[/bold white on red]")
        console.print("[bold white on red]╚══════════════════════════════════════════════════════════════╝[/bold white on red]")
        
        console.print("\n[bold]VULNERABILITY INVENTORY[/bold]")
        console.print(f"  🔴 CRITICAL: {critical}")
        console.print(f"  🟠 HIGH:     {high}")
        console.print(f"  🟡 MEDIUM:   {medium}")
        console.print(f"  🟢 LOW:      {low}")
        console.print(f"  [bold]TOTAL:     {len(vulns)}[/bold]")
        
        console.print("\n[bold red]CRITICAL PRIORITY ACTIONS[/bold red]")
        console.print("[red]Address these immediately (within 24 hours):[/red]\n")
        
        critical_vulns = [v for v in vulns if v.get("severity") == "CRITICAL"]
        for idx, v in enumerate(critical_vulns[:5], 1):
            console.print(f"[bold]{idx}. {v.get('vulnerability')} on {v.get('device')} ({v.get('ip')})[/bold]")
            console.print(f"   Category: {v.get('category')}")
            if v.get('cvss_score'):
                console.print(f"   CVSS Score: {v.get('cvss_score')}/10 - {v.get('exploitation_difficulty')} to exploit")
            console.print(f"   Recommended Actions:")
            for remedy in v.get('remediation', [])[:3]:
                console.print(f"     ✓ {remedy}")
            console.print()
        
        if len(critical_vulns) > 5:
            console.print(f"   ... and {len(critical_vulns) - 5} more CRITICAL issues\n")
        
        console.print("[bold yellow]HIGH PRIORITY ACTIONS[/bold yellow]")
        console.print("[yellow]Address within 7 days:[/yellow]\n")
        
        high_vulns = [v for v in vulns if v.get("severity") == "HIGH"]
        for idx, v in enumerate(high_vulns[:3], 1):
            console.print(f"[bold]{idx}. {v.get('vulnerability')} on {v.get('device')} ({v.get('ip')})[/bold]")
            console.print(f"   Recommended Actions:")
            for remedy in v.get('remediation', [])[:2]:
                console.print(f"     ✓ {remedy}")
            console.print()
        
        if len(high_vulns) > 3:
            console.print(f"   ... and {len(high_vulns) - 3} more HIGH priority issues\n")
        
        console.print("[bold cyan]REMEDIATION SUMMARY[/bold cyan]")
        console.print("Most common remediation steps:")
        remediation_counts = {}
        for v in vulns:
            for remedy in v.get('remediation', [])[:2]:
                remediation_counts[remedy] = remediation_counts.get(remedy, 0) + 1
        
        for remedy, count in sorted(remediation_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            console.print(f"  [{count}] {remedy}")
        
    else:
        print("\n" + "="*80)
        print("EXECUTIVE VULNERABILITY REPORT (v1.0.0)")
        print("="*80)
        print("\nVULNERABILITY INVENTORY")
        print(f"  CRITICAL: {critical}")
        print(f"  HIGH:     {high}")
        print(f"  MEDIUM:   {medium}")
        print(f"  LOW:      {low}")
        print(f"  TOTAL:    {len(vulns)}")
        
        print("\nCRITICAL PRIORITY ACTIONS")
        print("Address these immediately (within 24 hours):\n")
        
        critical_vulns = [v for v in vulns if v.get("severity") == "CRITICAL"]
        for idx, v in enumerate(critical_vulns[:5], 1):
            print(f"{idx}. {v.get('vulnerability')} on {v.get('device')} ({v.get('ip')})")
            print(f"   Category: {v.get('category')}")
            if v.get('cvss_score'):
                print(f"   CVSS Score: {v.get('cvss_score')}/10 - {v.get('exploitation_difficulty')} to exploit")
            print(f"   Recommended Actions:")
            for remedy in v.get('remediation', [])[:3]:
                print(f"     ✓ {remedy}")
            print()
        
        if len(critical_vulns) > 5:
            print(f"   ... and {len(critical_vulns) - 5} more CRITICAL issues\n")
        
        print("HIGH PRIORITY ACTIONS")
        print("Address within 7 days:\n")
        
        high_vulns = [v for v in vulns if v.get("severity") == "HIGH"]
        for idx, v in enumerate(high_vulns[:3], 1):
            print(f"{idx}. {v.get('vulnerability')} on {v.get('device')} ({v.get('ip')})")
            print(f"   Recommended Actions:")
            for remedy in v.get('remediation', [])[:2]:
                print(f"     ✓ {remedy}")
            print()
        
        if len(high_vulns) > 3:
            print(f"   ... and {len(high_vulns) - 3} more HIGH priority issues\n")
        
        print("REMEDIATION SUMMARY")
        print("Most common remediation steps:")
        remediation_counts = {}
        for v in vulns:
            for remedy in v.get('remediation', [])[:2]:
                remediation_counts[remedy] = remediation_counts.get(remedy, 0) + 1
        
        for remedy, count in sorted(remediation_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  [{count}] {remedy}")

def main():
    parser = argparse.ArgumentParser(description="net-inspect v1.0.0: Network Security Intelligence with Real-Time CVE Detection", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cidr", action="append", help="CIDR to scan (can use multiple times: --cidr 10.0.1.0/24 --cidr fe80::/64)")
    parser.add_argument("--cidrs", help="Multiple CIDRs to scan (comma-separated)")
    parser.add_argument("--cidr-file", help="File containing CIDRs (one per line)")
    parser.add_argument("--ipv6", action="store_true", help="Prefer IPv6 auto-detection (use with no --cidr)")
    parser.add_argument("--profile", choices=["quiet", "balanced", "aggressive"], default="balanced", 
                        help="Scan profile: quiet (minimal noise), balanced (default), aggressive (full enumeration)")
    parser.add_argument("--timing", choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"], default="normal",
                        help="Nmap timing template: paranoid (slowest) to insane (fastest)")
    parser.add_argument("--json-only", action="store_true", help="Output pure JSON to stdout (no tables, no interactive mode)")
    parser.add_argument("--no-probe", action="store_true", help="Skip per-host service probes")
    parser.add_argument("--top-ports", type=int, default=TOP_PORTS_DEFAULT, help="nmap --top-ports N")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--save", action="store_true", help="Save results (CSV + JSON)")
    parser.add_argument("--save-all", action="store_true", help="Save all including raw XML")
    parser.add_argument("--map", action="store_true", help="Show network topology map")
    parser.add_argument("--threats", action="store_true", help="Show threat assessment")
    parser.add_argument("--cve-check", action="store_true", help="Check for known CVEs using real-time NVD API")
    parser.add_argument("--nvd-api-key", type=str, help="NVD API key for 10x faster CVE checking (optional, free from nvd.nist.gov)")
    parser.add_argument("--clear-cve-cache", action="store_true", help="Clear cached CVE data and exit")
    parser.add_argument("--save-baseline", action="store_true", help="Save network snapshot for later comparison")
    parser.add_argument("--compare-baseline", action="store_true", help="Compare with previous baseline snapshot")
    parser.add_argument("--capture", action="store_true", help="Enable tcpdump packet capture during scan")
    parser.add_argument("--capture-host", help="Capture only traffic for specific host IP (requires --capture)")
    parser.add_argument("--capture-duration", type=int, default=30, help="Capture duration in seconds (default: 30)")
    parser.add_argument("--capture-filter", help="Additional tcpdump filter expression (e.g., 'tcp port 22')")
    # NEW v1.5.0 Enumeration arguments
    parser.add_argument("--enum-all", action="store_true", help="Enable all enumeration modules")
    parser.add_argument("--enum-dns", action="store_true", help="Enable DNS enumeration (⚠️  loud)")
    parser.add_argument("--enum-smb", action="store_true", help="Enable SMB enumeration (⚠️  will attempt null sessions)")
    parser.add_argument("--enum-http", action="store_true", help="Enable HTTP enumeration (⚠️  creates web traffic)")
    parser.add_argument("--enum-snmp", action="store_true", help="Enable SNMP enumeration (⚠️  community string bruteforce)")
    parser.add_argument("--enum-email", action="store_true", help="Enable email enumeration (⚠️  SMTP probes)")
    parser.add_argument("--enum-secrets", action="store_true", help="Enable secrets scanning (⚠️  aggressive pattern matching)")
    parser.add_argument("--vuln-report", choices=["off", "quick", "professional", "enterprise"], default="professional",
                        help="Vulnerability report level: off=none, quick=simple table, professional=detailed analysis, enterprise=executive summary")
    parser.add_argument("--spoof-check", action="store_true", help="Run correlation engine to detect spoofed/suspicious hosts (v2.0.0 feature)")

    # NEW v1.0.0 Advanced Features
    # Traffic Analysis
    parser.add_argument("--analyze-traffic", action="store_true", help="Analyze captured traffic for credentials, files, and security issues (requires --capture)")

    # Monitoring/Daemon Mode
    parser.add_argument("--daemon", action="store_true", help="Run in daemon mode (continuous monitoring)")
    parser.add_argument("--interval", type=int, default=3600, help="Scan interval for daemon mode (seconds, default: 3600)")
    parser.add_argument("--webhook", help="Webhook URL for alerts (Slack, Discord, etc.)")
    parser.add_argument("--alert-email", help="Email address for alerts")
    parser.add_argument("--syslog-server", help="Syslog server for alerts (host:port)")

    # Threat Intelligence
    parser.add_argument("--threat-intel", action="store_true", help="Enable threat intelligence lookups (AbuseIPDB, VirusTotal, Shodan)")
    parser.add_argument("--abuseipdb-key", help="AbuseIPDB API key")
    parser.add_argument("--virustotal-key", help="VirusTotal API key")
    parser.add_argument("--shodan-key", help="Shodan API key")

    # Firewall Testing
    parser.add_argument("--firewall-test", action="store_true", help="⚠️  Test firewall evasion techniques (AUTHORIZED USE ONLY)")
    parser.add_argument("--firewall-target", help="Target IP for firewall testing (required with --firewall-test)")

    # TLS/SSL Audit
    parser.add_argument("--tls-audit", action="store_true", help="Audit SSL/TLS security for HTTPS services (SSL Labs-style)")
    parser.add_argument("--tls-deep", action="store_true", help="Deep TLS analysis (slower, more thorough)")

    # PDF Reports
    parser.add_argument("--report-pdf", help="Generate PDF report (specify output file path)")
    parser.add_argument("--report-format", choices=["executive", "professional", "technical"], default="professional", help="PDF report format")

    # Exploit Mapping
    parser.add_argument("--show-exploits", action="store_true", help="Show available exploits for detected CVEs (Metasploit, Exploit-DB, GitHub)")

    # Geolocation
    parser.add_argument("--geolocate", action="store_true", help="Geolocate IP addresses (identify geographic location)")
    parser.add_argument("--geolocate-public", action="store_true", help="Geolocate the public IP (shared by all NAT'd devices)")

    args = parser.parse_args()
    
    # Initialize CVE checker
    api_key = args.nvd_api_key if hasattr(args, 'nvd_api_key') and args.nvd_api_key else None
    cve_checker = CVEChecker(api_key=api_key)
    
    # Handle clear cache command
    if args.clear_cve_cache:
        cve_checker.clear_cache()
        if USE_RICH:
            console.print("[green]✅ CVE cache cleared[/green]")
        else:
            print("✅ CVE cache cleared")
        return

    # Handle daemon mode (NEW v1.0.0)
    if args.daemon:
        if not DAEMON_AVAILABLE:
            print("[!] Daemon mode requires monitoring module. Install dependencies: pip install requests")
            sys.exit(1)

        from netinspect.monitoring.daemon import run_daemon
        run_daemon(
            interval=args.interval,
            baseline_file=BASELINES + "/baseline.json" if args.compare_baseline else None,
            webhook_url=args.webhook,
            email_to=args.alert_email,
            syslog_server=args.syslog_server
        )
        return  # Daemon runs forever

    # Handle firewall testing (NEW v1.0.0)
    if args.firewall_test:
        if not FIREWALL_TEST_AVAILABLE:
            print("[!] Firewall testing requires Scapy. Install with: pip install scapy")
            sys.exit(1)

        if not args.firewall_target:
            print("[!] --firewall-target required with --firewall-test")
            sys.exit(1)

        print("=" * 80)
        print("⚠️  WARNING: Firewall evasion testing should ONLY be performed")
        print("   with explicit written authorization from the target owner.")
        print("   Unauthorized testing may be ILLEGAL under computer fraud laws.")
        print("=" * 80)
        confirm = input("\nI have authorization to test this target [y/N]: ")
        if confirm.lower() != 'y':
            print("\nAborted. No testing performed.")
            sys.exit(0)

        tester = FirewallTester(args.firewall_target, verbose=True)
        results = tester.run_all_tests()
        print(tester.get_report())
        sys.exit(0)

    # Skip all UI output if JSON-only mode
    if not args.json_only:
        print_dependency_check()
    
    missing = [n for n,ok,req,cat in check_dependencies() if req and not ok]
    if missing:
        msg = f"Required binaries missing: {', '.join(missing)}"
        if USE_RICH: console.print(f"[red]{msg}[/red]")
        else: print(msg)
        sys.exit(1)
    cidrs = parse_cidr_input(args.cidr, args.cidrs, args.cidr_file)
    if not cidrs:
        try:
            iface, cidr = detect_iface_and_cidr(prefer_ipv6=args.ipv6)
            cidrs = [cidr]
        except Exception as e:
            if USE_RICH: console.print(f"[red]Interface/CIDR detection failed: {e}[/red]")
            else: print(f"Interface/CIDR detection failed: {e}")
            sys.exit(1)
    else:
        try:
            iface, _ = detect_iface_and_cidr(prefer_ipv6=args.ipv6)
        except: iface = "auto"
    start = datetime.now()
    scan_id = f"scan_{start.strftime('%Y%m%d_%H%M%S')}"
    cidrs_display = ", ".join(cidrs) if len(cidrs) <= 3 else f"{len(cidrs)} networks"
    # Display profile and timing information
    profile_cfg = SCAN_PROFILES.get(args.profile, SCAN_PROFILES["balanced"])
    timing_cfg = TIMING_PROFILES.get(args.timing, TIMING_PROFILES["normal"])
    profile_info = f"Profile: {args.profile.upper()} ({profile_cfg['description']}) | Timing: {args.timing.upper()} ({timing_cfg['description']})"
    
    # Only show UI elements if not in JSON-only mode
    if not args.json_only:
        if USE_RICH:
            console.print(Panel(f"[bold]net-inspect v1.0.0[/bold]    Scan ID: [magenta]{scan_id}[/magenta]\n[cyan]Interface: {iface}    Networks: {cidrs_display}[/cyan]\n[yellow]{profile_info}[/yellow]\nStarted: {start.strftime('%Y-%m-%d %H:%M:%S')}", title="🔒 net-inspect"))
        else:
            print(f"\nnet-inspect v1.0.0")
            print(f"Scan ID: {scan_id} | Interface: {iface} | Networks: {cidrs_display}")
            print(f"{profile_info}")
            print(f"Started: {start.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Display profile warning if not balanced
    if not args.json_only and args.profile != "balanced":
        warning = profile_cfg.get("warnings", "")
        if USE_RICH:
            console.print(f"\n[yellow]{warning}[/yellow]")
        else:
            print(f"\n{warning}")
    
    # Display enum warnings if quiet profile with enumeration enabled
    if not args.json_only and args.profile == "quiet" and (args.enum_all or args.enum_dns or args.enum_smb or args.enum_http or args.enum_snmp or args.enum_email or args.enum_secrets):
        enum_warning = "⚠️  WARNING: QUIET profile selected but enumeration modules enabled. Enumeration is inherently loud and will generate alerts."
        if USE_RICH:
            console.print(f"[red]{enum_warning}[/red]")
        else:
            print(f"{enum_warning}")
    global_capture_id = None
    if args.capture:
        if not args.json_only:
            if USE_RICH: console.print("[cyan]🔴 Starting tcpdump packet capture...[/cyan]")
            else: print("Starting tcpdump packet capture...")
        global_capture_id = start_tcpdump_capture(iface, args.capture_host, scan_id, args.capture_duration, args.capture_filter)
        if global_capture_id and not args.json_only:
            target = args.capture_host or "all traffic"
            if USE_RICH:
                console.print(f"[green]✓ Capturing {target} → {CAPTURES}[/green]")
            else:
                print(f"✓ Capturing {target} → {CAPTURES}")
    
    devices, cidr_devices_map = discover_multiple_cidrs(cidrs, CIDR_DISCOVERY_CONCURRENCY, args.json_only)
    
    # Enrich local machine info if it was discovered on the network
    local_info = get_local_machine_info()
    local_hostname = local_info.get("hostname", "").lower()
    for d in devices:
        d_hostname = (d.get("hostname") or "").lower()
        # Match by hostname or IP
        if (d_hostname == local_hostname or 
            d_hostname.split('.')[0] == local_hostname.split('.')[0] or
            d.get("ip") == "127.0.0.1"):  # Edge case: localhost
            # Populate with local machine info
            if local_info.get("mac"):
                d["mac"] = local_info["mac"]
            if local_info.get("vendor"):
                d["vendor"] = local_info["vendor"]
            d["device_type"] = local_info["device_type"]
            if not args.json_only:
                if USE_RICH:
                    console.print(f"[cyan]✓ Enriched local machine ({local_hostname}): MAC={d.get('mac')}, Vendor={d.get('vendor')}[/cyan]")
                elif os.environ.get("VERBOSE"):
                    print(f"✓ Enriched local machine ({local_hostname}): MAC={d.get('mac')}, Vendor={d.get('vendor')}")
    
    # Extract vendors from the CURRENT scan's PCAP file (if it exists)
    pcap_vendors = {}
    if global_capture_id:
        # Get the actual PCAP file path from tcpdump_processes
        current_pcap = tcpdump_processes.get(global_capture_id, {}).get("file") if global_capture_id in tcpdump_processes else None
        if current_pcap and os.path.exists(current_pcap):
            if not args.json_only:
                if USE_RICH: console.print(f"[cyan]Analyzing PCAP for vendor data...[/cyan]")
                else: print(f"Analyzing PCAP for vendor data...")
            pcap_vendors = extract_vendors_from_pcap(current_pcap)
            if pcap_vendors and not args.json_only:
                if USE_RICH:
                    console.print(f"[green]✓ Found {len(pcap_vendors)} vendor(s) from PCAP[/green]")
                else:
                    print(f"✓ Found {len(pcap_vendors)} vendor(s) from PCAP")
    
    if not args.json_only:
        if USE_RICH: console.print("\n[bold]Enhancing hostname resolution and vendor lookup...[/bold]")
        else: print("\nEnhancing hostname resolution and vendor lookup...")
    for d in devices:
        if d.get("mac"):
            # If nmap didn't find a vendor, or found "Unknown", try our enhanced lookup
            # Handle all forms of "empty": None, "", "-", "Unknown", "?"
            vendor_val = (d.get("vendor") or "").strip()
            if not vendor_val or vendor_val == "Unknown" or vendor_val == "?" or vendor_val == "-":
                vendor = get_mac_vendor_enhanced(d["mac"], d.get("hostname"), pcap_vendors)
                if not vendor:
                    # Last resort: aggressive vendor inference
                    vendor = get_mac_vendor_aggressive(d["mac"], d.get("hostname"))
                if vendor: 
                    d["vendor"] = vendor
        nmap_hostname, mac = d.get("hostname"), d.get("mac")
        resolved = resolve_hostname_comprehensive(d["ip"], mac, nmap_hostname)
        d["hostname"] = resolved
    if not devices:
        if USE_RICH: console.print("[yellow]No live hosts discovered across all CIDRs.[/yellow]")
        else: print("No live hosts discovered across all CIDRs.")
        show_cidr_summary(cidr_devices_map, {})
        sys.exit(0)
    host_infos, probes_done = {}, 0
    if not args.no_probe:
        if USE_RICH and not args.json_only:
            with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), TimeElapsedColumn(), console=console) as progress:
                task = progress.add_task(f"Service probes (concurrency={args.concurrency})", total=len(devices))
                with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                    futures = {ex.submit(run_nmap_probe, d["ip"], args.top_ports, NMAP_TIMEOUT, args.profile, args.timing): d for d in devices}
                    for fut in as_completed(futures):
                        d = futures[fut]
                        try:
                            info = fut.result()
                        except: info = {"ip": d["ip"], "hostname": None, "ports": [], "os": None, "nmap_xml": None}
                        info["mac"], info["vendor"], info["cidr"], info["iface"] = d.get("mac"), d.get("vendor"), d.get("cidr"), iface
                        info["hostname"] = d.get("hostname") or info.get("hostname") or "unknown"
                        score, flags, breakdown = compute_risk(info, info.get("mac"))
                        info["risk"], info["flags"], info["breakdown"] = score, flags, breakdown
                        info["devtype"] = infer_devtype(info, info.get("vendor") or "")
                        info["os"] = infer_os(info, info.get("hostname") or "", info.get("vendor") or "")
                        host_infos[d["ip"]] = info
                        probes_done += 1
                        progress.update(task, advance=1)
        elif not args.json_only:
            print(f"Probing {len(devices)} hosts...")
            with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                futures = {ex.submit(run_nmap_probe, d["ip"], args.top_ports, NMAP_TIMEOUT, args.profile, args.timing): d for d in devices}
                for fut in as_completed(futures):
                    d = futures[fut]
                    try:
                        info = fut.result()
                    except: info = {"ip": d["ip"], "hostname": None, "ports": [], "os": None, "nmap_xml": None}
                    info["mac"], info["vendor"], info["cidr"], info["iface"] = d.get("mac"), d.get("vendor"), d.get("cidr"), iface
                    info["hostname"] = d.get("hostname") or info.get("hostname") or "unknown"
                    score, flags, breakdown = compute_risk(info, info.get("mac"))
                    info["risk"], info["flags"], info["breakdown"] = score, flags, breakdown
                    info["devtype"] = infer_devtype(info, info.get("vendor") or "")
                    info["os"] = infer_os(info, info.get("hostname") or "", info.get("vendor") or "")
                    host_infos[d["ip"]] = info
                    probes_done += 1
        else:
            # Silent mode for json_only
            with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                futures = {ex.submit(run_nmap_probe, d["ip"], args.top_ports, NMAP_TIMEOUT, args.profile, args.timing): d for d in devices}
                for fut in as_completed(futures):
                    d = futures[fut]
                    try:
                        info = fut.result()
                    except: info = {"ip": d["ip"], "hostname": None, "ports": [], "os": None, "nmap_xml": None}
                    info["mac"], info["vendor"], info["cidr"], info["iface"] = d.get("mac"), d.get("vendor"), d.get("cidr"), iface
                    info["hostname"] = d.get("hostname") or info.get("hostname") or "unknown"
                    score, flags, breakdown = compute_risk(info, info.get("mac"))
                    info["risk"], info["flags"], info["breakdown"] = score, flags, breakdown
                    info["devtype"] = infer_devtype(info, info.get("vendor") or "")
                    info["os"] = infer_os(info, info.get("hostname") or "", info.get("vendor") or "")
                    host_infos[d["ip"]] = info
                    probes_done += 1
    else:
        for d in devices:
            info = {"ip": d["ip"], "hostname": d.get("hostname") or "unknown", "mac": d.get("mac"), "vendor": d.get("vendor"), "cidr": d.get("cidr"), "ports": [], "nmap_xml": None, "iface": iface}
            score, flags, breakdown = compute_risk(info, info.get("mac"))
            info["risk"], info["flags"], info["breakdown"] = score, flags, breakdown
            info["devtype"] = infer_devtype(info, info.get("vendor") or "")
            info["os"] = infer_os(info, info.get("hostname") or "", info.get("vendor") or "")
            host_infos[d["ip"]] = info
    
    # Run enumeration phase (v1.5.0 - NEW)
    run_enumeration_phase(host_infos, args)
    
    rows = []
    for idx, d in enumerate(devices, start=1):
        info = host_infos.get(d["ip"], {"ip": d["ip"], "hostname": d.get("hostname") or "unknown", "mac": d.get("mac"), "vendor": d.get("vendor"), "cidr": d.get("cidr"), "ports": [], "nmap_xml": None, "iface": iface})
        info.setdefault("risk", 0)
        info.setdefault("flags", [])
        info.setdefault("breakdown", [])
        info.setdefault("devtype", infer_devtype(info, info.get("vendor") or ""))
        info.setdefault("os", infer_os(info, info.get("hostname") or "", info.get("vendor") or ""))
        rows.append((idx, info))
    
    # Sort rows for better organization:
    # 1. By risk level (descending) - highest risk first
    # 2. By device type (alphabetically) - groups similar devices
    # 3. By IP address (for consistent ordering within same risk/type)
    def sort_key(row):
        idx, info = row
        risk = info.get("risk", 0)
        devtype = info.get("devtype", "unknown").lower()
        ip = info.get("ip", "0.0.0.0")
        # Convert IP to tuple of integers for proper sorting
        try:
            ip_parts = tuple(int(part) for part in ip.split('.'))
        except:
            ip_parts = (0, 0, 0, 0)
        # Sort by: -risk (negative for descending), devtype, ip
        return (-risk, devtype, ip_parts)
    
    rows.sort(key=sort_key)

    # Re-index rows after sorting
    rows = [(i+1, info) for i, (_, info) in enumerate(rows)]

    # ========== NEW v1.0.0 ADVANCED ANALYSIS FEATURES ==========

    # Threat Intelligence
    if args.threat_intel and THREAT_INTEL_AVAILABLE:
        if not args.json_only:
            if USE_RICH:
                console.print("\n[cyan]🔍 Running threat intelligence checks...[/cyan]")
            else:
                print("\n[*] Running threat intelligence checks...")

        # Load API keys with config fallback
        abuseipdb_key = load_api_key('abuseipdb', args.abuseipdb_key) if CONFIG_AVAILABLE else args.abuseipdb_key
        virustotal_key = load_api_key('virustotal', args.virustotal_key) if CONFIG_AVAILABLE else args.virustotal_key
        shodan_key = load_api_key('shodan', args.shodan_key) if CONFIG_AVAILABLE else args.shodan_key

        threat_checker = ThreatIntelChecker(
            abuseipdb_key=abuseipdb_key,
            virustotal_key=virustotal_key,
            shodan_key=shodan_key
        )

        for _, info in rows:
            ip = info.get('ip')
            try:
                threat_data = threat_checker.check_ip(ip)
                info['threat_intel'] = threat_data

                if not args.json_only and threat_data.get('is_malicious'):
                    risk_level = threat_data.get('overall_risk', 'UNKNOWN')
                    if USE_RICH:
                        console.print(f"  [red]🚨 {ip}: MALICIOUS (Risk: {risk_level})[/red]")
                    else:
                        print(f"  🚨 {ip}: MALICIOUS (Risk: {risk_level})")
            except Exception as e:
                if not args.json_only:
                    if USE_RICH:
                        console.print(f"  [yellow][!] Threat intel check failed for {ip}: {e}[/yellow]")
                    else:
                        print(f"  [!] Threat intel check failed for {ip}: {e}")

    # TLS/SSL Security Audit
    if args.tls_audit and TLS_ANALYSIS_AVAILABLE:
        if not args.json_only:
            if USE_RICH:
                console.print("\n[cyan]🔒 Running TLS/SSL security audits...[/cyan]")
            else:
                print("\n[*] Running TLS/SSL security audits...")

        for _, info in rows:
            ports = info.get('ports', [])
            https_ports = [p for p in ports if p.get('service') in ['https', 'ssl'] or p.get('port') in [443, 8443]]

            if https_ports:
                info['tls_audits'] = []
                for port_info in https_ports:
                    ip = info.get('ip')
                    port = port_info.get('port', 443)

                    try:
                        tls_analyzer = TLSAnalyzer(ip, port)
                        tls_results = tls_analyzer.analyze()
                        info['tls_audits'].append(tls_results)

                        if not args.json_only:
                            grade = tls_results.get('grade', 'F')
                            score = tls_results.get('score', 0)
                            if USE_RICH:
                                console.print(f"  [{ip}:{port}] TLS Grade: [bold]{grade}[/bold] (Score: {score}/100)")
                            else:
                                print(f"  [{ip}:{port}] TLS Grade: {grade} (Score: {score}/100)")
                    except Exception as e:
                        if not args.json_only:
                            if USE_RICH:
                                console.print(f"  [yellow][!] TLS audit failed for {ip}:{port}: {e}[/yellow]")
                            else:
                                print(f"  [!] TLS audit failed for {ip}:{port}: {e}")

    # Geolocation - Public IP Mode
    if args.geolocate_public and GEOLOCATION_AVAILABLE:
        # Get public IP
        public_ip = get_public_ip()

        if public_ip:
            try:
                geolocator = GeoLocator()
                geo_data = geolocator.locate(public_ip)

                if not args.json_only:
                    if geo_data.get('error'):
                        if USE_RICH:
                            console.print(f"\n[yellow]Failed to geolocate {public_ip}: {geo_data.get('error')}[/yellow]")
                        else:
                            print(f"\nFailed to geolocate {public_ip}: {geo_data.get('error')}")
                    else:
                        # Helper: Country code to flag emoji
                        def country_flag(country_code):
                            if not country_code or len(country_code) != 2:
                                return ""
                            # Convert country code to regional indicator symbols
                            return "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in country_code.upper())

                        # Reverse DNS lookup
                        reverse_dns = "Not available"
                        try:
                            import socket
                            reverse_dns = socket.gethostbyaddr(public_ip)[0]
                        except:
                            pass

                        # Extract data
                        city = geo_data.get('city', 'Unknown')
                        region = geo_data.get('region', 'Unknown')
                        country = geo_data.get('country', 'Unknown')
                        country_code = geo_data.get('countryCode', '??')
                        lat = geo_data.get('lat')
                        lon = geo_data.get('lon')
                        isp = geo_data.get('isp', 'Unknown')
                        org = geo_data.get('org', 'Unknown')
                        timezone = geo_data.get('timezone', 'Unknown')
                        zip_code = geo_data.get('zip', 'N/A')
                        as_number = geo_data.get('as', 'N/A')
                        flag = country_flag(country_code)

                        # Google Maps link
                        maps_link = f"https://maps.google.com/?q={lat},{lon}" if lat and lon else "N/A"

                        # Build beautiful output (Option 5 style)
                        separator = "═" * 79

                        if USE_RICH:
                            console.print(f"\n[bold cyan]{separator}[/bold cyan]")
                            console.print(f"[bold cyan]{'':^27}🌍 PUBLIC IP GEOLOCATION{'':^27}[/bold cyan]")
                            console.print(f"[bold cyan]{separator}[/bold cyan]\n")

                            console.print(f"[bold green]📍 LOCATION DETAILS[/bold green]")
                            console.print(f"  [cyan]Public IP:[/cyan]      {public_ip}")
                            console.print(f"  [cyan]Location:[/cyan]       {city}, {region}, {country} {flag}")
                            if lat and lon:
                                console.print(f"  [cyan]Coordinates:[/cyan]    {lat}, {lon}")
                                console.print(f"  [cyan]Google Maps:[/cyan]    [link={maps_link}]{maps_link}[/link]")
                            console.print(f"  [cyan]Reverse DNS:[/cyan]    {reverse_dns}\n")

                            console.print(f"[bold green]🌐 NETWORK PROVIDER[/bold green]")
                            console.print(f"  [cyan]ISP:[/cyan]            {isp}")
                            console.print(f"  [cyan]Organization:[/cyan]   {org}")
                            console.print(f"  [cyan]AS Number:[/cyan]      {as_number}")
                            console.print(f"  [cyan]Timezone:[/cyan]       {timezone}")
                            console.print(f"  [cyan]ZIP Code:[/cyan]       {zip_code}\n")

                            # Network flags
                            flags = []
                            if geo_data.get('mobile'):
                                flags.append('📱 Mobile')
                            if geo_data.get('proxy'):
                                flags.append('🔒 Proxy')
                            if geo_data.get('hosting'):
                                flags.append('☁️ Hosting')

                            if flags:
                                console.print(f"[bold yellow]⚠️  NETWORK FLAGS[/bold yellow]")
                                console.print(f"  {', '.join(flags)}\n")

                            # Count devices
                            device_count = len(rows)
                            console.print(f"[bold blue]ℹ️  IMPORTANT:[/bold blue] All {device_count} device(s) on this network share this Internet location")
                            console.print(f"[dim]             (NAT translates 192.168.1.x → {public_ip})[/dim]\n")

                            console.print(f"[bold cyan]{separator}[/bold cyan]")
                        else:
                            print(f"\n{separator}")
                            print(f"{'':^27}🌍 PUBLIC IP GEOLOCATION{'':^27}")
                            print(f"{separator}\n")

                            print(f"📍 LOCATION DETAILS")
                            print(f"  Public IP:      {public_ip}")
                            print(f"  Location:       {city}, {region}, {country} {flag}")
                            if lat and lon:
                                print(f"  Coordinates:    {lat}, {lon}")
                                print(f"  Google Maps:    {maps_link}")
                            print(f"  Reverse DNS:    {reverse_dns}\n")

                            print(f"🌐 NETWORK PROVIDER")
                            print(f"  ISP:            {isp}")
                            print(f"  Organization:   {org}")
                            print(f"  AS Number:      {as_number}")
                            print(f"  Timezone:       {timezone}")
                            print(f"  ZIP Code:       {zip_code}\n")

                            # Network flags
                            flags = []
                            if geo_data.get('mobile'):
                                flags.append('📱 Mobile')
                            if geo_data.get('proxy'):
                                flags.append('🔒 Proxy')
                            if geo_data.get('hosting'):
                                flags.append('☁️ Hosting')

                            if flags:
                                print(f"⚠️  NETWORK FLAGS")
                                print(f"  {', '.join(flags)}\n")

                            device_count = len(rows)
                            print(f"ℹ️  IMPORTANT: All {device_count} device(s) on this network share this Internet location")
                            print(f"             (NAT translates 192.168.1.x → {public_ip})\n")

                            print(f"{separator}")

                # Add to ALL hosts for JSON/PDF output
                for _, info in rows:
                    info['public_ip_geolocation'] = geo_data
                    info['public_ip'] = public_ip

            except Exception as e:
                if not args.json_only:
                    if USE_RICH:
                        console.print(f"\n[yellow][!] Public IP geolocation failed: {e}[/yellow]")
                    else:
                        print(f"\n[!] Public IP geolocation failed: {e}")
        else:
            if not args.json_only:
                if USE_RICH:
                    console.print("\n[yellow][!] Could not determine public IP address[/yellow]")
                else:
                    print("\n[!] Could not determine public IP address")

    # Geolocation - Per-IP Mode
    elif args.geolocate and GEOLOCATION_AVAILABLE:
        if not args.json_only:
            if USE_RICH:
                console.print("\n[cyan]🌍 Geolocating IP addresses...[/cyan]")
            else:
                print("\n[*] Geolocating IP addresses...")

        geolocator = GeoLocator()

        # Helper to detect private IPs
        def is_private_ip(ip_str):
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            try:
                first = int(parts[0])
                second = int(parts[1])
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
                if first == 127:
                    return True
            except:
                pass
            return False

        for _, info in rows:
            ip = info.get('ip')
            try:
                geo_data = geolocator.locate(ip)
                info['geolocation'] = geo_data

                if not args.json_only:
                    # Check if this is a private IP
                    if is_private_ip(ip):
                        if USE_RICH:
                            console.print(f"  [yellow]{ip}: Private IP (RFC 1918) - Not geolocatable[/yellow]")
                        else:
                            print(f"  {ip}: Private IP (RFC 1918) - Not geolocatable")
                    elif geo_data.get('error'):
                        if USE_RICH:
                            console.print(f"  [yellow]{ip}: Geolocation failed - {geo_data.get('error')}[/yellow]")
                        else:
                            print(f"  {ip}: Geolocation failed - {geo_data.get('error')}")
                    else:
                        # Show detailed geolocation information
                        city = geo_data.get('city', 'Unknown')
                        region = geo_data.get('region', 'Unknown')
                        country = geo_data.get('country', 'Unknown')
                        country_code = geo_data.get('countryCode', '??')
                        lat = geo_data.get('lat')
                        lon = geo_data.get('lon')
                        isp = geo_data.get('isp', 'Unknown')

                        location_str = f"{ip}: {city}, {region}, {country} ({country_code})"
                        if lat and lon:
                            location_str += f" | Coordinates: {lat}, {lon}"
                        location_str += f" | ISP: {isp}"

                        if USE_RICH:
                            console.print(f"  [green]{location_str}[/green]")
                        else:
                            print(f"  {location_str}")

                        # Show additional details if available
                        if geo_data.get('timezone'):
                            extra = f"    Timezone: {geo_data['timezone']}"
                            if geo_data.get('zip'):
                                extra += f", ZIP: {geo_data['zip']}"
                            if USE_RICH:
                                console.print(f"  [dim]{extra}[/dim]")
                            else:
                                print(f"  {extra}")

                        # Show flags
                        flags = []
                        if geo_data.get('mobile'):
                            flags.append('📱 Mobile')
                        if geo_data.get('proxy'):
                            flags.append('🔒 Proxy')
                        if geo_data.get('hosting'):
                            flags.append('☁️ Hosting')

                        if flags:
                            flags_str = "    Flags: " + ", ".join(flags)
                            if USE_RICH:
                                console.print(f"  [dim]{flags_str}[/dim]")
                            else:
                                print(f"  {flags_str}")

            except Exception as e:
                if not args.json_only:
                    if USE_RICH:
                        console.print(f"  [yellow][!] Geolocation failed for {ip}: {e}[/yellow]")
                    else:
                        print(f"  [!] Geolocation failed for {ip}: {e}")

    # Exploit Mapping
    if args.show_exploits and args.cve_check and EXPLOIT_MAPPING_AVAILABLE:
        if not args.json_only:
            if USE_RICH:
                console.print("\n[cyan]💣 Finding exploits for detected CVEs...[/cyan]")
            else:
                print("\n[*] Finding exploits for detected CVEs...")

        exploit_mapper = ExploitMapper()

        for _, info in rows:
            cve_findings = info.get('cves', [])
            if cve_findings:
                info['exploits'] = []
                for finding in cve_findings:
                    for cve in finding.get('cves', []):
                        cve_id = cve.get('cve_id')
                        if cve_id:
                            try:
                                exploit_data = exploit_mapper.find_exploits(cve_id)
                                if exploit_data.get('exploits'):
                                    info['exploits'].append(exploit_data)
                                    if not args.json_only:
                                        exploit_count = len(exploit_data['exploits'])
                                        if USE_RICH:
                                            console.print(f"  [red]💣 {cve_id}: {exploit_count} exploit(s) available[/red]")
                                        else:
                                            print(f"  💣 {cve_id}: {exploit_count} exploit(s) available")
                            except Exception:
                                pass

    # ========== END v1.0.0 ADVANCED ANALYSIS FEATURES ==========

    # Run spoof detection (v2.0.0 correlation engine) if requested
    if args.spoof_check:
        if not CORRELATION_AVAILABLE:
            if not args.json_only:
                if USE_RICH:
                    console.print("\n[yellow]⚠️  Correlation engine not available - skipping spoof check[/yellow]")
                    console.print("[yellow]   (net-inspect-v2-correlation-engine.py not found)[/yellow]")
                else:
                    print("\n⚠️  Correlation engine not available - skipping spoof check")
                    print("   (net-inspect-v2-correlation-engine.py not found)")
        else:
            # Build scan results in correlation engine format
            scan_results = {
                "scan_id": scan_id,
                "iface": iface,
                "cidrs": cidrs,
                "timestamp": datetime.now().isoformat(),
                "hosts": []
            }
            for _, r in rows:
                scan_results["hosts"].append({
                    "hostname": r.get("hostname") or "-",
                    "ip": r.get("ip"),
                    "cidr": r.get("cidr") or "-",
                    "mac": r.get("mac") or "-",
                    "vendor": r.get("vendor") or "-",
                    "os": r.get("os") or "-",
                    "risk": r.get("risk") or 0,
                    "flags": r.get("flags", []),
                    "devtype": r.get("devtype") or "-",
                    "ports": r.get("ports", [])
                })

            # Run correlation analysis
            if not args.json_only:
                if USE_RICH:
                    console.print("\n[cyan]🔍 Running spoof detection analysis...[/cyan]")
                else:
                    print("\n🔍 Running spoof detection analysis...")

            try:
                engine = CorrelationEngine()
                engine.ingest_scan_data(scan_results)
                scored_hosts = engine.compute_spoof_scores()

                # Display results (same format as standalone correlation engine)
                if not args.json_only:
                    # Count by risk level
                    critical_count = sum(1 for h in scored_hosts if h['spoof_score'] >= 75)
                    high_count = sum(1 for h in scored_hosts if 50 <= h['spoof_score'] < 75)
                    medium_count = sum(1 for h in scored_hosts if 25 <= h['spoof_score'] < 50)
                    low_count = sum(1 for h in scored_hosts if h['spoof_score'] < 25)

                    print(f"\n📋 Spoof Detection Analysis - {len(scored_hosts)} Host(s)")
                    print("="*80)
                    print(f"\n  🔴 CRITICAL: {critical_count}  |  🟠 HIGH: {high_count}  |  🟡 MEDIUM: {medium_count}  |  🟢 LOW: {low_count}")
                    print("="*80)

                    # Display all hosts (sorted by spoof score, highest first)
                    for idx, host in enumerate(scored_hosts, 1):
                        score = host['spoof_score']
                        risk = host['risk_level']

                        # Color-code risk level
                        if risk == 'CRITICAL':
                            risk_icon = '🔴'
                            risk_color = '\033[91m'  # Red
                        elif risk == 'HIGH':
                            risk_icon = '🟠'
                            risk_color = '\033[93m'  # Yellow/Orange
                        elif risk == 'MEDIUM':
                            risk_icon = '🟡'
                            risk_color = '\033[93m'  # Yellow
                        else:
                            risk_icon = '🟢'
                            risk_color = '\033[92m'  # Green

                        reset_color = '\033[0m'

                        print(f"\n{'─'*80}")
                        print(f"[{idx}/{len(scored_hosts)}] {host['ip']} ({host.get('hostname', 'unknown')})")
                        print(f"{'─'*80}")
                        print(f"  MAC Address:    {host['mac']}")

                        # Show vendor/OS if available
                        vendor = host.get('vendor', 'Unknown')
                        if vendor != 'Unknown':
                            print(f"  Vendor:         {vendor}")

                        # Spoof score with visual bar
                        bar_length = 40
                        filled = int((score / 100) * bar_length)
                        bar = '█' * filled + '░' * (bar_length - filled)
                        print(f"  Spoof Score:    {risk_color}{score:.1f}/100{reset_color} {risk_icon} {risk}")
                        print(f"                  [{bar}]")

                        # Show top contributing factors
                        top_factors = host['breakdown']['top_contributors']
                        if any(score > 0 for _, score in top_factors):
                            print(f"  Top Indicators:")
                            for factor, factor_score in top_factors:
                                if factor_score > 0:
                                    # Map factor names to readable descriptions
                                    factor_names = {
                                        'layer2': 'Layer 2 (MAC/Vendor mismatch)',
                                        'dhcp': 'DHCP (Hostname inconsistency)',
                                        'fingerprint': 'Fingerprint (JA3/HTTP similarity)',
                                        'stack': 'Stack (TTL/TCP mismatch)',
                                        'behavioral': 'Behavioral (Clock skew/timing)',
                                        'baseline': 'Baseline (New/changed device)'
                                    }
                                    factor_desc = factor_names.get(factor, factor)
                                    pct = (factor_score / score * 100) if score > 0 else 0
                                    print(f"    • {factor_desc}: {factor_score:.1f} ({pct:.0f}%)")
                        else:
                            print(f"  Assessment:     ✓ No anomalies detected")

                    # Summary footer
                    print(f"\n{'='*80}")
                    suspicious_count = critical_count + high_count
                    if suspicious_count == 0:
                        print(f"✓ CLEAN - All {len(scored_hosts)} host(s) appear legitimate (scores < 50)")
                    else:
                        print(f"⚠️  WARNING - {suspicious_count} suspicious host(s) detected (scores ≥ 50)")
                        if critical_count > 0:
                            print(f"   🔴 {critical_count} CRITICAL risk host(s) require immediate investigation")
                        if high_count > 0:
                            print(f"   🟠 {high_count} HIGH risk host(s) require monitoring")

                    if medium_count > 0:
                        print(f"   🟡 {medium_count} host(s) with minor anomalies - monitor for changes")

                    print("="*80)
                    print()  # Extra line break before regular output

            except Exception as e:
                if not args.json_only:
                    if USE_RICH:
                        console.print(f"\n[red]❌ Correlation engine error: {e}[/red]")
                    else:
                        print(f"\n❌ Correlation engine error: {e}")

    # Handle JSON-only output mode (early exit)
    if args.json_only:
        output_json_only(rows, scan_id, iface, cidrs)
        # Handle save if requested (quiet mode to not pollute JSON output)
        if args.save or args.save_all:
            save_results(scan_id, iface, cidrs, rows, args.save_all, quiet=True)
        sys.exit(0)
    
    show_cidr_summary(cidr_devices_map, host_infos)
    show_summary_table(scan_id, iface, cidrs, rows)
    criticals = [r for _, r in rows if r.get("risk", 0) >= 60]
    if USE_RICH:
        console.print("\n[bold]Quick notes:[/bold]")
        if criticals: console.print(" • Hosts flagged RED (RISK ≥ 60): " + ", ".join([c["ip"] for c in criticals]))
        else: console.print(" • No hosts flagged critical.")
        console.print(" • To view details for a host, type its # and press Enter (interactive mode).")
        console.print(" • Press 's' at any time to toggle Save options at end-of-scan.")
    else:
        print("\nQuick notes:")
        if criticals: print(" • Hosts flagged RED (RISK ≥ 60): " + ", ".join([c["ip"] for c in criticals]))
        else: print(" • No hosts flagged critical.")
    if args.map: show_network_map(cidr_devices_map, host_infos)
    if args.threats: show_threat_assessment(cidr_devices_map, host_infos)
    if args.cve_check: show_cve_check(host_infos, cve_checker)
    
    # Build and display vulnerability report (enhanced in v1.0.0 with real CVE data)
    if args.vuln_report != "off":
        vulns = build_vulnerability_list(host_infos, cve_checker if args.cve_check else None)
        if args.vuln_report == "quick":
            show_vulnerability_summary_quick(vulns)
        elif args.vuln_report == "professional":
            show_vulnerability_summary_professional(vulns)
        elif args.vuln_report == "enterprise":
            show_vulnerability_summary_enterprise(vulns)
    
    total = len(rows)
    print() # Blank line before detailed host views
    for idx, info in rows:
        show_detailed_host_view(idx, total, info, scan_id, cve_checker if args.cve_check else None)
    show_progress_and_timers(len(rows), probes_done)
    show_scan_summary(scan_id, rows, start)
    
    # Stop all packet captures and show summary
    if args.capture or global_capture_id:
        if USE_RICH: console.print("[cyan]🛑 Stopping packet captures...[/cyan]")
        else: print("Stopping packet captures...")
        captures = stop_all_captures()
        if captures:
            show_capture_summary(captures)

    # Analyze traffic if requested (NEW v1.0.0)
    if args.analyze_traffic and global_capture_id:
        # Get the actual PCAP file path from tcpdump_processes
        current_pcap = tcpdump_processes.get(global_capture_id, {}).get("file") if global_capture_id in tcpdump_processes else None

        if current_pcap and os.path.exists(current_pcap) and TRAFFIC_ANALYSIS_AVAILABLE:
            if not args.json_only:
                if USE_RICH:
                    console.print("\n[cyan]📊 Analyzing captured traffic...[/cyan]")
                else:
                    print("\n[*] Analyzing captured traffic...")
            try:
                analyzer = TrafficAnalyzer(current_pcap, verbose=not args.json_only)
                traffic_results = analyzer.analyze()

                if not args.json_only:
                    summary = analyzer.get_summary()
                    if USE_RICH:
                        console.print(summary)
                    else:
                        print(summary)

                # Add to each host's info
                for _, info in rows:
                    info['traffic_analysis'] = traffic_results
            except Exception as e:
                if not args.json_only:
                    if USE_RICH:
                        console.print(f"[yellow][!] Traffic analysis failed: {e}[/yellow]")
                    else:
                        print(f"[!] Traffic analysis failed: {e}")
        elif args.analyze_traffic and not TRAFFIC_ANALYSIS_AVAILABLE:
            if not args.json_only:
                if USE_RICH:
                    console.print("[yellow][!] Traffic analysis requires Scapy. Install with: pip install scapy[/yellow]")
                else:
                    print("[!] Traffic analysis requires Scapy. Install with: pip install scapy")

    if args.save_baseline: save_baseline(scan_id, rows, cidrs)
    if args.compare_baseline: compare_baseline(rows, cidrs)
    save_now = args.save or args.save_all
    if not save_now:
        if USE_RICH:
            console.print("\n[bold]INTERACTIVE PROMPT (end-of-scan)[/bold]")
            console.print("[1] Save summary (CSV + JSON)")
            console.print("[2] Save summary + raw XML (if available)")
            console.print("[3] Discard (do not save)  ← default")
            choice = Prompt.ask("Choice", choices=["1","2","3"], default="3")
        else:
            print("\nINTERACTIVE PROMPT (end-of-scan)")
            print("[1] Save summary (CSV + JSON)")
            print("[2] Save summary + raw XML (if available)")
            print("[3] Discard (do not save)  ← default")
            choice = input("Choice [1/2/3] (3): ").strip() or "3"
        if choice == "1": save_now = True
        elif choice == "2": save_now, args.save_all = True, True
    if save_now: save_results(scan_id, iface, cidrs, rows, args.save_all)
    else:
        if USE_RICH: console.print("\n[cyan]Ephemeral run — no files written.[/cyan]")
        else: print("\nEphemeral run — no files written.")
    show_risk_legend()
    show_tips()

    # Generate PDF report if requested (NEW v1.0.0)
    if args.report_pdf and REPORTLAB_AVAILABLE:
        if not args.json_only:
            if USE_RICH:
                console.print(f"\n[cyan]📄 Generating PDF report: {args.report_pdf}[/cyan]")
            else:
                print(f"\n[*] Generating PDF report: {args.report_pdf}")
        try:
            # Prepare scan data
            scan_data = {
                'scan_id': scan_id,
                'timestamp': start.isoformat(),
                'interface': iface,
                'cidrs': cidrs,
                'hosts': [info for _, info in rows]
            }

            generate_pdf_report(scan_data, args.report_pdf, args.report_format)
            if not args.json_only:
                if USE_RICH:
                    console.print(f"  [green]✅ PDF report saved: {args.report_pdf}[/green]")
                else:
                    print(f"  ✅ PDF report saved: {args.report_pdf}")
        except Exception as e:
            if not args.json_only:
                if USE_RICH:
                    console.print(f"  [yellow][!] PDF generation failed: {e}[/yellow]")
                else:
                    print(f"  [!] PDF generation failed: {e}")
    elif args.report_pdf and not REPORTLAB_AVAILABLE:
        if not args.json_only:
            if USE_RICH:
                console.print("[yellow][!] PDF reports require reportlab. Install with: pip install reportlab[/yellow]")
            else:
                print("[!] PDF reports require reportlab. Install with: pip install reportlab")

    if USE_RICH: console.print("\n[bold green]✅ Scan complete![/bold green]")
    else: print("\n✅ Scan complete!")

if __name__ == "__main__":
    main()
