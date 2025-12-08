#!/usr/bin/env python3
"""
Threat Intelligence Integration for net-inspect
Integrates with AbuseIPDB, VirusTotal, Shodan, and MISP
"""

import os
import time
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ThreatIntelChecker:
    """
    Multi-source threat intelligence checker.

    Supported sources:
    - AbuseIPDB (IP reputation)
    - VirusTotal (IP/domain reputation)
    - Shodan (public exposure check)
    - MISP (optional, for enterprise)
    """

    def __init__(self,
                 abuseipdb_key: Optional[str] = None,
                 virustotal_key: Optional[str] = None,
                 shodan_key: Optional[str] = None,
                 cache_duration: int = 86400):  # 24 hours
        """
        Initialize Threat Intel Checker.

        Args:
            abuseipdb_key: AbuseIPDB API key
            virustotal_key: VirusTotal API key
            shodan_key: Shodan API key
            cache_duration: Cache duration in seconds (default: 24 hours)
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("Threat intelligence requires 'requests' library")

        self.abuseipdb_key = abuseipdb_key or os.environ.get('ABUSEIPDB_API_KEY')
        self.virustotal_key = virustotal_key or os.environ.get('VIRUSTOTAL_API_KEY')
        self.shodan_key = shodan_key or os.environ.get('SHODAN_API_KEY')
        self.cache_duration = cache_duration

        # Setup cache directory
        self.cache_dir = Path.home() / ".cache" / "net-inspect" / "threat-intel"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Rate limiting
        self.last_abuseipdb_call = 0
        self.last_virustotal_call = 0
        self.last_shodan_call = 0

        # API endpoints
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        self.virustotal_url = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        self.shodan_url = "https://api.shodan.io/shodan/host/{ip}"

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP against all configured threat intel sources.

        Args:
            ip: IP address to check

        Returns:
            Dictionary with threat intel results
        """
        results = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'overall_risk': 'CLEAN',
            'risk_score': 0,
            'is_malicious': False,
            'warnings': []
        }

        # Check cache first
        cached = self._read_cache(ip)
        if cached:
            return cached

        # AbuseIPDB check
        if self.abuseipdb_key:
            try:
                abuseipdb_data = self._check_abuseipdb(ip)
                results['sources']['abuseipdb'] = abuseipdb_data

                # Update risk based on AbuseIPDB
                abuse_score = abuseipdb_data.get('abuseConfidenceScore', 0)
                if abuse_score >= 75:
                    results['is_malicious'] = True
                    results['overall_risk'] = 'CRITICAL'
                    results['risk_score'] = max(results['risk_score'], 90)
                elif abuse_score >= 50:
                    results['overall_risk'] = 'HIGH' if results['overall_risk'] == 'CLEAN' else results['overall_risk']
                    results['risk_score'] = max(results['risk_score'], 70)
                elif abuse_score >= 25:
                    results['overall_risk'] = 'MEDIUM' if results['overall_risk'] == 'CLEAN' else results['overall_risk']
                    results['risk_score'] = max(results['risk_score'], 50)

            except Exception as e:
                results['warnings'].append(f"AbuseIPDB check failed: {e}")

        # VirusTotal check
        if self.virustotal_key:
            try:
                virustotal_data = self._check_virustotal(ip)
                results['sources']['virustotal'] = virustotal_data

                # Update risk based on VirusTotal
                malicious_count = virustotal_data.get('malicious', 0)
                if malicious_count >= 5:
                    results['is_malicious'] = True
                    results['overall_risk'] = 'CRITICAL'
                    results['risk_score'] = max(results['risk_score'], 85)
                elif malicious_count >= 2:
                    results['overall_risk'] = 'HIGH' if results['overall_risk'] in ['CLEAN', 'MEDIUM'] else results['overall_risk']
                    results['risk_score'] = max(results['risk_score'], 65)

            except Exception as e:
                results['warnings'].append(f"VirusTotal check failed: {e}")

        # Shodan check
        if self.shodan_key:
            try:
                shodan_data = self._check_shodan(ip)
                results['sources']['shodan'] = shodan_data

                # Shodan doesn't indicate malicious, but shows public exposure
                if shodan_data.get('found'):
                    results['warnings'].append(f"IP appears in Shodan (publicly scanned)")

            except Exception as e:
                results['warnings'].append(f"Shodan check failed: {e}")

        # Cache results
        self._write_cache(ip, results)

        return results

    def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP against AbuseIPDB."""
        self._rate_limit('abuseipdb', 1)  # 1 request per second (free tier)

        headers = {
            'Key': self.abuseipdb_key,
            'Accept': 'application/json'
        }

        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': ''
        }

        response = requests.get(self.abuseipdb_url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                'totalReports': data.get('totalReports', 0),
                'numDistinctUsers': data.get('numDistinctUsers', 0),
                'lastReportedAt': data.get('lastReportedAt'),
                'countryCode': data.get('countryCode'),
                'isp': data.get('isp'),
                'domain': data.get('domain'),
                'isWhitelisted': data.get('isWhitelisted', False)
            }
        elif response.status_code == 429:
            raise Exception("Rate limit exceeded")
        else:
            raise Exception(f"HTTP {response.status_code}")

    def _check_virustotal(self, ip: str) -> Dict[str, Any]:
        """Check IP against VirusTotal."""
        self._rate_limit('virustotal', 15)  # 4 requests per minute (free tier)

        headers = {
            'x-apikey': self.virustotal_key
        }

        url = self.virustotal_url.format(ip=ip)
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})

            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_vendors': sum(stats.values()),
                'reputation': attributes.get('reputation', 0),
                'country': attributes.get('country'),
                'as_owner': attributes.get('as_owner')
            }
        elif response.status_code == 429:
            raise Exception("Rate limit exceeded")
        elif response.status_code == 404:
            return {'malicious': 0, 'note': 'IP not found in VirusTotal'}
        else:
            raise Exception(f"HTTP {response.status_code}")

    def _check_shodan(self, ip: str) -> Dict[str, Any]:
        """Check IP against Shodan."""
        self._rate_limit('shodan', 1)  # 1 request per second

        url = self.shodan_url.format(ip=ip)
        params = {'key': self.shodan_key}

        response = requests.get(url, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()
            return {
                'found': True,
                'ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'org': data.get('org'),
                'isp': data.get('isp'),
                'country': data.get('country_name'),
                'city': data.get('city'),
                'last_update': data.get('last_update'),
                'vulns': list(data.get('vulns', [])) if data.get('vulns') else []
            }
        elif response.status_code == 404:
            return {'found': False, 'note': 'IP not found in Shodan'}
        else:
            raise Exception(f"HTTP {response.status_code}")

    def _rate_limit(self, source: str, delay: float):
        """Enforce rate limiting for API calls."""
        if source == 'abuseipdb':
            elapsed = time.time() - self.last_abuseipdb_call
            if elapsed < delay:
                time.sleep(delay - elapsed)
            self.last_abuseipdb_call = time.time()

        elif source == 'virustotal':
            elapsed = time.time() - self.last_virustotal_call
            if elapsed < delay:
                time.sleep(delay - elapsed)
            self.last_virustotal_call = time.time()

        elif source == 'shodan':
            elapsed = time.time() - self.last_shodan_call
            if elapsed < delay:
                time.sleep(delay - elapsed)
            self.last_shodan_call = time.time()

    def _get_cache_key(self, ip: str) -> str:
        """Generate cache filename for IP."""
        hash_key = hashlib.md5(ip.encode()).hexdigest()
        return f"threat_intel_{hash_key}.json"

    def _read_cache(self, ip: str) -> Optional[Dict]:
        """Read threat intel data from cache if fresh."""
        cache_file = self.cache_dir / self._get_cache_key(ip)

        if not cache_file.exists():
            return None

        # Check age
        age_seconds = time.time() - cache_file.stat().st_mtime

        if age_seconds > self.cache_duration:
            return None

        # Load cached data
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except:
            return None

    def _write_cache(self, ip: str, data: Dict):
        """Write threat intel data to cache."""
        cache_file = self.cache_dir / self._get_cache_key(ip)
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Non-critical if cache write fails

    def check_bulk(self, ips: List[str], progress_callback=None) -> Dict[str, Dict]:
        """
        Check multiple IPs (with progress tracking).

        Args:
            ips: List of IP addresses
            progress_callback: Optional callback function(current, total)

        Returns:
            Dictionary mapping IP -> threat intel results
        """
        results = {}

        for i, ip in enumerate(ips, 1):
            try:
                results[ip] = self.check_ip(ip)

                if progress_callback:
                    progress_callback(i, len(ips))

            except Exception as e:
                results[ip] = {
                    'ip': ip,
                    'error': str(e),
                    'overall_risk': 'UNKNOWN'
                }

        return results

    def format_report(self, intel_data: Dict[str, Any]) -> str:
        """Generate human-readable threat intel report."""
        lines = []
        lines.append("=" * 80)
        lines.append(f"THREAT INTELLIGENCE: {intel_data['ip']}")
        lines.append("=" * 80)

        # Overall assessment
        risk_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'CLEAN': '🟢'}.get(intel_data['overall_risk'], '⚪')
        lines.append(f"\n{risk_icon} OVERALL RISK: {intel_data['overall_risk']} (Score: {intel_data['risk_score']}/100)")

        if intel_data['is_malicious']:
            lines.append("⚠️  WARNING: IP flagged as MALICIOUS by threat intelligence sources")

        # AbuseIPDB
        if 'abuseipdb' in intel_data['sources']:
            abuse = intel_data['sources']['abuseipdb']
            lines.append(f"\n[AbuseIPDB]")
            lines.append(f"  Abuse Confidence: {abuse['abuseConfidenceScore']}%")
            lines.append(f"  Total Reports: {abuse['totalReports']}")
            if abuse['lastReportedAt']:
                lines.append(f"  Last Report: {abuse['lastReportedAt']}")
            if abuse['isp']:
                lines.append(f"  ISP: {abuse['isp']}")
            if abuse['isWhitelisted']:
                lines.append(f"  ✓ Whitelisted")

        # VirusTotal
        if 'virustotal' in intel_data['sources']:
            vt = intel_data['sources']['virustotal']
            if 'note' not in vt:
                lines.append(f"\n[VirusTotal]")
                lines.append(f"  Malicious: {vt['malicious']}/{vt['total_vendors']} vendors")
                lines.append(f"  Suspicious: {vt['suspicious']}")
                lines.append(f"  Reputation: {vt['reputation']}")
                if vt.get('as_owner'):
                    lines.append(f"  AS Owner: {vt['as_owner']}")

        # Shodan
        if 'shodan' in intel_data['sources']:
            shodan = intel_data['sources']['shodan']
            if shodan.get('found'):
                lines.append(f"\n[Shodan]")
                lines.append(f"  ⚠️  IP appears in public Shodan scans")
                if shodan.get('ports'):
                    lines.append(f"  Open Ports: {', '.join(map(str, shodan['ports'][:10]))}")
                if shodan.get('org'):
                    lines.append(f"  Organization: {shodan['org']}")
                if shodan.get('vulns'):
                    lines.append(f"  Known Vulns: {', '.join(shodan['vulns'][:5])}")

        # Warnings
        if intel_data['warnings']:
            lines.append(f"\n[Warnings]")
            for warning in intel_data['warnings']:
                lines.append(f"  • {warning}")

        lines.append("\n" + "=" * 80)

        return "\n".join(lines)


def check_threat_intel(ip: str,
                      abuseipdb_key: Optional[str] = None,
                      virustotal_key: Optional[str] = None,
                      shodan_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to check single IP.

    Args:
        ip: IP address to check
        abuseipdb_key: AbuseIPDB API key
        virustotal_key: VirusTotal API key
        shodan_key: Shodan API key

    Returns:
        Threat intelligence results
    """
    checker = ThreatIntelChecker(
        abuseipdb_key=abuseipdb_key,
        virustotal_key=virustotal_key,
        shodan_key=shodan_key
    )

    return checker.check_ip(ip)
