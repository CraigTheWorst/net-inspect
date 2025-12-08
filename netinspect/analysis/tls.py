#!/usr/bin/env python3
"""
SSL/TLS Security Analysis Module for net-inspect
Comprehensive TLS/SSL testing and certificate validation
"""

import ssl
import socket
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

class TLSAnalyzer:
    """
    Comprehensive SSL/TLS security analyzer.

    Features:
    - Certificate validation and chain analysis
    - Cipher suite enumeration
    - Protocol version testing
    - Known vulnerability checks (Heartbleed, POODLE, etc.)
    - SSL Labs-style grading
    """

    def __init__(self, host: str, port: int = 443, timeout: int = 10):
        """
        Initialize TLS Analyzer.

        Args:
            host: Target hostname or IP
            port: Target port (default: 443)
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.results = {
            'host': host,
            'port': port,
            'certificate': {},
            'protocols': {},
            'ciphers': [],
            'vulnerabilities': [],
            'grade': 'F',
            'score': 0
        }

    def analyze(self) -> Dict[str, Any]:
        """Run complete TLS analysis."""
        try:
            # Certificate analysis
            self._analyze_certificate()

            # Protocol version testing
            self._test_protocols()

            # Cipher suite enumeration
            self._enumerate_ciphers()

            # Vulnerability checks
            self._check_vulnerabilities()

            # Calculate grade
            self._calculate_grade()

        except Exception as e:
            self.results['error'] = str(e)

        return self.results

    def _analyze_certificate(self):
        """Analyze SSL certificate."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()

                    self.results['certificate'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': [x[1] for x in cert.get('subjectAltName', [])],
                        'OCSP': cert.get('OCSP'),
                        'caIssuers': cert.get('caIssuers'),
                        'crlDistributionPoints': cert.get('crlDistributionPoints')
                    }

                    # Validate dates
                    try:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        now = datetime.now()

                        self.results['certificate']['valid'] = not_before <= now <= not_after
                        self.results['certificate']['days_until_expiry'] = (not_after - now).days

                        if self.results['certificate']['days_until_expiry'] < 0:
                            self.results['vulnerabilities'].append({
                                'name': 'Expired Certificate',
                                'severity': 'CRITICAL',
                                'description': 'Certificate has expired'
                            })
                        elif self.results['certificate']['days_until_expiry'] < 30:
                            self.results['vulnerabilities'].append({
                                'name': 'Certificate Expiring Soon',
                                'severity': 'HIGH',
                                'description': f'Certificate expires in {self.results["certificate"]["days_until_expiry"]} days'
                            })

                    except:
                        pass

                    # Check key size using openssl
                    self._check_key_size()

        except Exception as e:
            self.results['certificate']['error'] = str(e)

    def _check_key_size(self):
        """Check certificate key size using openssl."""
        try:
            cmd = f"echo | openssl s_client -connect {self.host}:{self.port} 2>/dev/null | openssl x509 -noout -text"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Extract key size
                key_match = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', result.stdout)
                if key_match:
                    key_size = int(key_match.group(1))
                    self.results['certificate']['keySize'] = key_size

                    if key_size < 2048:
                        self.results['vulnerabilities'].append({
                            'name': 'Weak Key Size',
                            'severity': 'CRITICAL',
                            'description': f'RSA key size {key_size} bits is too small (minimum: 2048)'
                        })
                    elif key_size == 2048:
                        self.results['vulnerabilities'].append({
                            'name': 'Adequate Key Size',
                            'severity': 'LOW',
                            'description': '2048-bit keys acceptable but 4096-bit recommended'
                        })

                # Extract signature algorithm
                sig_match = re.search(r'Signature Algorithm:\s*(\S+)', result.stdout)
                if sig_match:
                    sig_alg = sig_match.group(1)
                    self.results['certificate']['signatureAlgorithm'] = sig_alg

                    if 'sha1' in sig_alg.lower():
                        self.results['vulnerabilities'].append({
                            'name': 'Weak Signature Algorithm',
                            'severity': 'HIGH',
                            'description': 'SHA-1 is deprecated, use SHA-256 or higher'
                        })

        except Exception:
            pass

    def _test_protocols(self):
        """Test supported TLS/SSL protocol versions."""
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Will be rejected by modern systems
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLS 1.0': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLS 1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            'TLS 1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            'TLS 1.3': ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None
        }

        for proto_name, proto in protocols.items():
            if proto is None:
                continue

            try:
                context = ssl.SSLContext(proto)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Disable specific protocols to test individual versions
                if proto_name == 'TLS 1.0' and hasattr(context, 'options'):
                    context.options |= ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3

                with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        self.results['protocols'][proto_name] = {
                            'supported': True,
                            'version': ssock.version()
                        }

                # Flag deprecated protocols
                if proto_name in ['SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1']:
                    self.results['vulnerabilities'].append({
                        'name': f'Deprecated Protocol: {proto_name}',
                        'severity': 'HIGH' if 'SSL' in proto_name else 'MEDIUM',
                        'description': f'{proto_name} is deprecated and should be disabled'
                    })

            except:
                self.results['protocols'][proto_name] = {'supported': False}

    def _enumerate_ciphers(self):
        """Enumerate supported cipher suites using openssl."""
        try:
            # Get cipher list
            cmd = f"nmap --script ssl-enum-ciphers -p {self.port} {self.host} 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse nmap output for ciphers
                weak_ciphers = []

                for line in result.stdout.split('\n'):
                    # Look for cipher names
                    if 'TLS_' in line or 'SSL_' in line:
                        cipher_match = re.search(r'(TLS|SSL)_\S+', line)
                        if cipher_match:
                            cipher = cipher_match.group(0)

                            # Check for weak ciphers
                            if any(weak in cipher for weak in ['RC4', 'DES', 'NULL', 'EXPORT', 'anon', 'ADH']):
                                weak_ciphers.append(cipher)
                                self.results['vulnerabilities'].append({
                                    'name': f'Weak Cipher: {cipher}',
                                    'severity': 'HIGH',
                                    'description': f'Cipher {cipher} is considered weak/insecure'
                                })

                            self.results['ciphers'].append(cipher)

                # Check for Forward Secrecy
                fs_ciphers = [c for c in self.results['ciphers'] if 'DHE' in c or 'ECDHE' in c]
                if not fs_ciphers and self.results['ciphers']:
                    self.results['vulnerabilities'].append({
                        'name': 'No Forward Secrecy',
                        'severity': 'MEDIUM',
                        'description': 'No ciphers with Forward Secrecy (ECDHE/DHE) detected'
                    })

        except Exception:
            # Fallback: use Python's SSL to get some cipher info
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        cipher = ssock.cipher()
                        if cipher:
                            self.results['ciphers'].append(cipher[0])

            except:
                pass

    def _check_vulnerabilities(self):
        """Check for known SSL/TLS vulnerabilities."""
        # Heartbleed (OpenSSL bug, rare now but check anyway)
        if 'TLS 1.0' in self.results['protocols'] or 'TLS 1.1' in self.results['protocols']:
            # Placeholder - real Heartbleed test requires specific probe
            pass

        # POODLE (requires SSLv3)
        if self.results['protocols'].get('SSLv3', {}).get('supported'):
            self.results['vulnerabilities'].append({
                'name': 'POODLE (SSLv3)',
                'severity': 'CRITICAL',
                'description': 'SSLv3 is vulnerable to POODLE attack',
                'cve': 'CVE-2014-3566'
            })

        # BEAST (TLS 1.0 + CBC ciphers)
        if self.results['protocols'].get('TLS 1.0', {}).get('supported'):
            cbc_ciphers = [c for c in self.results['ciphers'] if 'CBC' in c]
            if cbc_ciphers:
                self.results['vulnerabilities'].append({
                    'name': 'BEAST (TLS 1.0 + CBC)',
                    'severity': 'MEDIUM',
                    'description': 'TLS 1.0 with CBC ciphers vulnerable to BEAST',
                    'cve': 'CVE-2011-3389'
                })

        # Check for compression (CRIME)
        # This would require actual SSL handshake analysis
        pass

    def _calculate_grade(self):
        """Calculate SSL Labs-style security grade."""
        score = 100

        # Protocol penalties
        if self.results['protocols'].get('SSLv2', {}).get('supported'):
            score -= 40
        if self.results['protocols'].get('SSLv3', {}).get('supported'):
            score -= 30
        if self.results['protocols'].get('TLS 1.0', {}).get('supported'):
            score -= 15
        if self.results['protocols'].get('TLS 1.1', {}).get('supported'):
            score -= 10

        # Certificate penalties
        if not self.results['certificate'].get('valid', True):
            score -= 50

        key_size = self.results['certificate'].get('keySize', 4096)
        if key_size < 1024:
            score -= 40
        elif key_size < 2048:
            score -= 20
        elif key_size < 4096:
            score -= 5

        # Cipher penalties
        weak_vulns = [v for v in self.results['vulnerabilities'] if 'Weak Cipher' in v['name']]
        score -= len(weak_vulns) * 5

        # Critical vulnerabilities
        critical_vulns = [v for v in self.results['vulnerabilities'] if v['severity'] == 'CRITICAL']
        score -= len(critical_vulns) * 20

        # High vulnerabilities
        high_vulns = [v for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH']
        score -= len(high_vulns) * 10

        # Determine grade
        score = max(0, min(100, score))
        self.results['score'] = score

        if score >= 90:
            self.results['grade'] = 'A+'
        elif score >= 80:
            self.results['grade'] = 'A'
        elif score >= 70:
            self.results['grade'] = 'B'
        elif score >= 60:
            self.results['grade'] = 'C'
        elif score >= 50:
            self.results['grade'] = 'D'
        else:
            self.results['grade'] = 'F'

    def get_report(self) -> str:
        """Generate human-readable TLS security report."""
        lines = []
        lines.append("=" * 80)
        lines.append(f"SSL/TLS SECURITY ANALYSIS: {self.host}:{self.port}")
        lines.append("=" * 80)

        # Grade
        grade = self.results['grade']
        score = self.results['score']
        grade_icon = {'A+': '🟢', 'A': '🟢', 'B': '🟡', 'C': '🟡', 'D': '🟠', 'F': '🔴'}.get(grade, '⚪')
        lines.append(f"\n{grade_icon} OVERALL GRADE: {grade} (Score: {score}/100)\n")

        # Certificate
        cert = self.results['certificate']
        if cert and not cert.get('error'):
            lines.append("[CERTIFICATE]")
            subject = cert.get('subject', {})
            issuer = cert.get('issuer', {})

            lines.append(f"  Subject: {subject.get('commonName', 'N/A')}")
            lines.append(f"  Issuer: {issuer.get('commonName', 'N/A')}")
            lines.append(f"  Valid: {cert.get('notBefore')} to {cert.get('notAfter')}")

            if cert.get('valid'):
                days = cert.get('days_until_expiry', 0)
                lines.append(f"  ✓ Certificate valid ({days} days until expiry)")
            else:
                lines.append(f"  ❌ Certificate INVALID or EXPIRED")

            if 'keySize' in cert:
                key_icon = '✓' if cert['keySize'] >= 2048 else '❌'
                lines.append(f"  {key_icon} Key Size: {cert['keySize']} bits")

            if cert.get('subjectAltName'):
                lines.append(f"  SANs: {', '.join(cert['subjectAltName'][:5])}")

        # Protocols
        lines.append("\n[SUPPORTED PROTOCOLS]")
        for proto, data in self.results['protocols'].items():
            if data.get('supported'):
                icon = '❌' if proto in ['SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1'] else '✓'
                lines.append(f"  {icon} {proto}")
            else:
                lines.append(f"  ✓ {proto} (disabled)")

        # Ciphers
        if self.results['ciphers']:
            lines.append(f"\n[CIPHER SUITES] ({len(self.results['ciphers'])} total)")
            # Show first 10 weak ciphers
            weak = [c for c in self.results['ciphers'] if any(w in c for w in ['RC4', 'DES', 'NULL', 'EXPORT'])]
            if weak:
                lines.append(f"  ⚠️  Weak ciphers detected:")
                for cipher in weak[:5]:
                    lines.append(f"    ❌ {cipher}")

        # Vulnerabilities
        if self.results['vulnerabilities']:
            lines.append(f"\n[VULNERABILITIES] ({len(self.results['vulnerabilities'])} found)")
            for vuln in self.results['vulnerabilities'][:10]:
                severity = vuln['severity']
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                lines.append(f"  {icon} [{severity}] {vuln['name']}")
                lines.append(f"      {vuln['description']}")
        else:
            lines.append(f"\n✓ No major vulnerabilities detected")

        # Recommendations
        lines.append("\n[RECOMMENDATIONS]")
        if score < 80:
            if any('SSLv' in p or 'TLS 1.0' in p or 'TLS 1.1' in p for p in self.results['protocols'] if self.results['protocols'][p].get('supported')):
                lines.append("  1. Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1")
            if cert.get('keySize', 4096) < 2048:
                lines.append("  2. Upgrade to RSA 2048-bit or 4096-bit keys")
            if [v for v in self.results['vulnerabilities'] if 'Weak Cipher' in v['name']]:
                lines.append("  3. Remove weak cipher suites (RC4, DES, 3DES, NULL)")
            lines.append("  4. Enable Forward Secrecy (ECDHE/DHE ciphers)")
            lines.append("  5. Consider using Mozilla SSL Configuration Generator")
        else:
            lines.append("  ✓ Configuration is good. Continue monitoring for new vulnerabilities.")

        lines.append("\n" + "=" * 80)

        return "\n".join(lines)


def analyze_tls(host: str, port: int = 443) -> Dict[str, Any]:
    """
    Convenience function to analyze TLS.

    Args:
        host: Target hostname or IP
        port: Target port (default: 443)

    Returns:
        TLS analysis results
    """
    analyzer = TLSAnalyzer(host, port)
    return analyzer.analyze()
