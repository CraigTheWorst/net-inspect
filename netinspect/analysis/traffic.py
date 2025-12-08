#!/usr/bin/env python3
"""
Traffic Analysis Module for net-inspect
Analyzes PCAP files for credentials, file extraction, and security issues
"""

import os
import re
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import hashlib

# Try to import scapy
try:
    from scapy.all import rdpcap, TCP, UDP, IP, IPv6, Raw, ICMP, ARP, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.inet import TCP as TCPLayer
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class TrafficAnalyzer:
    """
    Analyzes packet captures for security-relevant information.

    Features:
    - Credential extraction (FTP, HTTP, Telnet, SMTP, POP3, IMAP)
    - File carving (images, documents, keys)
    - Certificate extraction from TLS handshakes
    - Session reconstruction
    - Unencrypted data detection
    """

    def __init__(self, pcap_file: str, verbose: bool = False):
        """
        Initialize Traffic Analyzer.

        Args:
            pcap_file: Path to PCAP file
            verbose: Enable verbose output
        """
        self.pcap_file = pcap_file
        self.verbose = verbose
        self.results = {
            'credentials': [],
            'files': [],
            'certificates': [],
            'sessions': [],
            'warnings': [],
            'statistics': {}
        }

        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy not available. Install with: pip install scapy")

        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    def analyze(self) -> Dict[str, Any]:
        """
        Run complete traffic analysis.

        Returns:
            Dictionary with analysis results
        """
        try:
            # Load packets
            if self.verbose:
                print(f"[*] Loading PCAP: {self.pcap_file}")

            packets = rdpcap(self.pcap_file)

            if self.verbose:
                print(f"[*] Loaded {len(packets)} packets")

            # Statistics
            self.results['statistics'] = self._compute_statistics(packets)

            # Extract credentials
            if self.verbose:
                print("[*] Extracting credentials...")
            self.results['credentials'] = self._extract_credentials(packets)

            # Carve files
            if self.verbose:
                print("[*] Carving files...")
            self.results['files'] = self._carve_files(packets)

            # Extract certificates
            if self.verbose:
                print("[*] Extracting certificates...")
            self.results['certificates'] = self._extract_certificates(packets)

            # Session analysis
            if self.verbose:
                print("[*] Analyzing sessions...")
            self.results['sessions'] = self._analyze_sessions(packets)

            # Security warnings
            if self.verbose:
                print("[*] Checking for security issues...")
            self.results['warnings'] = self._security_warnings(packets)

            if self.verbose:
                print()  # Add blank line before traffic analysis summary

            return self.results

        except Exception as e:
            raise Exception(f"Traffic analysis failed: {e}")

    def _compute_statistics(self, packets) -> Dict[str, Any]:
        """Compute packet statistics."""
        stats = {
            'total_packets': len(packets),
            'protocols': {},
            'total_bytes': 0,
            'ip_pairs': set(),
            'ports': set()
        }

        for pkt in packets:
            # Byte count
            stats['total_bytes'] += len(pkt)

            # Protocol distribution
            if IP in pkt:
                proto = pkt[IP].proto
                proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f'Other({proto})')
                stats['protocols'][proto_name] = stats['protocols'].get(proto_name, 0) + 1

                # IP pairs
                stats['ip_pairs'].add((pkt[IP].src, pkt[IP].dst))

            # Ports
            if TCP in pkt:
                stats['ports'].add(pkt[TCP].sport)
                stats['ports'].add(pkt[TCP].dport)
            elif UDP in pkt:
                stats['ports'].add(pkt[UDP].sport)
                stats['ports'].add(pkt[UDP].dport)

        # Convert sets to counts for JSON serialization
        stats['unique_ip_pairs'] = len(stats['ip_pairs'])
        stats['unique_ports'] = len(stats['ports'])
        del stats['ip_pairs']
        del stats['ports']

        return stats

    def _extract_credentials(self, packets) -> List[Dict[str, str]]:
        """Extract credentials from unencrypted protocols."""
        credentials = []

        for pkt in packets:
            if not pkt.haslayer(Raw):
                continue

            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            except:
                continue

            src_ip = pkt[IP].src if IP in pkt else "Unknown"
            dst_ip = pkt[IP].dst if IP in pkt else "Unknown"

            # FTP credentials
            ftp_user = re.search(r'USER\s+(\S+)', payload)
            ftp_pass = re.search(r'PASS\s+(\S+)', payload)

            if ftp_user:
                credentials.append({
                    'protocol': 'FTP',
                    'type': 'username',
                    'value': ftp_user.group(1),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip
                })

            if ftp_pass:
                credentials.append({
                    'protocol': 'FTP',
                    'type': 'password',
                    'value': ftp_pass.group(1),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip
                })

            # HTTP Basic Auth
            http_auth = re.search(r'Authorization:\s*Basic\s+(\S+)', payload, re.IGNORECASE)
            if http_auth:
                import base64
                try:
                    decoded = base64.b64decode(http_auth.group(1)).decode('utf-8')
                    if ':' in decoded:
                        user, passwd = decoded.split(':', 1)
                        credentials.append({
                            'protocol': 'HTTP',
                            'type': 'basic_auth',
                            'username': user,
                            'password': passwd,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip
                        })
                except:
                    pass

            # HTTP POST credentials
            http_post = re.search(r'POST\s+(\S+)', payload)
            if http_post:
                # Look for common password field names
                password_match = re.search(r'(?:pass(?:word)?|pwd)=([^&\s]+)', payload, re.IGNORECASE)
                user_match = re.search(r'(?:user(?:name)?|login|email)=([^&\s]+)', payload, re.IGNORECASE)

                if password_match or user_match:
                    cred = {
                        'protocol': 'HTTP POST',
                        'url': http_post.group(1),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    }
                    if user_match:
                        cred['username'] = user_match.group(1)
                    if password_match:
                        cred['password'] = password_match.group(1)
                    credentials.append(cred)

            # Telnet credentials (look for login patterns)
            if TCP in pkt and pkt[TCP].dport == 23:
                # Telnet login attempts
                if re.search(r'login:|username:', payload, re.IGNORECASE):
                    credentials.append({
                        'protocol': 'TELNET',
                        'type': 'login_prompt',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'note': 'Telnet session detected - credentials may follow'
                    })

            # SMTP AUTH
            smtp_auth = re.search(r'AUTH\s+(?:LOGIN|PLAIN)\s+(\S+)', payload, re.IGNORECASE)
            if smtp_auth:
                credentials.append({
                    'protocol': 'SMTP',
                    'type': 'auth',
                    'value': smtp_auth.group(1),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'note': 'Base64-encoded credentials'
                })

            # POP3/IMAP
            pop_user = re.search(r'USER\s+(\S+)', payload)
            pop_pass = re.search(r'PASS\s+(\S+)', payload)

            if TCP in pkt and pkt[TCP].dport in [110, 143]:  # POP3, IMAP
                if pop_user:
                    credentials.append({
                        'protocol': 'POP3/IMAP',
                        'type': 'username',
                        'value': pop_user.group(1),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    })
                if pop_pass:
                    credentials.append({
                        'protocol': 'POP3/IMAP',
                        'type': 'password',
                        'value': pop_pass.group(1),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    })

        return credentials

    def _carve_files(self, packets) -> List[Dict[str, Any]]:
        """Carve files from packet captures."""
        files = []

        # File signatures (magic bytes)
        signatures = {
            'PNG': (b'\x89PNG\r\n\x1a\n', '.png'),
            'JPEG': (b'\xff\xd8\xff', '.jpg'),
            'PDF': (b'%PDF', '.pdf'),
            'ZIP': (b'PK\x03\x04', '.zip'),
            'GIF': (b'GIF89a', '.gif'),
            'SSH_KEY': (b'-----BEGIN', '.key'),
            'PCAP': (b'\xd4\xc3\xb2\xa1', '.pcap')
        }

        # Reconstruct TCP streams
        streams = {}

        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                # Create stream identifier
                if IP in pkt:
                    stream_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                else:
                    continue

                if stream_id not in streams:
                    streams[stream_id] = b''

                streams[stream_id] += bytes(pkt[Raw].load)

        # Search streams for file signatures
        for stream_id, data in streams.items():
            for file_type, (signature, extension) in signatures.items():
                if signature in data:
                    # Found a file signature
                    start_idx = data.find(signature)

                    # Extract reasonable chunk (max 1MB for demo)
                    chunk = data[start_idx:start_idx + 1024*1024]

                    # Calculate hash
                    file_hash = hashlib.md5(chunk).hexdigest()

                    files.append({
                        'type': file_type,
                        'extension': extension,
                        'size_bytes': len(chunk),
                        'md5': file_hash,
                        'src_ip': stream_id[0],
                        'dst_ip': stream_id[2],
                        'note': f'Carved from TCP stream'
                    })

        return files

    def _extract_certificates(self, packets) -> List[Dict[str, Any]]:
        """Extract TLS certificates from handshakes."""
        certificates = []

        # Look for TLS handshake patterns
        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                try:
                    payload = bytes(pkt[Raw].load)

                    # TLS handshake starts with 0x16 (handshake), followed by version
                    if payload.startswith(b'\x16\x03'):
                        # Look for certificate message (0x0b)
                        if b'\x0b' in payload[5:10]:  # Certificate message type
                            src_ip = pkt[IP].src if IP in pkt else "Unknown"
                            dst_ip = pkt[IP].dst if IP in pkt else "Unknown"
                            dst_port = pkt[TCP].dport if TCP in pkt else 0

                            # Try to extract certificate using openssl (if available)
                            cert_info = self._parse_certificate_openssl(src_ip, dst_ip, dst_port)

                            if cert_info:
                                certificates.append(cert_info)
                            else:
                                certificates.append({
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'port': dst_port,
                                    'note': 'TLS certificate detected (parsing requires openssl)'
                                })
                except:
                    pass

        return certificates

    def _parse_certificate_openssl(self, src_ip: str, dst_ip: str, port: int) -> Optional[Dict]:
        """Parse certificate using openssl (if available)."""
        # This is a placeholder - real implementation would use openssl
        # or pyOpenSSL to parse certificate from packets
        return None

    def _analyze_sessions(self, packets) -> List[Dict[str, Any]]:
        """Analyze TCP sessions."""
        sessions = {}

        for pkt in packets:
            if TCP in pkt and IP in pkt:
                # Session identifier
                session_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)

                if session_id not in sessions:
                    sessions[session_id] = {
                        'src_ip': pkt[IP].src,
                        'src_port': pkt[TCP].sport,
                        'dst_ip': pkt[IP].dst,
                        'dst_port': pkt[TCP].dport,
                        'packets': 0,
                        'bytes': 0,
                        'flags': set()
                    }

                sessions[session_id]['packets'] += 1
                sessions[session_id]['bytes'] += len(pkt)

                # TCP flags
                if pkt[TCP].flags:
                    flag_str = str(pkt[TCP].flags)
                    sessions[session_id]['flags'].add(flag_str)

        # Convert to list and clean up
        session_list = []
        for session_id, data in sessions.items():
            data['flags'] = list(data['flags'])
            session_list.append(data)

        return session_list

    def _security_warnings(self, packets) -> List[Dict[str, str]]:
        """Detect security issues in traffic."""
        warnings = []

        unencrypted_protocols = {
            21: 'FTP',
            23: 'Telnet',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }

        detected_protocols = set()

        for pkt in packets:
            if TCP in pkt:
                port = pkt[TCP].dport
                if port in unencrypted_protocols:
                    protocol = unencrypted_protocols[port]
                    if protocol not in detected_protocols:
                        detected_protocols.add(protocol)
                        warnings.append({
                            'severity': 'HIGH' if port in [21, 23] else 'MEDIUM',
                            'issue': f'Unencrypted {protocol} traffic detected',
                            'port': port,
                            'recommendation': f'Use encrypted alternative for {protocol}'
                        })

        return warnings

    def get_summary(self) -> str:
        """Generate human-readable summary."""
        summary = []
        summary.append("=" * 80)
        summary.append("TRAFFIC ANALYSIS SUMMARY")
        summary.append("=" * 80)

        # Statistics
        stats = self.results.get('statistics', {})
        summary.append(f"\nPACKET STATISTICS:")
        summary.append(f"  Total Packets: {stats.get('total_packets', 0)}")
        summary.append(f"  Total Bytes: {stats.get('total_bytes', 0):,}")
        summary.append(f"  Unique IP Pairs: {stats.get('unique_ip_pairs', 0)}")
        summary.append(f"  Unique Ports: {stats.get('unique_ports', 0)}")

        # Protocols
        protocols = stats.get('protocols', {})
        if protocols:
            summary.append(f"\n  Protocol Distribution:")
            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                summary.append(f"    {proto}: {count}")

        # Credentials
        creds = self.results.get('credentials', [])
        if creds:
            summary.append(f"\n🔑 CREDENTIALS FOUND: {len(creds)}")
            for cred in creds[:10]:  # Show first 10
                protocol = cred.get('protocol', 'Unknown')
                src = cred.get('src_ip', 'Unknown')
                dst = cred.get('dst_ip', 'Unknown')

                if 'username' in cred and 'password' in cred:
                    summary.append(f"  [{protocol}] {src} → {dst}")
                    summary.append(f"    Username: {cred['username']}")
                    summary.append(f"    Password: {cred['password']}")
                elif 'type' in cred and 'value' in cred:
                    summary.append(f"  [{protocol}] {src} → {dst}")
                    summary.append(f"    {cred['type']}: {cred['value']}")
        else:
            summary.append(f"\n✓ No credentials found in unencrypted traffic")

        # Files
        files = self.results.get('files', [])
        if files:
            summary.append(f"\n📁 FILES CARVED: {len(files)}")
            for file_info in files[:10]:
                summary.append(f"  {file_info['type']} ({file_info['size_bytes']:,} bytes)")
                summary.append(f"    MD5: {file_info['md5']}")
                summary.append(f"    {file_info['src_ip']} → {file_info['dst_ip']}")

        # Warnings
        warnings = self.results.get('warnings', [])
        if warnings:
            summary.append(f"\n⚠️  SECURITY WARNINGS: {len(warnings)}")
            for warning in warnings:
                severity = warning.get('severity', 'UNKNOWN')
                issue = warning.get('issue', 'Unknown issue')
                summary.append(f"  [{severity}] {issue}")
                if 'recommendation' in warning:
                    summary.append(f"    → {warning['recommendation']}")

        summary.append("\n" + "=" * 80)

        return "\n".join(summary)


def analyze_pcap(pcap_file: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Convenience function to analyze a PCAP file.

    Args:
        pcap_file: Path to PCAP file
        verbose: Enable verbose output

    Returns:
        Analysis results dictionary
    """
    analyzer = TrafficAnalyzer(pcap_file, verbose=verbose)
    return analyzer.analyze()
