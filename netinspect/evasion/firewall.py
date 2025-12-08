#!/usr/bin/env python3
"""
Firewall Evasion Testing Module for net-inspect

⚠️  WARNING: FOR AUTHORIZED PENETRATION TESTING ONLY
Use of these techniques without explicit authorization may be illegal.
"""

import os
import socket
import subprocess
import time
from typing import Dict, List, Optional, Any, Tuple

try:
    from scapy.all import (
        IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
        sr1, sr, send, fragment, Raw, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class FirewallTester:
    """
    Firewall evasion and rule inference testing.

    Techniques:
    - Port knocking detection
    - Firewall rule inference
    - TTL manipulation
    - Fragmentation evasion
    - Packet mangling

    ⚠️  AUTHORIZED USE ONLY - REQUIRES EXPLICIT PERMISSION
    """

    def __init__(self, target: str, verbose: bool = False):
        """
        Initialize Firewall Tester.

        Args:
            target: Target IP address
            verbose: Enable verbose output
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Firewall testing requires Scapy. Install with: pip install scapy")

        self.target = target
        self.verbose = verbose
        self.results = {
            'target': target,
            'tests_run': [],
            'firewall_detected': False,
            'inferred_rules': [],
            'evasion_techniques': [],
            'recommendations': []
        }

        # Suppress Scapy warnings
        conf.verb = 0

    def run_all_tests(self) -> Dict[str, Any]:
        """Run complete firewall testing suite."""
        print(f"\n{'='*80}")
        print(f"FIREWALL EVASION TESTING: {self.target}")
        print(f"{'='*80}")
        print("⚠️  WARNING: Authorized penetration testing only!")
        print(f"{'='*80}\n")

        # Test 1: Basic connectivity
        if self.verbose:
            print("[*] Test 1: Basic connectivity check...")
        self._test_basic_connectivity()

        # Test 2: Port knocking detection
        if self.verbose:
            print("[*] Test 2: Port knocking sequence detection...")
        self._test_port_knocking()

        # Test 3: Firewall rule inference
        if self.verbose:
            print("[*] Test 3: Firewall rule inference...")
        self._test_rule_inference()

        # Test 4: TTL manipulation
        if self.verbose:
            print("[*] Test 4: TTL manipulation evasion...")
        self._test_ttl_manipulation()

        # Test 5: Fragmentation evasion
        if self.verbose:
            print("[*] Test 5: Fragmentation evasion...")
        self._test_fragmentation()

        # Test 6: Packet timing analysis
        if self.verbose:
            print("[*] Test 6: Packet timing analysis...")
        self._test_timing_analysis()

        # Generate recommendations
        self._generate_recommendations()

        return self.results

    def _test_basic_connectivity(self):
        """Test basic ICMP and TCP connectivity."""
        test = {
            'name': 'Basic Connectivity',
            'icmp_response': False,
            'tcp_syn_response': False,
            'tcp_ack_response': False
        }

        try:
            # ICMP ping
            pkt = IP(dst=self.target)/ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)

            if resp:
                test['icmp_response'] = True
                if self.verbose:
                    print(f"  [+] ICMP response received")
            else:
                if self.verbose:
                    print(f"  [-] No ICMP response (may be filtered)")

            # TCP SYN to common port (80)
            syn_pkt = IP(dst=self.target)/TCP(dport=80, flags='S')
            syn_resp = sr1(syn_pkt, timeout=2, verbose=0)

            if syn_resp and TCP in syn_resp:
                test['tcp_syn_response'] = True
                test['tcp_syn_flags'] = str(syn_resp[TCP].flags)

                if syn_resp[TCP].flags == 'SA':  # SYN-ACK
                    if self.verbose:
                        print(f"  [+] Port 80 open (SYN-ACK received)")
                elif syn_resp[TCP].flags == 'RA':  # RST-ACK
                    if self.verbose:
                        print(f"  [+] Port 80 closed (RST-ACK received)")
            else:
                if self.verbose:
                    print(f"  [-] No TCP response to SYN (filtered?)")

            # TCP ACK probe (firewall detection)
            ack_pkt = IP(dst=self.target)/TCP(dport=80, flags='A')
            ack_resp = sr1(ack_pkt, timeout=2, verbose=0)

            if ack_resp and TCP in ack_resp:
                test['tcp_ack_response'] = True
                if self.verbose:
                    print(f"  [+] TCP ACK response (stateless firewall?)")
            else:
                if self.verbose:
                    print(f"  [-] No ACK response (stateful firewall detected)")
                self.results['firewall_detected'] = True

        except Exception as e:
            test['error'] = str(e)
            if self.verbose:
                print(f"  [!] Error: {e}")

        self.results['tests_run'].append(test)

    def _test_port_knocking(self):
        """Test for port knocking sequences."""
        test = {
            'name': 'Port Knocking Detection',
            'sequences_tested': [],
            'potential_knock': False
        }

        # Common port knocking sequences
        sequences = [
            [7000, 8000, 9000],  # Common sequence
            [1234, 2345, 3456],  # Sequential
            [1000, 2000, 3000],  # Incremental
        ]

        try:
            for sequence in sequences:
                if self.verbose:
                    print(f"  [*] Testing knock sequence: {sequence}")

                # Send knocks
                for port in sequence:
                    pkt = IP(dst=self.target)/TCP(dport=port, flags='S')
                    sr1(pkt, timeout=0.5, verbose=0)
                    time.sleep(0.1)

                # Test target port (22 for SSH)
                test_pkt = IP(dst=self.target)/TCP(dport=22, flags='S')
                resp = sr1(test_pkt, timeout=2, verbose=0)

                if resp and TCP in resp and resp[TCP].flags == 'SA':
                    test['potential_knock'] = True
                    test['working_sequence'] = sequence
                    if self.verbose:
                        print(f"  [+] Port 22 opened after knock sequence!")
                    break

                test['sequences_tested'].append({
                    'sequence': sequence,
                    'success': False
                })

        except Exception as e:
            test['error'] = str(e)

        self.results['tests_run'].append(test)

    def _test_rule_inference(self):
        """Infer firewall rules by testing various packet combinations."""
        test = {
            'name': 'Firewall Rule Inference',
            'inferred_rules': []
        }

        # Test common ports
        test_ports = [22, 23, 80, 443, 3389, 8080]

        try:
            for port in test_ports:
                # SYN scan
                syn_pkt = IP(dst=self.target)/TCP(dport=port, flags='S')
                syn_resp = sr1(syn_pkt, timeout=2, verbose=0)

                # ACK scan
                ack_pkt = IP(dst=self.target)/TCP(dport=port, flags='A')
                ack_resp = sr1(ack_pkt, timeout=2, verbose=0)

                # Analyze responses
                rule = {'port': port}

                if syn_resp and TCP in syn_resp:
                    if syn_resp[TCP].flags == 'SA':
                        rule['state'] = 'OPEN'
                    elif syn_resp[TCP].flags == 'RA':
                        rule['state'] = 'CLOSED'
                else:
                    rule['state'] = 'FILTERED'

                if ack_resp:
                    rule['stateful'] = False  # Stateless firewall
                else:
                    rule['stateful'] = True   # Stateful firewall

                test['inferred_rules'].append(rule)
                self.results['inferred_rules'].append(rule)

                if self.verbose:
                    print(f"  Port {port}: {rule['state']} ({'Stateful' if rule.get('stateful') else 'Stateless'})")

        except Exception as e:
            test['error'] = str(e)

        self.results['tests_run'].append(test)

    def _test_ttl_manipulation(self):
        """Test TTL-based firewall evasion."""
        test = {
            'name': 'TTL Manipulation',
            'ttl_tests': []
        }

        try:
            # Test with various TTL values
            ttl_values = [1, 64, 128, 255]

            for ttl in ttl_values:
                pkt = IP(dst=self.target, ttl=ttl)/ICMP()
                resp = sr1(pkt, timeout=2, verbose=0)

                ttl_result = {
                    'ttl': ttl,
                    'response': resp is not None,
                    'response_ttl': resp[IP].ttl if resp and IP in resp else None
                }

                test['ttl_tests'].append(ttl_result)

                if self.verbose:
                    if resp:
                        print(f"  TTL={ttl}: Response received (TTL={resp[IP].ttl})")
                    else:
                        print(f"  TTL={ttl}: No response")

            # Check if low TTL can bypass firewall
            low_ttl_pkt = IP(dst=self.target, ttl=1)/TCP(dport=80, flags='S')
            low_ttl_resp = sr1(low_ttl_pkt, timeout=2, verbose=0)

            if low_ttl_resp:
                test['low_ttl_bypass'] = True
                self.results['evasion_techniques'].append({
                    'technique': 'TTL Manipulation',
                    'description': 'Low TTL values may bypass firewall rules',
                    'command': f'nmap -sS --ttl 1 {self.target}'
                })

        except Exception as e:
            test['error'] = str(e)

        self.results['tests_run'].append(test)

    def _test_fragmentation(self):
        """Test IP fragmentation evasion."""
        test = {
            'name': 'Fragmentation Evasion',
            'fragmentation_works': False
        }

        try:
            # Create fragmented packet
            payload = "X" * 1500  # Large payload to force fragmentation
            pkt = IP(dst=self.target)/ICMP()/Raw(load=payload)

            # Fragment the packet
            frags = fragment(pkt, fragsize=800)

            if self.verbose:
                print(f"  [*] Sending {len(frags)} fragments...")

            # Send fragments
            for frag in frags:
                send(frag, verbose=0)

            # Wait for response
            time.sleep(1)

            # Test if fragmentation bypasses firewall
            # (In real scenario, would need to check if service responded)
            test['fragmentation_works'] = False  # Placeholder

            if self.verbose:
                print(f"  [*] Fragmentation test completed")

            self.results['evasion_techniques'].append({
                'technique': 'IP Fragmentation',
                'description': 'Fragment packets to evade inspection',
                'command': f'nmap -sS -f {self.target}'
            })

        except Exception as e:
            test['error'] = str(e)

        self.results['tests_run'].append(test)

    def _test_timing_analysis(self):
        """Analyze firewall response timing to detect rate limiting."""
        test = {
            'name': 'Timing Analysis',
            'rate_limiting_detected': False,
            'response_times': []
        }

        try:
            # Send rapid SYN packets
            for i in range(10):
                start = time.time()
                pkt = IP(dst=self.target)/TCP(dport=80, flags='S')
                resp = sr1(pkt, timeout=2, verbose=0)
                elapsed = time.time() - start

                test['response_times'].append(elapsed)

                if self.verbose and i % 5 == 0:
                    print(f"  Packet {i+1}: {elapsed:.3f}s")

            # Analyze timing
            avg_time = sum(test['response_times']) / len(test['response_times'])
            later_avg = sum(test['response_times'][5:]) / len(test['response_times'][5:])

            if later_avg > avg_time * 2:
                test['rate_limiting_detected'] = True
                if self.verbose:
                    print(f"  [+] Rate limiting detected (response time increased)")

        except Exception as e:
            test['error'] = str(e)

        self.results['tests_run'].append(test)

    def _generate_recommendations(self):
        """Generate evasion recommendations based on test results."""
        recs = []

        if self.results['firewall_detected']:
            recs.append({
                'priority': 'HIGH',
                'recommendation': 'Stateful firewall detected. Use ACK scanning or fragmentation.',
                'commands': [
                    f'nmap -sA {self.target}  # ACK scan',
                    f'nmap -sS -f {self.target}  # Fragmented SYN scan'
                ]
            })

        # Check for filtered ports
        filtered_ports = [r for r in self.results.get('inferred_rules', []) if r.get('state') == 'FILTERED']

        if filtered_ports:
            recs.append({
                'priority': 'MEDIUM',
                'recommendation': f'{len(filtered_ports)} filtered port(s) detected. Try alternative scan techniques.',
                'commands': [
                    f'nmap -sN {self.target}  # NULL scan',
                    f'nmap -sF {self.target}  # FIN scan',
                    f'nmap -sX {self.target}  # XMAS scan'
                ]
            })

        # Always recommend slow/stealthy scans
        recs.append({
            'priority': 'INFO',
            'recommendation': 'For stealth, use slow timing and source port manipulation',
            'commands': [
                f'nmap -sS -T0 --source-port 53 {self.target}  # DNS source port',
                f'nmap -sS -T1 --data-length 25 {self.target}  # Random data padding'
            ]
        })

        self.results['recommendations'] = recs

    def get_report(self) -> str:
        """Generate human-readable firewall testing report."""
        lines = []
        lines.append("=" * 80)
        lines.append(f"FIREWALL EVASION TEST REPORT: {self.target}")
        lines.append("=" * 80)

        # Firewall detection
        if self.results['firewall_detected']:
            lines.append("\n🛡️  FIREWALL DETECTED: Stateful packet filtering active")
        else:
            lines.append("\n✓ No obvious firewall detected (or very permissive rules)")

        # Test results
        for test in self.results['tests_run']:
            lines.append(f"\n[{test['name']}]")

            if 'error' in test:
                lines.append(f"  ❌ Error: {test['error']}")
                continue

            # Specific test outputs
            if test['name'] == 'Firewall Rule Inference' and 'inferred_rules' in test:
                for rule in test['inferred_rules'][:10]:  # Show first 10
                    state_icon = {'OPEN': '🟢', 'CLOSED': '🔴', 'FILTERED': '🟡'}.get(rule['state'], '⚪')
                    lines.append(f"  {state_icon} Port {rule['port']}: {rule['state']}")

        # Evasion techniques
        if self.results['evasion_techniques']:
            lines.append(f"\n📋 SUGGESTED EVASION TECHNIQUES:")
            for tech in self.results['evasion_techniques']:
                lines.append(f"  • {tech['technique']}")
                lines.append(f"    {tech['description']}")
                lines.append(f"    Command: {tech['command']}")

        # Recommendations
        if self.results['recommendations']:
            lines.append(f"\n💡 RECOMMENDATIONS:")
            for rec in self.results['recommendations']:
                priority_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}.get(rec['priority'], '⚪')
                lines.append(f"\n  {priority_icon} [{rec['priority']}] {rec['recommendation']}")
                if 'commands' in rec:
                    for cmd in rec['commands']:
                        lines.append(f"    $ {cmd}")

        lines.append("\n" + "=" * 80)
        lines.append("⚠️  WARNING: Use these techniques only with explicit authorization!")
        lines.append("=" * 80)

        return "\n".join(lines)


def test_firewall(target: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Convenience function to test firewall.

    Args:
        target: Target IP address
        verbose: Enable verbose output

    Returns:
        Firewall test results
    """
    tester = FirewallTester(target, verbose=verbose)
    return tester.run_all_tests()
