#!/usr/bin/env python3
"""
Correlation Engine for net-inspect v2.0.0
Multi-layer correlation analysis to detect spoofed/suspicious hosts
"""

from typing import Dict, List, Any
import re


class CorrelationEngine:
    """
    Advanced correlation engine for detecting spoofed or suspicious devices.

    Detection Methods:
    - MAC/Vendor mismatch detection
    - Hostname consistency checks
    - OS fingerprint correlation
    - Behavioral anomaly detection
    """

    def __init__(self):
        """Initialize the correlation engine."""
        self.scan_data = None
        self.hosts = []

    def ingest_scan_data(self, scan_results: Dict[str, Any]) -> None:
        """
        Ingest scan data for analysis.

        Args:
            scan_results: Dictionary containing scan metadata and host list
        """
        self.scan_data = scan_results
        self.hosts = scan_results.get("hosts", [])

    def compute_spoof_scores(self) -> List[Dict[str, Any]]:
        """
        Compute spoof scores for all hosts.

        Returns:
            List of hosts with spoof scores and detection flags
        """
        scored_hosts = []

        for host in self.hosts:
            score = 0
            flags = []

            # Track individual category contributions
            layer2_score = 0  # MAC/Vendor mismatches
            dhcp_score = 0    # Hostname inconsistencies
            fingerprint_score = 0  # Not implemented yet
            stack_score = 0   # Not implemented yet
            behavioral_score = 0  # Not implemented yet
            baseline_score = 0  # Not implemented yet

            # Check 1: MAC/Vendor mismatch (Layer 2)
            vendor = host.get("vendor", "").lower()
            os_detected = host.get("os", "").lower()
            mac = host.get("mac", "")

            # Check for vendor/OS mismatches
            if vendor and os_detected:
                # Apple device without Apple vendor
                if "ios" in os_detected or "macos" in os_detected or "darwin" in os_detected:
                    if "apple" not in vendor:
                        layer2_score += 30
                        flags.append("OS/Vendor mismatch: Apple OS without Apple MAC")

                # Android without known Android vendors
                if "android" in os_detected:
                    android_vendors = ["samsung", "google", "oneplus", "xiaomi", "huawei", "lg", "motorola"]
                    if not any(v in vendor for v in android_vendors):
                        layer2_score += 20
                        flags.append("OS/Vendor mismatch: Android without known manufacturer")

                # Windows on non-PC vendor
                if "windows" in os_detected:
                    pc_vendors = ["intel", "dell", "hp", "lenovo", "asus", "acer", "msi"]
                    if vendor != "-" and not any(v in vendor for v in pc_vendors):
                        layer2_score += 15
                        flags.append("Suspicious: Windows on unusual hardware")

            # Check 2: Hostname inconsistencies (DHCP)
            hostname = host.get("hostname", "").lower()
            if hostname and hostname != "-":
                # Generic/suspicious hostnames
                generic_patterns = [
                    r"^localhost",
                    r"^test",
                    r"^admin",
                    r"^root",
                    r"^unknown",
                    r"^noname",
                    r"^\d+\.\d+\.\d+\.\d+$"  # IP as hostname
                ]
                for pattern in generic_patterns:
                    if re.match(pattern, hostname):
                        dhcp_score += 25
                        flags.append(f"Suspicious hostname: {hostname}")
                        break

                # Hostname/vendor mismatch
                hostname_vendor_map = {
                    "android": ["samsung", "google", "oneplus", "xiaomi"],
                    "iphone": ["apple"],
                    "ipad": ["apple"],
                    "macbook": ["apple"],
                    "pixel": ["google", "intel"],
                    "galaxy": ["samsung"]
                }
                for name_part, expected_vendors in hostname_vendor_map.items():
                    if name_part in hostname:
                        if not any(v in vendor for v in expected_vendors):
                            dhcp_score += 35
                            flags.append(f"Hostname/Vendor conflict: '{hostname}' vs '{vendor}'")

            # Check 3: Missing MAC address (Layer 2 issue)
            if not mac or mac == "-":
                layer2_score += 40
                flags.append("Missing MAC address - possible IP spoofing")

            # Check 4: No open ports but claims to be active device
            ports = host.get("ports", [])
            devtype = host.get("devtype", "")
            if not ports and devtype not in ["unknown", "-"]:
                behavioral_score += 10
                flags.append("No services detected on claimed active device")

            # Check 5: Unusually high risk score
            risk = host.get("risk", 0)
            if risk >= 80:
                behavioral_score += 15
                flags.append(f"Abnormally high risk score: {risk}/100")

            # Calculate total score
            score = layer2_score + dhcp_score + fingerprint_score + stack_score + behavioral_score + baseline_score

            # Normalize score (cap at 100)
            spoof_score = min(score, 100)

            # Determine risk level
            if spoof_score >= 75:
                risk_level = "CRITICAL"
                risk_emoji = "🔴"
            elif spoof_score >= 50:
                risk_level = "HIGH"
                risk_emoji = "🟠"
            elif spoof_score >= 25:
                risk_level = "MEDIUM"
                risk_emoji = "🟡"
            else:
                risk_level = "LOW"
                risk_emoji = "🟢"

            # Create breakdown with top contributors
            contributors = [
                ('layer2', layer2_score),
                ('dhcp', dhcp_score),
                ('fingerprint', fingerprint_score),
                ('stack', stack_score),
                ('behavioral', behavioral_score),
                ('baseline', baseline_score)
            ]

            scored_hosts.append({
                **host,  # Include all original host data
                "spoof_score": spoof_score,
                "spoof_flags": flags,
                "risk_level": risk_level,  # Changed from spoof_risk_level
                "risk_emoji": risk_emoji,
                "breakdown": {
                    "top_contributors": contributors
                }
            })

        # Sort by spoof score (highest first)
        scored_hosts.sort(key=lambda h: h["spoof_score"], reverse=True)

        return scored_hosts
