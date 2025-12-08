#!/usr/bin/env python3
"""
Continuous Monitoring Daemon for net-inspect
Provides periodic scanning, baseline comparison, and alerting
"""

import os
import sys
import time
import json
import signal
import sqlite3
import smtplib
import syslog
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class MonitorDaemon:
    """
    Continuous network monitoring daemon.

    Features:
    - Periodic scanning at configurable intervals
    - Automatic baseline comparison
    - Multi-channel alerting (webhook, email, syslog)
    - Historical data storage (SQLite)
    - Graceful shutdown handling
    """

    def __init__(self,
                 interval: int = 3600,
                 baseline_file: Optional[str] = None,
                 webhook_url: Optional[str] = None,
                 email_to: Optional[str] = None,
                 syslog_server: Optional[str] = None,
                 db_path: Optional[str] = None,
                 scan_command: Optional[str] = None):
        """
        Initialize monitoring daemon.

        Args:
            interval: Scan interval in seconds
            baseline_file: Path to baseline JSON file
            webhook_url: Webhook URL for alerts
            email_to: Email address for alerts
            syslog_server: Syslog server (host:port)
            db_path: SQLite database path
            scan_command: Custom scan command (defaults to netinspect basic scan)
        """
        self.interval = interval
        self.baseline_file = baseline_file
        self.webhook_url = webhook_url
        self.email_to = email_to
        self.syslog_server = syslog_server
        self.scan_command = scan_command
        self.running = False
        self.scan_count = 0

        # Setup database
        if db_path:
            self.db_path = db_path
        else:
            db_dir = Path.home() / ".local" / "share" / "net-inspect"
            db_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(db_dir / "monitoring.db")

        self._init_database()

        # Load baseline if provided
        self.baseline_data = None
        if baseline_file and os.path.exists(baseline_file):
            try:
                with open(baseline_file, 'r') as f:
                    self.baseline_data = json.load(f)
            except Exception as e:
                print(f"[!] Failed to load baseline: {e}")

        # Signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _init_database(self):
        """Initialize SQLite database for historical data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_hosts INTEGER,
                new_hosts INTEGER,
                missing_hosts INTEGER,
                changed_hosts INTEGER,
                critical_findings INTEGER,
                scan_data TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT,
                alert_type TEXT,
                message TEXT,
                details TEXT
            )
        """)

        conn.commit()
        conn.close()

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n[*] Received signal {signum}, shutting down gracefully...")
        self.running = False

    def start(self):
        """Start the monitoring daemon."""
        print("[*] Starting net-inspect monitoring daemon")
        print(f"[*] Scan interval: {self.interval} seconds ({self.interval/60:.1f} minutes)")
        print(f"[*] Database: {self.db_path}")

        if self.baseline_file:
            print(f"[*] Baseline: {self.baseline_file}")
        if self.webhook_url:
            print(f"[*] Webhook alerts: {self.webhook_url}")
        if self.email_to:
            print(f"[*] Email alerts: {self.email_to}")

        self.running = True

        try:
            while self.running:
                self.scan_count += 1
                print(f"\n{'='*60}")
                print(f"[*] Starting scan #{self.scan_count} at {datetime.now()}")
                print(f"{'='*60}")

                try:
                    self._run_scan()
                except Exception as e:
                    print(f"[!] Scan failed: {e}")
                    self._send_alert("ERROR", "scan_failure", f"Scan failed: {e}", {})

                if self.running:
                    print(f"[*] Next scan in {self.interval} seconds...")
                    time.sleep(self.interval)

        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")
        finally:
            print("[*] Daemon stopped")

    def _run_scan(self):
        """Execute a network scan."""
        # Build scan command
        if self.scan_command:
            cmd = self.scan_command
        else:
            # Default: basic scan with JSON output
            cmd = "netinspect --json-only"

        # Execute scan
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            scan_data = json.loads(result.stdout) if result.stdout else {}
        except subprocess.TimeoutExpired:
            print("[!] Scan timeout (10 minutes)")
            return
        except json.JSONDecodeError:
            print("[!] Failed to parse scan output as JSON")
            return
        except Exception as e:
            print(f"[!] Scan execution failed: {e}")
            return

        # Analyze results
        analysis = self._analyze_scan(scan_data)

        # Store in database
        self._store_scan(analysis, scan_data)

        # Check for alerts
        self._check_alerts(analysis)

    def _analyze_scan(self, scan_data: Dict) -> Dict[str, Any]:
        """Analyze scan results and compare with baseline."""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'total_hosts': len(scan_data.get('hosts', [])),
            'new_hosts': [],
            'missing_hosts': [],
            'changed_hosts': [],
            'critical_findings': 0
        }

        current_hosts = {h.get('mac', h.get('ip')): h for h in scan_data.get('hosts', [])}

        # Compare with baseline if available
        if self.baseline_data:
            baseline_hosts = {h.get('mac', h.get('ip')): h for h in self.baseline_data.get('hosts', [])}

            # Find new hosts
            for mac, host in current_hosts.items():
                if mac not in baseline_hosts:
                    analysis['new_hosts'].append(host)
                elif self._host_changed(baseline_hosts[mac], host):
                    analysis['changed_hosts'].append({
                        'before': baseline_hosts[mac],
                        'after': host
                    })

            # Find missing hosts
            for mac, host in baseline_hosts.items():
                if mac not in current_hosts:
                    analysis['missing_hosts'].append(host)

        # Count critical findings
        for host in scan_data.get('hosts', []):
            risk = host.get('risk', 0)
            if risk >= 60:
                analysis['critical_findings'] += 1

        return analysis

    def _host_changed(self, before: Dict, after: Dict) -> bool:
        """Check if host has changed significantly."""
        # Check if IP changed (MAC spoofing indicator)
        if before.get('ip') != after.get('ip'):
            return True

        # Check if OS changed
        if before.get('os') != after.get('os'):
            return True

        # Check if hostname changed
        if before.get('hostname') != after.get('hostname'):
            return True

        return False

    def _store_scan(self, analysis: Dict, scan_data: Dict):
        """Store scan results in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scans (timestamp, total_hosts, new_hosts, missing_hosts,
                             changed_hosts, critical_findings, scan_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis['timestamp'],
            analysis['total_hosts'],
            len(analysis['new_hosts']),
            len(analysis['missing_hosts']),
            len(analysis['changed_hosts']),
            analysis['critical_findings'],
            json.dumps(scan_data)
        ))

        conn.commit()
        conn.close()

    def _check_alerts(self, analysis: Dict):
        """Check for conditions that require alerting."""
        alerts = []

        # New hosts detected
        if analysis['new_hosts']:
            alerts.append({
                'severity': 'HIGH',
                'type': 'new_hosts',
                'message': f"{len(analysis['new_hosts'])} new host(s) detected",
                'details': analysis['new_hosts']
            })

        # Missing hosts
        if analysis['missing_hosts']:
            alerts.append({
                'severity': 'MEDIUM',
                'type': 'missing_hosts',
                'message': f"{len(analysis['missing_hosts'])} host(s) disappeared",
                'details': analysis['missing_hosts']
            })

        # Changed hosts (potential spoofing)
        if analysis['changed_hosts']:
            alerts.append({
                'severity': 'CRITICAL',
                'type': 'changed_hosts',
                'message': f"{len(analysis['changed_hosts'])} host(s) changed (potential spoofing)",
                'details': analysis['changed_hosts']
            })

        # Critical findings
        if analysis['critical_findings'] > 0:
            alerts.append({
                'severity': 'HIGH',
                'type': 'critical_findings',
                'message': f"{analysis['critical_findings']} host(s) with critical risk (≥60)",
                'details': {'count': analysis['critical_findings']}
            })

        # Send alerts
        for alert in alerts:
            self._send_alert(alert['severity'], alert['type'], alert['message'], alert['details'])

    def _send_alert(self, severity: str, alert_type: str, message: str, details: Any):
        """Send alert via configured channels."""
        # Store alert in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (timestamp, severity, alert_type, message, details)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), severity, alert_type, message, json.dumps(details)))
        conn.commit()
        conn.close()

        # Print to console
        severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'ERROR': '❌'}.get(severity, '⚪')
        print(f"\n{severity_icon} ALERT [{severity}] {message}")

        # Webhook alert
        if self.webhook_url:
            self._send_webhook(severity, alert_type, message, details)

        # Email alert
        if self.email_to:
            self._send_email(severity, alert_type, message, details)

        # Syslog alert
        if self.syslog_server:
            self._send_syslog(severity, alert_type, message)

    def _send_webhook(self, severity: str, alert_type: str, message: str, details: Any):
        """Send webhook alert (Slack, Discord, generic HTTP POST)."""
        if not REQUESTS_AVAILABLE:
            print("[!] Webhook alerts require 'requests' library")
            return

        try:
            # Format for Slack/Discord
            payload = {
                'text': f"[{severity}] net-inspect Alert",
                'attachments': [{
                    'color': {'CRITICAL': 'danger', 'HIGH': 'warning', 'MEDIUM': '#ffcc00', 'LOW': 'good'}.get(severity, '#808080'),
                    'fields': [
                        {'title': 'Type', 'value': alert_type, 'short': True},
                        {'title': 'Severity', 'value': severity, 'short': True},
                        {'title': 'Message', 'value': message, 'short': False}
                    ],
                    'footer': 'net-inspect monitoring',
                    'ts': int(time.time())
                }]
            }

            response = requests.post(self.webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                print(f"  ✓ Webhook alert sent")
            else:
                print(f"  ! Webhook failed: {response.status_code}")

        except Exception as e:
            print(f"  ! Webhook error: {e}")

    def _send_email(self, severity: str, alert_type: str, message: str, details: Any):
        """Send email alert."""
        try:
            msg = MIMEMultipart()
            msg['From'] = 'netinspect@localhost'
            msg['To'] = self.email_to
            msg['Subject'] = f"[{severity}] net-inspect Alert: {alert_type}"

            body = f"""
net-inspect Monitoring Alert

Severity: {severity}
Type: {alert_type}
Time: {datetime.now()}

Message:
{message}

Details:
{json.dumps(details, indent=2)}

---
net-inspect v1.0.0
"""

            msg.attach(MIMEText(body, 'plain'))

            # Send via local SMTP (assumes postfix/sendmail configured)
            server = smtplib.SMTP('localhost')
            server.send_message(msg)
            server.quit()

            print(f"  ✓ Email alert sent to {self.email_to}")

        except Exception as e:
            print(f"  ! Email error: {e}")

    def _send_syslog(self, severity: str, alert_type: str, message: str):
        """Send syslog alert."""
        try:
            priority = {
                'CRITICAL': syslog.LOG_CRIT,
                'HIGH': syslog.LOG_ERR,
                'MEDIUM': syslog.LOG_WARNING,
                'LOW': syslog.LOG_INFO
            }.get(severity, syslog.LOG_NOTICE)

            syslog_message = f"net-inspect: [{severity}] {alert_type}: {message}"

            if self.syslog_server:
                # Remote syslog (requires syslog client)
                # For simplicity, just log locally
                syslog.syslog(priority, syslog_message)
            else:
                syslog.syslog(priority, syslog_message)

            print(f"  ✓ Syslog alert sent")

        except Exception as e:
            print(f"  ! Syslog error: {e}")

    def get_history(self, limit: int = 10) -> List[Dict]:
        """Get scan history from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, total_hosts, new_hosts, missing_hosts,
                   changed_hosts, critical_findings
            FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        conn.close()

        history = []
        for row in rows:
            history.append({
                'timestamp': row[0],
                'total_hosts': row[1],
                'new_hosts': row[2],
                'missing_hosts': row[3],
                'changed_hosts': row[4],
                'critical_findings': row[5]
            })

        return history


def run_daemon(interval: int,
               baseline_file: Optional[str] = None,
               webhook_url: Optional[str] = None,
               email_to: Optional[str] = None,
               syslog_server: Optional[str] = None):
    """
    Convenience function to run monitoring daemon.

    Args:
        interval: Scan interval in seconds
        baseline_file: Path to baseline JSON
        webhook_url: Webhook URL for alerts
        email_to: Email for alerts
        syslog_server: Syslog server
    """
    daemon = MonitorDaemon(
        interval=interval,
        baseline_file=baseline_file,
        webhook_url=webhook_url,
        email_to=email_to,
        syslog_server=syslog_server
    )

    daemon.start()
