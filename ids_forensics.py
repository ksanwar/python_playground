"""
Intrusion Detection & Forensic Analysis System

Features:
- System log analysis (auth logs, suspicious activity)
- Network connection monitoring
- File integrity monitoring
- Process anomaly detection
- Comprehensive forensic reporting
- Daily automated analysis

Usage: python ids_forensics.py [--baseline] [--check] [--alert-email user@example.com]
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

DB_PATH = os.path.expanduser('~/.ids_forensics.db')
BASELINE_PATH = os.path.expanduser('~/.ids_baseline.json')
REPORT_DIR = os.path.expanduser('~/.ids_reports')


def init_db():
    """Initialize SQLite database for tracking events."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT,
        severity TEXT,
        description TEXT,
        source TEXT,
        details TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS file_hashes (
        path TEXT PRIMARY KEY,
        hash TEXT,
        last_checked DATETIME,
        size INTEGER,
        permissions TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS network_baseline (
        port INTEGER,
        protocol TEXT,
        service TEXT,
        first_seen DATETIME,
        PRIMARY KEY (port, protocol)
    )''')
    
    conn.commit()
    conn.close()


def log_event(event_type, severity, description, source, details=''):
    """Log security event to database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO events (event_type, severity, description, source, details)
                 VALUES (?, ?, ?, ?, ?)''',
              (event_type, severity, description, source, details))
    conn.commit()
    conn.close()
    
    if severity in ['CRITICAL', 'HIGH']:
        logging.warning(f"{severity}: {event_type} - {description}")
    else:
        logging.info(f"{severity}: {event_type} - {description}")


def analyze_auth_logs():
    """Analyze authentication logs for suspicious activity."""
    suspicious = {
        'failed_logins': defaultdict(int),
        'root_logins': [],
        'sudo_abuse': [],
        'new_users': [],
    }
    
    try:
        if os.path.exists('/var/log/auth.log'):
            auth_log = '/var/log/auth.log'
        elif os.path.exists('/var/log/secure'):
            auth_log = '/var/log/secure'
        else:
            logging.warning('Auth log not found')
            return suspicious
        
        # Get last 24 hours of logs
        cutoff = datetime.datetime.now() - datetime.timedelta(days=1)
        
        with open(auth_log, 'r', errors='ignore') as f:
            for line in f:
                if 'Failed password' in line or 'authentication failure' in line:
                    match = re.search(r'for (\w+) from ([\d.]+)', line)
                    if match:
                        user, ip = match.groups()
                        suspicious['failed_logins'][f"{user}@{ip}"] += 1
                
                if 'Accepted' in line and 'root' in line and 'ssh' in line:
                    suspicious['root_logins'].append(line.strip())
                
                if 'sudo' in line and 'COMMAND' in line:
                    suspicious['sudo_abuse'].append(line.strip())
                
                if 'new user' in line.lower() or 'add user' in line.lower():
                    suspicious['new_users'].append(line.strip())
    
    except PermissionError:
        logging.warning('Permission denied reading auth logs. Run with sudo for full analysis.')
    
    # Alert on thresholds
    for (user_ip, count) in suspicious['failed_logins'].items():
        if count >= 5:
            log_event('FAILED_LOGIN_FLOOD', 'HIGH', 
                     f'{count} failed login attempts for {user_ip}',
                     'auth_logs', f"Failed logins: {count}")
    
    if suspicious['root_logins']:
        log_event('ROOT_LOGIN', 'MEDIUM', 
                 f'{len(suspicious["root_logins"])} direct root logins detected',
                 'auth_logs', '\n'.join(suspicious['root_logins'][:3]))
    
    return suspicious


def analyze_network():
    """Analyze network connections and open ports."""
    network_issues = {
        'listening_ports': [],
        'established_connections': [],
        'suspicious_ips': [],
    }
    
    try:
        # Get listening ports
        result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        proto_addr = parts[3]
                        network_issues['listening_ports'].append(proto_addr)
        
        # Get established connections
        result = subprocess.run(['netstat', '-tnp'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        remote = parts[4]
                        network_issues['established_connections'].append(remote)
                        
                        # Flag suspicious IPs (non-private, unusual ports)
                        ip = remote.split(':')[0]
                        if not is_private_ip(ip):
                            network_issues['suspicious_ips'].append(remote)
    
    except Exception as e:
        logging.debug(f"Network analysis failed: {e}")
    
    # Alert on suspicious connections
    if network_issues['suspicious_ips']:
        log_event('SUSPICIOUS_CONNECTION', 'MEDIUM',
                 f'{len(network_issues["suspicious_ips"])} outbound connections to external IPs',
                 'network', ', '.join(network_issues['suspicious_ips'][:5]))
    
    return network_issues


def is_private_ip(ip):
    """Check if IP is private."""
    private_ranges = [
        '10.',
        '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        '192.168.',
        '127.',
        'localhost',
    ]
    return any(ip.startswith(r) for r in private_ranges)


def file_hash(filepath):
    """Compute SHA256 hash of file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except Exception as e:
        logging.debug(f"Failed to hash {filepath}: {e}")
        return None


def establish_baseline():
    """Create baseline of critical files and system state."""
    baseline = {
        'timestamp': datetime.datetime.now().isoformat(),
        'files': {},
        'packages': [],
    }
    
    # Critical files to monitor
    critical_files = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/sshd_config',
        '/etc/crontab',
        '/root/.ssh/authorized_keys',
        os.path.expanduser('~/.ssh/authorized_keys'),
    ]
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    for filepath in critical_files:
        if os.path.exists(filepath):
            try:
                hash_val = file_hash(filepath)
                size = os.path.getsize(filepath)
                perms = oct(os.stat(filepath).st_mode)[-3:]
                
                baseline['files'][filepath] = {
                    'hash': hash_val,
                    'size': size,
                    'permissions': perms,
                }
                
                c.execute('''INSERT OR REPLACE INTO file_hashes (path, hash, size, permissions, last_checked)
                           VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                         (filepath, hash_val, size, perms))
            except PermissionError:
                logging.warning(f"Permission denied for {filepath}")
    
    conn.commit()
    conn.close()
    
    # Save baseline
    os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
    with open(BASELINE_PATH, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    logging.info(f"Baseline established with {len(baseline['files'])} files")
    return baseline


def check_file_integrity():
    """Check if critical files have been modified."""
    if not os.path.exists(BASELINE_PATH):
        logging.warning("No baseline found. Run with --baseline first")
        return
    
    with open(BASELINE_PATH, 'r') as f:
        baseline = json.load(f)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    modifications = []
    
    for filepath, baseline_info in baseline['files'].items():
        if not os.path.exists(filepath):
            log_event('FILE_DELETED', 'HIGH', f'Critical file deleted: {filepath}', 'file_integrity')
            modifications.append(f"DELETED: {filepath}")
            continue
        
        current_hash = file_hash(filepath)
        current_size = os.path.getsize(filepath)
        current_perms = oct(os.stat(filepath).st_mode)[-3:]
        
        if current_hash != baseline_info['hash']:
            log_event('FILE_MODIFIED', 'HIGH', f'Critical file modified: {filepath}', 'file_integrity',
                     f"Hash changed: {baseline_info['hash'][:8]}→{current_hash[:8]}")
            modifications.append(f"MODIFIED: {filepath}")
        
        if current_perms != baseline_info['permissions']:
            log_event('PERMISSION_CHANGED', 'MEDIUM', f'Permissions changed: {filepath}', 'file_integrity',
                     f"{baseline_info['permissions']} → {current_perms}")
        
        c.execute('''INSERT OR REPLACE INTO file_hashes (path, hash, size, permissions, last_checked)
                   VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                 (filepath, current_hash, current_size, current_perms))
    
    conn.commit()
    conn.close()
    
    if modifications:
        logging.warning(f"File integrity issues detected: {modifications}")
    else:
        logging.info("File integrity check passed")
    
    return modifications


def analyze_processes():
    """Detect suspicious processes."""
    suspicious = []
    
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
        
        suspicious_patterns = [
            r'nc\s+-l',  # netcat listener
            r'ncat\s+-l',
            r'/dev/tcp',  # bash network redirection
            r'curl\s+.*\|.*bash',  # curl piped to shell
            r'wget\s+.*\|.*bash',
            r'base64.*exec',  # encoded execution
            r'eval\s*\(',
        ]
        
        for line in result.stdout.split('\n'):
            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    suspicious.append(line.strip())
                    log_event('SUSPICIOUS_PROCESS', 'HIGH', f'Detected suspicious process', 'process_analysis', line)
    
    except Exception as e:
        logging.debug(f"Process analysis failed: {e}")
    
    return suspicious


def generate_report():
    """Generate comprehensive forensic report."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    
    report_file = os.path.join(REPORT_DIR, f"forensic_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'hostname': subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(),
        'auth_analysis': analyze_auth_logs(),
        'network_analysis': analyze_network(),
        'file_integrity': check_file_integrity(),
        'process_analysis': analyze_processes(),
    }
    
    # Get recent events from database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT event_type, severity, description, timestamp FROM events ORDER BY timestamp DESC LIMIT 100')
    events = [dict(zip([x[0] for x in c.description], row)) for row in c.fetchall()]
    report['recent_events'] = events
    conn.close()
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logging.info(f"Report saved to {report_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("FORENSIC ANALYSIS REPORT")
    print("="*60)
    print(f"Timestamp: {report['timestamp']}")
    print(f"Hostname: {report['hostname']}")
    print(f"\nFailed Login Attempts: {sum(report['auth_analysis']['failed_logins'].values())}")
    print(f"Root Logins Detected: {len(report['auth_analysis']['root_logins'])}")
    print(f"Listening Ports: {len(report['network_analysis']['listening_ports'])}")
    print(f"External Connections: {len(report['network_analysis']['suspicious_ips'])}")
    print(f"File Modifications: {len(report['file_integrity']) if report['file_integrity'] else 0}")
    print(f"Suspicious Processes: {len(report['process_analysis'])}")
    print(f"Recent Security Events: {len(events)}")
    
    if events:
        print("\nLatest Events:")
        for event in events[:5]:
            print(f"  [{event['severity']}] {event['event_type']}: {event['description']}")
    
    print("="*60 + "\n")
    
    return report_file


def main():
    parser = argparse.ArgumentParser(description='Intrusion Detection & Forensic Analysis')
    parser.add_argument('--baseline', action='store_true', help='Establish file baseline')
    parser.add_argument('--check', action='store_true', help='Check file integrity')
    parser.add_argument('--alert-email', help='Email address for alerts')
    parser.add_argument('--full-scan', action='store_true', help='Run full analysis with report')
    args = parser.parse_args()
    
    init_db()
    
    if args.baseline:
        establish_baseline()
    
    if args.check:
        check_file_integrity()
    
    if args.full_scan or (not args.baseline and not args.check):
        report_file = generate_report()
        
        if args.alert_email:
            send_alert_email(args.alert_email, report_file)


def send_alert_email(email, report_file):
    """Send alert email with report."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders
    
    smtp_server = os.environ.get('SMTP_SERVER')
    if not smtp_server:
        logging.warning('SMTP_SERVER not configured. Skipping email alert.')
        return
    
    try:
        msg = MIMEText(f"IDS daily scan completed. See attached report.")
        msg['Subject'] = "Security Alert: Daily IDS Forensic Report"
        msg['From'] = os.environ.get('EMAIL_FROM', 'ids@localhost')
        msg['To'] = email
        
        with open(report_file, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename= {os.path.basename(report_file)}')
            msg.attach(part)
        
        with smtplib.SMTP(smtp_server, int(os.environ.get('SMTP_PORT', 587)), timeout=30) as server:
            server.starttls()
            if os.environ.get('SMTP_USERNAME'):
                server.login(os.environ.get('SMTP_USERNAME'), os.environ.get('SMTP_PASSWORD'))
            server.send_message(msg)
        
        logging.info(f"Alert email sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send alert email: {e}")


if __name__ == '__main__':
    main()
