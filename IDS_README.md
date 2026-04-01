Intrusion Detection & Forensic Analysis System
===============================================

A comprehensive security monitoring tool that detects, analyzes, and reports on potential intrusions and security anomalies.

## Features

**Intrusion Detection:**
- Authentication log analysis (failed logins, root access, sudo abuse)
- Network connection monitoring (suspicious IPs, open ports)
- Suspicious process detection (reverse shells, code injection patterns)
- File integrity monitoring with baseline comparison

**Forensic Analysis:**
- Comprehensive daily security reports
- SQLite event database with historical tracking
- File modification detection with hash comparison
- Permission change notifications
- Email alerts for critical events

**Prevention & Response:**
- Baseline establishment for critical system files
- Automated alerting via email
- Daily cron scheduling support
- GitHub Actions integration for automated runs

## Quick Start

### 1. Initial Setup

```bash
# Copy script to home directory (already done)
cp ids_forensics.py ~/

# Establish system baseline (run once)
sudo python3 ~/ids_forensics.py --baseline

# You'll see: "Baseline established with X files"
```

### 2. Run First Scan

```bash
# Full forensic analysis with report
sudo python3 ~/ids_forensics.py --full-scan

# Output: JSON report in ~/.ids_reports/
```

### 3. Check File Integrity

```bash
# Compare against baseline
sudo python3 ~/ids_forensics.py --check

# Alerts on any modifications
```

## Usage

### Command-line Options

```bash
python3 ids_forensics.py --baseline
    Create baseline snapshot of critical system files
    
python3 ids_forensics.py --check
    Check if any monitored files have been modified since baseline
    
python3 ids_forensics.py --full-scan
    Run complete analysis: auth logs, network, processes, file integrity
    Generate JSON forensic report
    
python3 ids_forensics.py --full-scan --alert-email you@example.com
    Run full scan and email report to specified address
```

## Daily Automated Monitoring

### Option 1: Cron (Recommended for local systems)

Add to root crontab:

```bash
sudo crontab -e

# Add this line: run daily at 02:00 AM
0 2 * * * /usr/bin/python3 /Users/shabbir/ids_forensics.py --full-scan >> /var/log/ids_forensics.log 2>&1
```

### Option 2: GitHub Actions (Recommended for centralized monitoring)

**You can set up automated daily runs in GitHub.**

Create `.github/workflows/daily_ids_scan.yml`:

```yaml
name: Daily IDS Forensic Scan

on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM UTC daily
  workflow_dispatch: {}

jobs:
  scan:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Run IDS Forensic Scan
        env:
          SMTP_SERVER: ${{ secrets.SMTP_SERVER }}
          SMTP_PORT: ${{ secrets.SMTP_PORT }}
          SMTP_USERNAME: ${{ secrets.SMTP_USERNAME }}
          SMTP_PASSWORD: ${{ secrets.SMTP_PASSWORD }}
          EMAIL_FROM: ${{ secrets.EMAIL_FROM }}
          EMAIL_TO: ${{ secrets.EMAIL_TO }}
        run: |
          python3 ids_forensics.py --full-scan --alert-email "$EMAIL_TO"
```

## Output & Reports

### Report Location
```
~/.ids_reports/forensic_report_YYYYMMDD_HHMMSS.json
```

### Report Contents
```json
{
  "timestamp": "2026-04-01T...",
  "hostname": "your-machine",
  "auth_analysis": {
    "failed_logins": {"user@ip": count},
    "root_logins": [...],
    "sudo_abuse": [...]
  },
  "network_analysis": {
    "listening_ports": [...],
    "suspicious_ips": [...]
  },
  "file_integrity": ["MODIFIED: /etc/passwd"],
  "process_analysis": [...suspicious processes...],
  "recent_events": [...]
}
```

### Event Database
```
~/.ids_forensics.db (SQLite)
  - events table: timestamp, severity, type, description, details
  - file_hashes table: tracked files with hashes and permissions
  - network_baseline table: established services and ports
```

## Email Alerts (Optional)

To receive daily reports via email, set environment variables:

```bash
export SMTP_SERVER=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=your-email@gmail.com
export SMTP_PASSWORD=your-app-password
export EMAIL_FROM=your-email@gmail.com
export EMAIL_TO=recipient@example.com

python3 ids_forensics.py --full-scan --alert-email $EMAIL_TO
```

**Popular SMTP Servers:**
- Gmail: smtp.gmail.com (use App Password)
- Outlook: smtp-mail.outlook.com
- Office 365: smtp.office365.com
- SendGrid: smtp.sendgrid.net

## Security Analysis Capabilities

### Authentication Analysis
- Detects brute-force attacks (5+ failed logins = ALERT)
- Tracks direct root SSH logins
- Monitors sudo privilege escalation
- Identifies new user account creation

### Network Monitoring
- Lists all listening ports and services
- Tracks established connections
- Alerts on suspicious outbound connections to external IPs
- Identifies unusual port activity

### File Integrity
- Monitors critical files:
  - `/etc/passwd`, `/etc/shadow`
  - `/etc/sudoers`, `/etc/ssh/sshd_config`
  - SSH authorized_keys
  - System crontabs
- Detects modifications, permissions changes, deletions
- Compares against baseline using SHA256 hashing

### Process Detection
- Identifies reverse shells and backdoors
- Detects code injection attempts
- Alerts on suspicious pipe chains (curl|bash, wget|bash)
- Finds encoded command execution

## Interpreting Results

### Severity Levels
- **CRITICAL**: Immediate action required (file modifications, unauthorized access)
- **HIGH**: Investigate promptly (brute force, suspicious processes)
- **MEDIUM**: Monitor carefully (auth anomalies, permission changes)
- **LOW**: Routine information

### Common Alerts

```
FAILED_LOGIN_FLOOD: Multiple failed login attempts
  → Check if account is being targeted; consider IP blocking

ROOT_LOGIN: Direct SSH as root
  → Review SSH config; disable direct root login

FILE_MODIFIED: Critical system file changed
  → Run filesystem recovery if unauthorized

SUSPICIOUS_PROCESS: Reverse shell or injection detected
  → Kill process immediately; investigate source

SUSPICIOUS_CONNECTION: Outbound to external IP
  → Review process; may indicate data exfiltration or C&C contact
```

## Limitations & Notes

- Requires **sudo access** for full auth log and system file analysis
- On macOS, some tools (netstat) may have limited output
- File integrity checks use SHA256 (resistant to accidental changes)
- Host-based detection only (does not detect network attacks)
- Does not prevent attacks in real-time (alerts after incident)

## Best Practices

1. **Establish baseline immediately** after fresh system setup
2. **Review reports regularly** - don't ignore alerts
3. **Combine with network IDS** (Suricata, Zeek) for comprehensive coverage
4. **Update baseline** when making legitimate system changes
5. **Keep reports for forensics** - archive to secure storage
6. **Test email alerts** to ensure they work before relying on them
7. **Use with 2FA and SSH keys** - additional access controls
8. **Monitor disk space** - database and reports grow over time

## Troubleshooting

**"Permission denied reading auth logs"**
```bash
# Run with sudo
sudo python3 ids_forensics.py --full-scan
```

**"Baseline not found"**
```bash
# Establish baseline first
sudo python3 ids_forensics.py --baseline
```

**"No email alerts"**
- Verify SMTP environment variables are set
- Test SMTP credentials manually
- Check firewall/network access to SMTP server

**"False positives"**
- Review file modifications (may be from package updates)
- Add processes to whitelist if needed
- Update baseline after verified system changes

## Advanced Usage

### Export Events to CSV

```python
import sqlite3
import csv

conn = sqlite3.connect(os.path.expanduser('~/.ids_forensics.db'))
c = conn.cursor()
c.execute('SELECT * FROM events')
rows = c.fetchall()

with open('events.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerows(rows)
```

### Create Custom Analysis Rules

Extend the script to add:
- SELinux policy violations
- AppArmor alerts
- Kernel audit logs
- Firewall rule changes
- Binary execution tracking

## Legal & Ethical Use

- Use this tool **only on systems you own or have permission to monitor**
- Do not use for unauthorized surveillance or monitoring
- Comply with all local privacy and security regulations
- Keep analysis reports confidential
- Use forensic findings responsibly in incident response

## Future Enhancements

- Real-time alert notifications (Slack, PagerDuty)
- Machine learning anomaly detection
- Rootkit detection capabilities
- Endpoint Detection & Response (EDR) integration
- Compliance reporting (SOC 2, HIPAA, PCI-DSS)
- Splunk/ELK integration for centralized logging

## Support & Questions

For issues or suggestions, refer to incident response procedures and system security documentation.

---
*Last Updated: 2026-04-01*
*Disclaimer: This tool is for defensive security on authorized systems only.*
