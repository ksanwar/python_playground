#!/bin/bash
# IDS Forensics Setup Script

set -e

echo "=================================="
echo "IDS Forensics Setup"
echo "=================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/ids_forensics.py"

if [ ! -f "$SCRIPT_PATH" ]; then
    echo "Error: ids_forensics.py not found in $SCRIPT_DIR"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required"
    exit 1
fi

echo "[1/5] Creating database and baseline..."
sudo python3 "$SCRIPT_PATH" --baseline

echo ""
echo "[2/5] Running initial scan..."
sudo python3 "$SCRIPT_PATH" --full-scan

echo ""
echo "[3/5] Setting up daily cron job..."
CRON_JOB="0 2 * * * /usr/bin/python3 $SCRIPT_PATH --full-scan >> /var/log/ids_forensics.log 2>&1"

# Check if cron job already exists
if sudo crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
    echo "Cron job already installed"
else
    (sudo crontab -l 2>/dev/null || echo "") | sudo tee /tmp/crontab.tmp > /dev/null
    echo "$CRON_JOB" | sudo tee -a /tmp/crontab.tmp > /dev/null
    sudo crontab -i /tmp/crontab.tmp 2>/dev/null || sudo crontab /tmp/crontab.tmp
    rm /tmp/crontab.tmp
    echo "✓ Cron job installed (runs daily at 2:00 AM)"
fi

echo ""
echo "[4/5] Directory setup..."
mkdir -p ~/.ids_reports
echo "✓ Reports directory: ~/.ids_reports"

echo ""
echo "[5/5] Configuration summary..."
echo "=================================="
echo "Setup complete!"
echo ""
echo "Next steps:"
echo ""
echo "1. Review the first report:"
echo "   ls -la ~/.ids_reports/"
echo ""
echo "2. To manually run a scan:"
echo "   sudo python3 $SCRIPT_PATH --full-scan"
echo ""
echo "3. To check file integrity:"
echo "   sudo python3 $SCRIPT_PATH --check"
echo ""
echo "4. For email alerts, set environment variables:"
echo "   export SMTP_SERVER=smtp.gmail.com"
echo "   export SMTP_USERNAME=your-email@gmail.com"
echo "   export SMTP_PASSWORD=your-app-password"
echo "   export EMAIL_FROM=your-email@gmail.com"
echo "   Then run: sudo python3 $SCRIPT_PATH --full-scan --alert-email user@example.com"
echo ""
echo "5. View database of all security events:"
echo "   sqlite3 ~/.ids_forensics.db 'SELECT * FROM events;'"
echo ""
echo "See IDS_README.md for full documentation"
echo "=================================="
