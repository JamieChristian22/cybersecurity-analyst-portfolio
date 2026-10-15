#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-security_audit_report.txt}"
{
  echo "LINUX SECURITY AUDIT REPORT"
  echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo
  echo "== System =="
  uname -a || true
  echo
  echo "== Effective User =="
  id || true
  echo
  echo "== Listening Ports =="
  if command -v ss >/dev/null 2>&1; then ss -tuln || true
  elif command -v netstat >/dev/null 2>&1; then netstat -tuln || true
  else echo "ss/netstat not available"; fi
  echo
  echo "== Firewall Status =="
  if command -v ufw >/dev/null 2>&1; then ufw status || true
  elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state || true
  else echo "No supported firewall CLI detected"; fi
  echo
  echo "== SSH Hardening Signals =="
  if [ -f /etc/ssh/sshd_config ]; then
    grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries)' /etc/ssh/sshd_config || true
  else echo "/etc/ssh/sshd_config not present"; fi
  echo
  echo "== UID 0 Accounts =="
  awk -F: '($3 == 0) {print $1 ":" $3 ":" $7}' /etc/passwd || true
  echo
  echo "== World-Writable Files in /etc and /var/tmp (limited scan) =="
  find /etc /var/tmp -xdev -type f -perm -0002 2>/dev/null | head -n 100 || true
  echo
  echo "== Enabled Services (first 50) =="
  if command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -n 55 || true
  else echo "systemctl not available"; fi
  echo
  echo "== Disk Usage =="
  df -h || true
  echo
  echo "== Recent Account Entries =="
  tail -n 10 /etc/passwd || true
} > "$OUT"

echo "Audit report written to $OUT"
