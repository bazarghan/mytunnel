#!/usr/bin/env bash
# Removes HLTunnel completely: service, tunnels, forwarding rules, kernel
# tuning, configuration and the program.
#
#   curl -fsSL https://raw.githubusercontent.com/bazarghan/mytunnel/main/uninstall.sh | sudo bash
#
# Add "-s -- --keep-config" to keep /etc/hltunnel (keys, tunnels, panel).
set -euo pipefail

KEEP=0
[ "${1:-}" = "--keep-config" ] && KEEP=1
[ "$(id -u)" -eq 0 ] || { echo "run as root: ... | sudo bash" >&2; exit 1; }

if [ -x /usr/local/bin/hltunnel ]; then
  if [ "$KEEP" = 1 ]; then
    /usr/local/bin/hltunnel uninstall -y --keep-config || true
  else
    /usr/local/bin/hltunnel uninstall -y || true
  fi
else
  systemctl disable --now hltunnel 2>/dev/null || true
  rm -f /etc/systemd/system/hltunnel.service
  systemctl daemon-reload 2>/dev/null || true
  if command -v nft >/dev/null 2>&1; then
    for tbl in hltunnel hltunnel_ipsec hltunnel_fetch hltunnel_raw hltunnel_plans hltunnel_seen hltunnel_guard; do
      nft delete table inet "$tbl" 2>/dev/null || true
    done
  fi
  while ip rule del pref 7700 2>/dev/null; do :; done
  while ip -6 rule del pref 7700 2>/dev/null; do :; done
  for l in $(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^hlx?-/ {print $2}' | cut -d@ -f1); do ip link del "$l" 2>/dev/null || true; done
  [ "$KEEP" = 1 ] || rm -rf /etc/hltunnel /etc/sysctl.d/90-hltunnel.conf /etc/modules-load.d/hltunnel.conf
fi
rm -f /usr/local/bin/hltunnel
echo "HLTunnel removed."
[ "$KEEP" = 1 ] && echo "Configuration kept in /etc/hltunnel."
exit 0
