#!/usr/bin/env bash
set -euo pipefail

echo "[uninstall] raspberry-wan-failover removal starting"

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo ./uninstall.sh" >&2
    exit 1
  fi
}

stop_disable() {
  systemctl stop wan-health.socket 2>/dev/null || true
  systemctl stop wan-failover.service 2>/dev/null || true
  systemctl stop wan-routes.service 2>/dev/null || true
  systemctl disable wan-health.socket 2>/dev/null || true
  systemctl disable wan-failover.service 2>/dev/null || true
  systemctl disable wan-routes.service 2>/dev/null || true
}

remove_units() {
  rm -f /etc/systemd/system/wan-health.socket
  rm -f /etc/systemd/system/wan-health@.service
  rm -f /etc/systemd/system/wan-failover.service
  rm -f /etc/systemd/system/wan-routes.service
  systemctl daemon-reload
}

remove_scripts() {
  rm -f /usr/local/bin/wan-health.sh
  rm -f /usr/local/bin/wan-failover.sh
  rm -f /usr/local/bin/wan-routes-setup.sh
  rm -f /usr/local/bin/fw_allow_normal.sh
  rm -f /usr/local/bin/fw_failover.sh
}

remove_sysctl() {
  rm -f /etc/sysctl.d/99-tailscale-forward.conf
  sysctl -p 2>/dev/null || true
}

remove_config() {
  rm -f /etc/raspberry-wan-failover.conf
  rm -f /var/run/wan-failover.state
}

require_root
stop_disable
remove_units
remove_scripts
remove_sysctl
remove_config

echo "[uninstall] Completed. You may want to clean any custom lines in /etc/iproute2/rt_tables (eth0table/wlan0table) manually if no longer needed."
