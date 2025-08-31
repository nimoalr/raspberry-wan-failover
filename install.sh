#!/usr/bin/env bash
set -euo pipefail

echo "[install] raspberry-wan-failover setup starting"

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF_SRC="$REPO_DIR/raspberry-wan-failover.conf"
CONF_EXAMPLE="$REPO_DIR/raspberry-wan-failover.conf.example"
CONF_DST="/etc/raspberry-wan-failover.conf"

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo ./install.sh" >&2
    exit 1
  fi
}

confirm_config_present() {
  if [[ ! -f "$CONF_SRC" ]]; then
    echo "Config file not found at $CONF_SRC" >&2
    echo "Copy and edit: cp raspberry-wan-failover.conf.example raspberry-wan-failover.conf" >&2
    exit 1
  fi
}

install_config() {
  echo "[install] Installing config to $CONF_DST"
  install -m 0644 "$CONF_SRC" "$CONF_DST"
}

validate_config() {
  echo "[install] Validating config"
  # shellcheck disable=SC1090
  source "$CONF_SRC"
  missing=()
  for v in ETH_IF WLAN_IF TAILS_IF ETH_GW WLAN_GW LAN_NET TAILSCALE_NET; do
    if [[ -z "${!v-}" ]]; then missing+=("$v"); fi
  done
  if (( ${#missing[@]} > 0 )); then
    echo "Missing required vars: ${missing[*]}" >&2
    exit 1
  fi
}

write_sysctl() {
  echo "[install] Enabling IP forwarding"
  cat >/etc/sysctl.d/99-tailscale-forward.conf <<'EOF'
# Enable IPv4 & IPv6 forwarding for subnet routing
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
  sysctl -p /etc/sysctl.d/99-tailscale-forward.conf || true
}

write_scripts() {
  echo "[install] Writing helper scripts to /usr/local/bin"

  cat >/usr/local/bin/wan-routes-setup.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/raspberry-wan-failover.conf

# Ensure tables exist
grep -q "eth0table" /etc/iproute2/rt_tables || echo "100 eth0table" | tee -a /etc/iproute2/rt_tables >/dev/null
grep -q "wlan0table" /etc/iproute2/rt_tables || echo "200 wlan0table" | tee -a /etc/iproute2/rt_tables >/dev/null

# Add default routes to policy tables (idempotent)
ip route add default via "$ETH_GW" dev "$ETH_IF" table eth0table 2>/dev/null || true
ip route add default via "$WLAN_GW" dev "$WLAN_IF" table wlan0table 2>/dev/null || true

# Ensure main default uses ETH_IF initially
ip route replace default via "$ETH_GW" dev "$ETH_IF" || true

# Advertise subnet via Tailscale (requires login)
if command -v tailscale >/dev/null 2>&1; then
  tailscale set --advertise-routes="$TAILSCALE_NET" || true
else
  echo "[wan-routes-setup] tailscale not found; skip advertise"
fi
EOF
  chmod +x /usr/local/bin/wan-routes-setup.sh

  cat >/usr/local/bin/fw_allow_normal.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/raspberry-wan-failover.conf

# Flush FORWARD and set policy ACCEPT
iptables -F FORWARD || true
iptables -P FORWARD ACCEPT || true

# Established/related
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true

# Allow Tailscale <-> LAN
iptables -A FORWARD -i "$TAILS_IF" -o "$ETH_IF" -d "$LAN_NET" -j ACCEPT || true
iptables -A FORWARD -i "$ETH_IF" -o "$TAILS_IF" -s "$LAN_NET" -j ACCEPT || true

# NAT in normal mode (optional)
if [[ "${NAT_ON_NORMAL:-yes}" == "yes" ]]; then
  iptables -t nat -C POSTROUTING -s "$LAN_NET" -o "$ETH_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$LAN_NET" -o "$ETH_IF" -j MASQUERADE
fi
EOF
  chmod +x /usr/local/bin/fw_allow_normal.sh

  cat >/usr/local/bin/fw_failover.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/raspberry-wan-failover.conf

# Lockdown defaults
iptables -F FORWARD || true
iptables -P FORWARD DROP || true

# Established/related
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true

# Allow loopback
iptables -A FORWARD -i lo -j ACCEPT || true

# Allow Tailscale <-> LAN
iptables -A FORWARD -i "$TAILS_IF" -o "$ETH_IF" -d "$LAN_NET" -j ACCEPT || true
iptables -A FORWARD -i "$ETH_IF" -o "$TAILS_IF" -s "$LAN_NET" -j ACCEPT || true

# Backward compatibility for old variable names
if [[ -z "${ALLOWED_IPS:-}" && -n "${ALLOWED_COORD_IP:-}" ]]; then
  ALLOWED_IPS="$ALLOWED_COORD_IP"
fi
if [[ -z "${ALLOWED_TCP_PORTS:-}" && -n "${ALLOWED_COORD_TCP_PORTS:-}" ]]; then
  ALLOWED_TCP_PORTS="$ALLOWED_COORD_TCP_PORTS"
fi

# Allow listed source IPs to reach specific TCP ports
if [[ -n "${ALLOWED_IPS:-}" && -n "${ALLOWED_TCP_PORTS:-}" ]]; then
  for ip in $ALLOWED_IPS; do
    for p in $ALLOWED_TCP_PORTS; do
      iptables -A FORWARD -s "$ip" -p tcp --dport "$p" -j ACCEPT || true
    done
  done
fi

# Handle renamed/misspelled block list variables
if [[ -z "${BLOCKED_INTERNET_ACCESS_IPS:-}" ]]; then
  if [[ -n "${BLOCKED_INTERNET_ACCES_IPS:-}" ]]; then
    BLOCKED_INTERNET_ACCESS_IPS="$BLOCKED_INTERNET_ACCES_IPS"
  elif [[ -n "${BLOCKED_IPS:-}" ]]; then
    BLOCKED_INTERNET_ACCESS_IPS="$BLOCKED_IPS"
  fi
fi

# Block listed IPs from leaving to internet
if [[ -n "${BLOCKED_INTERNET_ACCESS_IPS:-}" ]]; then
  for c in $BLOCKED_INTERNET_ACCESS_IPS; do
    iptables -A FORWARD -s "$c" -j REJECT || true
  done
fi

# NAT LAN -> WLAN_IF in failover (optional)
if [[ "${NAT_ON_FAILOVER:-yes}" == "yes" ]]; then
  iptables -t nat -C POSTROUTING -s "$LAN_NET" -o "$WLAN_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$LAN_NET" -o "$WLAN_IF" -j MASQUERADE
fi
EOF
  chmod +x /usr/local/bin/fw_failover.sh

  cat >/usr/local/bin/wan-failover.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/raspberry-wan-failover.conf

log() { logger -t wan-failover "$*"; echo "$(date -Iseconds) $*"; }

IFS=' ' read -r -a CHECK_ARRAY <<<"${CHECK_HOSTS:-1.1.1.1 8.8.8.8}"

ping_check() {
  for h in "${CHECK_ARRAY[@]}"; do
    if ping -I "$ETH_IF" -c "${PING_COUNT:-2}" -W "${PING_TIMEOUT:-2}" "$h" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

STATE_FILE_PATH="${STATE_FILE:-/var/run/wan-failover.state}"
CURRENT_STATE="$(cat "$STATE_FILE_PATH" 2>/dev/null || echo up)"
LAST_SWITCH_TS=0

while true; do
  if ping_check; then
    if [[ "$CURRENT_STATE" == "down" ]]; then
      ok=0
      checks=$(( ${DELAY_UP:-30} / 5 )); [[ $checks -lt 1 ]] && checks=1
      for _ in $(seq 1 $checks); do
        sleep 5
        if ping_check; then ok=$((ok+1)); else ok=0; fi
        [[ $ok -ge $checks ]] && break
      done
      if [[ $ok -ge $checks ]]; then
        NOW=$(date +%s)
        if [[ $((NOW - LAST_SWITCH_TS)) -ge ${COOLDOWN:-60} ]]; then
          log "ETH restored — switching default back to $ETH_IF ($ETH_GW)"
          /sbin/ip route replace default via "$ETH_GW" dev "$ETH_IF" || true
          /usr/local/bin/fw_allow_normal.sh || true
          CURRENT_STATE="up"
          echo "$CURRENT_STATE" >"$STATE_FILE_PATH"
          LAST_SWITCH_TS=$NOW
        fi
      fi
    fi
  else
    if [[ "$CURRENT_STATE" == "up" ]]; then
      bad=0
      checks=$(( ${DELAY_DOWN:-10} / 2 )); [[ $checks -lt 1 ]] && checks=1
      for _ in $(seq 1 $checks); do
        sleep 2
        if ! ping_check; then bad=$((bad+1)); else bad=0; fi
        [[ $bad -ge $checks ]] && break
      done
      if [[ $bad -ge $checks ]]; then
        NOW=$(date +%s)
        if [[ $((NOW - LAST_SWITCH_TS)) -ge ${COOLDOWN:-60} ]]; then
          log "ETH failed — switching default to $WLAN_IF ($WLAN_GW)"
          /sbin/ip route replace default via "$WLAN_GW" dev "$WLAN_IF" || true
          /usr/local/bin/fw_failover.sh || true
          CURRENT_STATE="down"
          echo "$CURRENT_STATE" >"$STATE_FILE_PATH"
          LAST_SWITCH_TS=$NOW
        fi
      fi
    fi
  fi
  sleep 5
done
EOF
  chmod +x /usr/local/bin/wan-failover.sh

  # Tiny HTTP health endpoint (socket-activated via systemd)
  cat >/usr/local/bin/wan-health.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/raspberry-wan-failover.conf

STATE_FILE_PATH="${STATE_FILE:-/var/run/wan-failover.state}"
STATE_VALUE="$(cat "$STATE_FILE_PATH" 2>/dev/null || echo up)"

# Read the first request line (e.g., GET /health HTTP/1.1)
read -r REQUEST_LINE || REQUEST_LINE=""
REQ_PATH="/"
if [[ "$REQUEST_LINE" =~ ^[A-Z]+[[:space:]]([^[:space:]]+) ]]; then
  REQ_PATH="${BASH_REMATCH[1]}"
fi

STATUS="ok"
[[ "$STATE_VALUE" == "down" ]] && STATUS="failover"

if [[ "$REQ_PATH" == "/" || "$REQ_PATH" == "/health" || "$REQ_PATH" == "/healthz" || "$REQ_PATH" == "/status" ]]; then
  BODY="{\"state\":\"$STATE_VALUE\",\"status\":\"$STATUS\"}"
  printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "${#BODY}" "$BODY"
else
  BODY='{"error":"not found"}'
  printf 'HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "${#BODY}" "$BODY"
fi
EOF
  chmod +x /usr/local/bin/wan-health.sh
}

write_units() {
  echo "[install] Writing systemd units"
  cat >/etc/systemd/system/wan-routes.service <<'EOF'
[Unit]
Description=Add WAN policy routes and advertise tailscale subnet
After=network-online.target tailscaled.service
Wants=network-online.target tailscaled.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wan-routes-setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/wan-failover.service <<'EOF'
[Unit]
Description=WAN failover manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wan-failover.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  # Health endpoint units (socket-activated per connection)
  # shellcheck disable=SC1090
  source "$CONF_SRC"
  HEALTH_BIND_VAL="${HEALTH_BIND:-0.0.0.0}"
  HEALTH_PORT_VAL="${HEALTH_PORT:-8080}"
  HEALTH_BIND_DEVICE_VAL="${HEALTH_BIND_DEVICE:-}"

  cat >/etc/systemd/system/wan-health@.service <<'EOF'
[Unit]
Description=WAN health HTTP endpoint (per-connection)
After=network.target

[Service]
Type=simple
StandardInput=socket
StandardOutput=socket
ExecStart=/usr/local/bin/wan-health.sh
EOF

  if [[ -n "$HEALTH_BIND_DEVICE_VAL" ]]; then
    BIND_LINE="BindToDevice=$HEALTH_BIND_DEVICE_VAL"
  else
    BIND_LINE=""
  fi

  cat >/etc/systemd/system/wan-health.socket <<EOF
[Unit]
Description=WAN health HTTP socket
After=network-online.target
Wants=network-online.target

[Socket]
Accept=true
ListenStream=${HEALTH_BIND_VAL}:${HEALTH_PORT_VAL}
NoDelay=true
${BIND_LINE}

[Install]
WantedBy=sockets.target
EOF
}

enable_services() {
  echo "[install] Enabling and starting services"
  systemctl daemon-reload
  systemctl enable --now wan-routes.service
  systemctl enable --now wan-failover.service
  systemctl enable --now wan-health.socket
}

require_root
confirm_config_present
validate_config
install_config
write_sysctl
write_scripts
write_units
enable_services

echo "[install] Done. Remember to approve $TAILSCALE_NET in Tailscale admin if required."
