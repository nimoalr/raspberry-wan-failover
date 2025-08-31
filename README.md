# raspberry-wan-failover

Turn a Raspberry Pi 5 running Raspbian into a remote location gateway powered by Tailscale subnet routing, simple firewall profiles, and WAN failover management with health-check endpoint.

Allows me to be notified with Uptime Kuma if my remote primary WAN is down and now on failover WAN. 

This repo contains two standalone scripts:
- install.sh — installs config, helper scripts, and systemd services
- uninstall.sh — removes all installed files and services

Configuration is centralized in `/etc/raspberry-wan-failover.conf` (templated in this repo as `raspberry-wan-failover.conf.example`).

## Quick start

1) Edit the config

- Copy the example and customize values (interfaces, gateways, LAN subnet, etc.).

```sh
cp raspberry-wan-failover.conf.example raspberry-wan-failover.conf
nano raspberry-wan-failover.conf
```

2) Install (on the Pi)

```sh
sudo ./install.sh
```

What it does:
- Enables IPv4/IPv6 forwarding via sysctl
- Installs `/etc/raspberry-wan-failover.conf`
- Installs helper scripts to `/usr/local/bin`:
	- wan-routes-setup.sh (policy routes + tailscale advertise-routes)
	- fw_allow_normal.sh (normal operation rules)
	- fw_failover.sh (failover operation rules)
	- wan-failover.sh (daemon that switches between profiles)
- Creates and enables systemd services:
	- wan-routes.service (oneshot at boot)
	- wan-failover.service (long-running)
	- wan-health.socket + wan-health@.service (socket-activated tiny HTTP endpoint)

3) Approve the subnet route in Tailscale

- In the Tailscale Admin Console, approve the route you configured (e.g. `192.168.20.0/24`).

4) Test

- From a Tailscale client, ping a host in your LAN subnet.
- Simulate failover: `sudo ip link set eth0 down`. The service should switch to wlan0, apply `fw_failover.sh`, and continue to allow Tailscale <-> LAN access. Restore with `sudo ip link set eth0 up`.

## Uninstall

```sh
sudo ./uninstall.sh
```

Removes services, helper scripts, sysctl entry, and config. Leaves your `/etc/iproute2/rt_tables` untouched except for a note in the output.

## Notes

- NAT is disabled by default in both modes; opt in per mode via `NAT_ON_NORMAL` and `NAT_ON_FAILOVER` if this Pi should provide internet egress.
- Tailscale subnet routers SNAT by default; you may disable with `tailscale up --snat-subnet-routes=false` if you manage routes on your LAN gateway.
- If remote clients can't reach LAN devices: check `iptables -L FORWARD -n -v` and `sysctl net.ipv4.ip_forward`.

### Generic firewall knobs (failover mode)

- `ALLOWED_IPS` + `ALLOWED_TCP_PORTS`: space-separated lists. Allows each IP to reach the listed TCP ports during failover.
- `BLOCKED_INTERNET_ACCESS_IPS`: space-separated list of IPs blocked from reaching the internet during failover.

## Health endpoint for Uptime Kuma & similar

- A minimal HTTP endpoint is exposed via systemd socket activation (no extra deps).
- Configure bind/port in `raspberry-wan-failover.conf`:
	- `HEALTH_BIND` (default `0.0.0.0`)
	- `HEALTH_PORT` (default `8080`)
	- `HEALTH_BIND_DEVICE` (optional, e.g., `tailscale0` to restrict exposure to this single interface)
- Paths: `/`, `/health`, `/healthz`, `/status`
- Response example:
	- Normal: `{"state":"up","status":"ok"}`
	- Failover: `{"state":"down","status":"failover"}`
- In Uptime Kuma, add an HTTP monitor to `http://<tailscale-ip>:8080/health`.
