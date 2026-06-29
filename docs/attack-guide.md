# Attack Scripts Guide — Honeypot Threat Intelligence Pipeline

Each attack has a dedicated wrapper script. Run any of them during a
presentation to demonstrate a specific attack type. The pipeline
classifies the attack, scores the risk, and the dashboard shows it live.

## Quick Start

```bash
# All scripts accept the VM IP as the first argument (default: 192.168.1.79)
scripts/attack-recon.sh              # uses default IP
scripts/attack-recon.sh 192.168.1.79 # explicit IP
scripts/attack-ddos.sh 192.168.1.79 50 10  # DDoS: IP, bots, connections
```

Dashboard: `http://<VM-IP>:5173`

## Attack Categories (21 total)

| # | Script | Category | Severity | What It Does |
|---|--------|----------|----------|-------------|
| 1 | `attack-brute-force.sh` | brute_force | medium | Credential spraying — 50 login attempts with common passwords |
| 2 | `attack-recon.sh` | reconnaissance | low | Host enumeration — whoami, uname, ifconfig, netstat, process listing |
| 3 | `attack-malware-download.sh` | malware_download | high | Payload retrieval via wget, curl, tftp |
| 4 | `attack-cryptomining.sh` | cryptomining | high | XMRig deployment, mining pool connection |
| 5 | `attack-persistence.sh` | persistence | high | SSH keys, crontab, systemd, rc.local backdoors |
| 6 | `attack-privilege-escalation.sh` | privilege_escalation | high | sudo -l, SUID search, pkexec, sudoers modification |
| 7 | `attack-credential-access.sh` | credential_access | medium | Reading /etc/shadow, SSH keys, AWS credentials |
| 8 | `attack-obfuscation.sh` | obfuscation | medium | Base64-encoded payloads, eval, piped bash |
| 9 | `attack-defense-evasion.sh` | defense_evasion | high | Log clearing, history wiping, firewall disable |
| 10 | `attack-destructive-action.sh` | destructive_action | high | rm -rf, dd, mkfs, fork bomb |
| 11 | `attack-reverse-shell.sh` | reverse_shell | high | Bash /dev/tcp, netcat -e, python socket, mkfifo |
| 12 | `attack-cloud-metadata.sh` | cloud_metadata_access | high | AWS/GCP metadata endpoint queries |
| 13 | `attack-container-escape.sh` | container_escape | high | Docker sock, nsenter, chroot to host |
| 14 | `attack-data-exfiltration.sh` | data_exfiltration | high | curl POST stolen data, tar+nc, ngrok tunneling |
| 15 | `attack-lateral-movement.sh` | lateral_movement | high | sshpass to other hosts, ssh-keyscan, rsync spread |
| 16 | `attack-network-scan.sh` | network_scan | medium | nmap, masscan, nc -zv port scanning |
| 17 | `attack-ddos.sh` | ddos | high | Botnet flood — 20 bots x 10 connections + DDoS tools |
| 18 | `attack-full-chain.sh` | ALL | critical | Complete attack lifecycle — all categories in one session |

## Presentation Order (recommended)

Run these in order during a demo. Each one fills a different dashboard
section. By the end, every category has data.

### Phase 1: Discovery (low risk)

```bash
scripts/attack-recon.sh
scripts/attack-network-scan.sh
scripts/attack-brute-force.sh
```

### Phase 2: Access (medium-high risk)

```bash
scripts/attack-credential-access.sh
scripts/attack-privilege-escalation.sh
scripts/attack-malware-download.sh
```

### Phase 3: Impact (high-critical risk)

```bash
scripts/attack-cryptomining.sh
scripts/attack-persistence.sh
scripts/attack-reverse-shell.sh
scripts/attack-container-escape.sh
scripts/attack-cloud-metadata.sh
scripts/attack-data-exfiltration.sh
scripts/attack-lateral-movement.sh
scripts/attack-obfuscation.sh
scripts/attack-defense-evasion.sh
scripts/attack-destructive-action.sh
```

### Phase 4: DDoS (special — volumetric)

```bash
scripts/attack-ddos.sh
# Or with more bots:
scripts/attack-ddos.sh 192.168.1.79 50 10
```

### Phase 5: Full chain (everything at once)

```bash
scripts/attack-full-chain.sh
```

## How Each Script Works

All scripts connect to the Cowrie SSH honeypot on port 2222. Cowrie
logs every connection, login attempt, and command. The pipeline
processes the log in real-time and the dashboard updates within
seconds.

```
Script ──SSH──► Cowrie:2222 ──logs──► Pipeline ──► Dashboard
                   │                      │
                   │                      ├── classify
                   │                      ├── score risk
                   │                      ├── store in SQLite
                   │                      └── update API
                   │
                   └── no real damage — Cowrie is a fake shell
```

## Verifying Each Attack

After running a script, check the dashboard or API:

```bash
# Check if a specific category has events
curl -s "http://<VM-IP>:5000/api/events?attack_category=ddos&limit=3" | python3 -m json.tool

# Check overall summary
curl -s http://<VM-IP>:5000/api/summary | python3 -m json.tool
```

## DDoS Script Details

The DDoS script is special — it simulates a distributed attack:

```bash
scripts/attack-ddos.sh [VM-IP] [bots] [connections]

# Examples:
scripts/attack-ddos.sh                          # 20 bots, 10 connections
scripts/attack-ddos.sh 192.168.1.79 50 10       # 50 bots, 10 connections each
scripts/attack-ddos.sh 192.168.1.79 100 5       # 100 bots, 5 connections each
```

It floods Cowrie with rapid SSH connections from simulated bot IPs.
Some bots also run DDoS tools (hping3, slowloris, goldeneye) which
trigger the `ddos` classification category.

## Firewall Response

After detecting attacks, the system can block malicious IPs:

```bash
# On the VM:
scripts/apply-blocklist.sh review    # see which IPs would be blocked
sudo scripts/apply-blocklist.sh apply  # block them with iptables
sudo iptables -L INPUT -n | grep honeypot-block  # verify blocks
```
