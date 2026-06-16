# 🦁 Lion-Eye: High-Performance Network Intelligence Engine

**Lion-Eye** is a professional-grade, CLI-based network OSINT and diagnostic tool designed for deep packet analysis, network discovery, and intelligence gathering. Built with Python and Scapy, it provides real-time visibility into network traffic with a rich, interactive dashboard.

---

## ✨ Key Features

*   🔍 **Advanced Network Discovery**: Dual-pass ARP scanning ensures high device detection accuracy. Resolves hostnames via Reverse DNS, NetBIOS, and mDNS.
*   🧬 **Advanced Passive Fingerprinting**: Identifies device **vendor** from the full IEEE MAC OUI database and detects **device type** (Chromecast, Apple TV, Printer, etc.) by passively listening to mDNS/SSDP broadcasts — no active probes sent.
*   📛 **Device Nicknames**: Save custom labels for known devices by MAC address (e.g. `"Boss's MacBook"`, `"Main Router"`). Labels appear in every scan and watcher session.
*   👁️ **Auto-Rescan Watcher**: Continuously monitors the network and instantly highlights when a device **joins** 🟢 or **leaves** 🔴, with a live event log.
*   🏹 **Interactive Hunt Mode**: Real-time MITM dashboard showing live traffic, top targeted hosts, and protocol distribution.
*   👻 **Ghost Mode (Stealth)**: Minimalistic dashboard focusing on high-fidelity intelligence: real-time TLS encryption status, app hits (Facebook, Google, etc.), and session sniffing status.
*   📡 **Passive DNS Query Logger**: Sniffs DNS queries on the network to reveal real website visits, top queried domains, most active clients, and app activity — read-only, no traffic modified.
*   🌪️ **ARP Killer (The Silent Shout)**: Instantly disconnect **ALL** devices from the network while keeping only your machine online.
*   🛡️ **L7 Protocol Intelligence**: DNS Decoding, TLS SNI Extraction, and Session Sniffer for cookies and auth tokens.
*   🚑 **Self-Healing Restoration**: Robust cleanup logic ensures `CTRL+C` always restores the target's connection.
*   📜 **Dual Logging System**: PCAP Export (Wireshark-compatible) + Plain Text Activity Logs.

---

## 🚀 Installation (Step-by-Step)

### 1. System Prerequisites
Linux-based system (Ubuntu/Debian/Kali recommended) with Python 3.10+.

```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv libpcap-dev libnetfilter-queue-dev
```

### 2. Project Setup
```bash
git clone https://github.com/MyoThihaTun68/lion_eye.git
cd lion_eye/backend

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Permissions
```bash
chmod +x lion
```

> ⚠️ **Always run commands from inside the `backend/` directory.**

---

## 🛠️ Usage Guide

All commands require **sudo** and must be run from `lion_eye/backend/`.

---

### 🔍 1. Network Scan
Discover all active devices on the network with vendor and device type detection.
```bash
sudo ./lion scan
```

**Sample output:**
```
╒═════╤════════════════╤══════════════════════════════╤═══════════════════╤═══════════╤═════════════════╕
│ #   │ IP Address     │ Nickname / Hostname           │ MAC Address       │ Vendor    │ Device Type     │
╞═════╪════════════════╪══════════════════════════════╪═══════════════════╪═══════════╪═════════════════╡
│ [1] │ 192.168.100.1  │ ★ Main Router                │ 90:f9:70:86:28:21 │ Huawei    │ Unknown (Quiet) │
│ [2] │ 192.168.100.6  │ ★ Boss's MacBook             │ 08:f8:bc:74:20:9c │ Apple     │ Apple (AirPlay) │
│ [3] │ 192.168.100.13 │ ? 192.168.100.13             │ 18:93:41:a5:e8:7b │ HP        │ Network Printer │
╘═════╧════════════════╧══════════════════════════════╧═══════════════════╧═══════════╧═════════════════╛
```

---

### 📛 2. Device Nicknames
Label devices by their MAC address so they are recognized in every scan and watcher session.

```bash
# Add or update a nickname
sudo ./lion nick set <MAC> "<Name>" "<Optional Note>"

# Examples
sudo ./lion nick set 90:f9:70:86:28:21 "Main Router"
sudo ./lion nick set 08:f8:bc:74:20:9c "Boss's MacBook" "Finance dept"
sudo ./lion nick set 50:3e:aa:86:22:df "Staff PC #1" "HR room"

# List all saved nicknames
sudo ./lion nick list

# Remove a nickname
sudo ./lion nick remove 08:f8:bc:74:20:9c
```

Nicknames are saved to `device_nicknames.json` in the `backend/` directory and are persistent across sessions. Labeled devices appear as `★ Name` (green), unknown devices as `? Hostname` (yellow).

---

### 👁️ 3. Auto-Rescan Watcher
Continuously monitors the network and alerts when devices join or leave.

```bash
# Watch with default 60-second interval
sudo ./lion scan --watch

# Watch with custom interval (e.g. every 30 seconds)
sudo ./lion scan --watch 30

# Watch every 2 minutes
sudo ./lion scan --watch 120
```

**What you'll see:**
```
🟢 NEW DEVICE JOINED: Boss's MacBook (192.168.100.6) [08:f8:bc:74:20:9c]
🔴 DEVICE LEFT: 192.168.100.14 (192.168.100.14) [1e:1c:fc:2f:ff:fc]

  📋 EVENT LOG (Recent)
  [10:30:03] 🟢 JOINED  Boss's MacBook    192.168.100.6   08:f8:bc:74:20:9c
  [10:30:03] 🔴 LEFT    192.168.100.14    192.168.100.14  1e:1c:fc:2f:ff:fc

  ★ Known: 3  ? Unknown: 6  Total joins: 10  Total leaves: 1
```

---

### 📡 4. DNS Query Logger
Passively sniff DNS traffic to see what websites and apps devices are using. **Read-only — no traffic is modified.**

```bash
# Log all DNS queries on the network
sudo ./lion dnslog

# Log only queries from a specific device IP
sudo ./lion dnslog -t 192.168.100.6

# Save to a custom log file
sudo ./lion dnslog -o my_session.log

# Combine: filter by IP and save to file
sudo ./lion dnslog -t 192.168.100.6 -o target_dns.log
```

**Dashboard shows:**
- 🌐 **Website Visits** — Clean, deduplicated site names (e.g. `youtube.com`, `facebook.com`)
- 📋 **Recent Raw Queries** — Full subdomain detail
- 👥 **Most Active Clients** — Which IPs make the most DNS requests
- 📱 **App Activity** — Categorized hits (YouTube 🔴, WhatsApp 💬, TikTok 🎵, etc.)

> **Note:** If "Website Visits" stays empty, the browser is using DNS-over-HTTPS (DoH).
> Disable it in Chrome: `chrome://settings/security` → Turn off **"Use secure DNS"**

---

### 🏹 5. Hunt Mode (Full Traffic Analysis)
Scan, pick a target, and launch a live dashboard with packet tables and traffic charts.
```bash
sudo ./lion scan --hunt
```

---

### 👻 6. Ghost Mode (Stealth Intelligence)
Monitor a target's app usage and session activity silently.
```bash
sudo ./lion scan --ghost
```

**Shows:**
- 🔵 App hits (Facebook, Google, WhatsApp, etc.)
- 🔒 TLS encryption status
- 🍪 Session cookie / auth token capture status
- 📊 Live data usage

---

### 👟 7. Kick Mode (Disconnect Target)
Scan, pick a target, and instantly disconnect them.
```bash
sudo ./lion scan --kick
```

---

### 🌪️ 8. ARP Killer
Disconnect **ALL** devices on the network at once.
```bash
sudo ./lion killer
```

---

### ⚙️ 9. Manual ARP (Advanced)
Specify target and gateway manually — useful when you already know the IPs.
```bash
# Ghost mode manually
sudo ./lion arp -t 192.168.1.5 -g 192.168.1.1 --ghost

# Hunt mode manually
sudo ./lion arp -t 192.168.1.5 -g 192.168.1.1 --hunt
```

---

### 🔬 10. Other Diagnostic Modules

```bash
# Layer 7 deep packet analysis
sudo ./lion l7

# Bandwidth monitor (upload/download speed)
sudo ./lion bandwidth

# Basic packet sniffing (save to PCAP)
sudo ./lion scan --sniff -o capture.pcap
```

---

## 📁 Output & Logs

| File | Description |
|------|-------------|
| `device_nicknames.json` | Saved device labels (persistent across sessions) |
| `dns_queries.log` | Full DNS query log from `dnslog` module |
| `lion_eye_activity.txt` | Human-readable activity log from hunt/ghost sessions |
| `capture.pcap` | PCAP packet dump (pass `-o capture.pcap` to any command) |

---

## 📦 Command Reference

| Command | Description |
|---------|-------------|
| `sudo ./lion scan` | Network discovery with vendor + fingerprinting |
| `sudo ./lion scan --watch [N]` | Auto-rescan watcher every N seconds |
| `sudo ./lion scan --hunt` | Pick target → Hunt dashboard |
| `sudo ./lion scan --ghost` | Pick target → Ghost mode |
| `sudo ./lion scan --kick` | Pick target → Disconnect |
| `sudo ./lion nick set <MAC> "Name"` | Save a device nickname |
| `sudo ./lion nick list` | Show all saved nicknames |
| `sudo ./lion nick remove <MAC>` | Remove a nickname |
| `sudo ./lion dnslog` | Passive DNS logger (all devices) |
| `sudo ./lion dnslog -t <IP>` | DNS logger filtered to one device |
| `sudo ./lion killer` | Disconnect all devices |
| `sudo ./lion arp -t <IP> -g <GW> --ghost` | Manual ghost mode |
| `sudo ./lion bandwidth` | Bandwidth speed monitor |
| `sudo ./lion l7` | Layer 7 deep analysis |

---

## ⚖️ Legal Disclaimer
This tool is for **educational and authorized security testing purposes only**. Unauthorized use of this tool on networks you do not own or have explicit permission to test is illegal. The developers assume no liability for misuse of this software.

---

**Developed by Myo Thiha Tun** 🦁🔥
