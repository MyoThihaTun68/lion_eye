# 🦁 Lion-Eye: High-Performance Network Intelligence

<p align="center">
  <img src="https://github.com/user-attachments/assets/a6fb715e-9e31-4a91-b571-fef71e0bca01" width="850" alt="Lion-Eye Scanner">
</p>

**Lion-Eye** is a lightweight, CLI-based network OSINT and diagnostic tool built with Python and Scapy. It provides real-time visibility into local network traffic via a sleek, interactive terminal dashboard engineered for performance and clarity.

---

## ✨ Key Features

*   🔍 **Smart Discovery**: Dual-pass scanning for 100% device detection (ARP, NetBIOS, mDNS).
*   🏹 **Hunt Mode**: Real-time interactive dashboard showing live traffic and protocol distribution.
*   👻 **Ghost Mode**: Stealth monitoring focusing on TLS/HTTPS domains and app hits.
*   🌪️ **ARP Killer**: Instantly isolate your machine by disconnecting all other devices on the network.
*   🛡️ **L7 Intelligence**: Deep packet inspection for DNS queries, SNI extraction, and session tokens.
*   🚑 **Self-Healing**: Robust cleanup logic ensures the network is restored instantly upon exit (`CTRL+C`).

---
## 🚀 Installation (Step-by-Step)



### 1. System Prerequisites

Ensure you are running on a Linux-based system (Ubuntu/Debian/Kali recommended) with Python 3.10+.



```bash

# Install system dependencies

sudo apt-get update

sudo apt-get install -y python3-pip python3-venv libpcap-dev libnetfilter-queue-dev

```



### 2. Project Setup

```bash

# Clone the repository

git clone https://github.com/MyoThihaTun68/lion_eye.git

cd lion_eye/backend



# Create and activate virtual environment

python3 -m venv venv

source venv/bin/activate



# Install Python requirements

pip install -r requirements.txt

```



### 3. Permissions

Lion-Eye requires raw socket access to perform ARP spoofing and packet sniffing.

```bash

# Make the main wrapper executable

chmod +x lion

```



---



## 🛠️ Usage Guide



Always run commands with **sudo** privileges.



### 1. Network Storming (ARP Killer)

Disconnect every device on the network except yourself:

```bash

sudo ./lion killer

```



### 2. High-Fidelity Intelligence (Ghost Mode)

Scan, pick a target, and monitor their active sessions and app usage stealthily:

```bash

sudo ./lion scan --ghost

```



### 3. Full Traffic Analysis (Hunt Mode)

The classic dashboard with live packet tables and traffic charts:

```bash

sudo ./lion scan --hunt

```



### 4. Direct Disconnect (Kick)

Instantly drop the internet connection for a specific target:

```bash

sudo ./lion scan --kick

```



### 5. Manual ARP Spoofing

For advanced users who already have Target and Gateway IPs:

sudo ./lion arp -t 192.168.1.5 -g 192.168.1.1 --ghost



## 📁 Output & Logs

*   **Intelligence Card**: Displays real-time app hits (e.g., 🔵 Facebook, 🔴 Google), encryption levels (TLS 1.3), and session token counts.

*   **Activity Log**: `lion_eye_activity.txt` (Human-readable log of all connections).

*   **Packet Dump**: Pass `-o capture.pcap` to any command to save data for Wireshark.



---



## ⚖️ Legal Disclaimer

This tool is for **educational and authorized security testing purposes only**. Unauthorized use of this tool on networks you do not own or have explicit permission to test is illegal. The developers assume no liability for misuse of this software.



---
