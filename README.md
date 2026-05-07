# 🦁 Lion-Eye: High-Performance Network Intelligence Engine


<img width="846" height="448" alt="LIONEYESCANBOARD" src="https://github.com/user-attachments/assets/a6fb715e-9e31-4a91-b571-fef71e0bca01" />


**Lion-Eye** is a professional-grade, CLI-based network OSINT and diagnostic tool designed for deep packet analysis, network discovery, and intelligence gathering. Built with Python and Scapy, it provides real-time visibility into network traffic with a rich, interactive dashboard.

---

## ✨ Key Features

*   🔍 **Advanced Network Discovery**: Dual-pass scanning ensures 100% device detection. Identifies devices using ARP, NetBIOS, and mDNS for precise hostname resolution.
*   🏹 **Interactive Hunt Mode**: Real-time MITM (Man-in-the-Middle) dashboard showing live traffic, top targeted hosts, and protocol distribution.
*   👻 **Ghost Mode (Stealth)**: Minimalistic dashboard focusing on high-fidelity intelligence: real-time TLS encryption status, app hits (Facebook, Google, etc.), and session sniffing status (Cookies/Tokens).
*   🌪️ **ARP Killer (The Silent Shout)**: Instantly disconnect **ALL** devices from the network while keeping only your machine online.
*   🛡️ **L7 Protocol Intelligence**: 
    *   **DNS Decoding**: See exactly which domains are being queried.
    *   **TLS SNI Extraction**: Identify HTTPS domains even in encrypted traffic.
    *   **Session Sniffer**: Detect active cookies and authorization tokens in real-time.
*   🚑 **Self-Healing Restoration**: Robust cleanup logic ensures that pressing `CTRL+C` always restores the target's connection and heals the network.
*   📜 **Dual Logging System**:
    *   **PCAP Export**: Save full packet captures for analysis in Wireshark.
    *   **Plain Text Logs**: Human-readable activity logs (`lion_eye_activity.txt`) recorded in real-time.

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
```bash
sudo ./lion arp -t 192.168.1.5 -g 192.168.1.1 --ghost
```<img width="846" height="448" alt="LIONEYESCANBOARD" src="https://github.com/user-attachments/assets/abfab33f-85f5-45c4-88f2-cd72695ef5c6" />


---

## 📁 Output & Logs
*   **Intelligence Card**: Displays real-time app hits (e.g., 🔵 Facebook, 🔴 Google), encryption levels (TLS 1.3), and session token counts.
*   **Activity Log**: `lion_eye_activity.txt` (Human-readable log of all connections).
*   **Packet Dump**: Pass `-o capture.pcap` to any command to save data for Wireshark.

---

## ⚖️ Legal Disclaimer
This tool is for **educational and authorized security testing purposes only**. Unauthorized use of this tool on networks you do not own or have explicit permission to test is illegal. The developers assume no liability for misuse of this software.

---

**Developed by Myo Thiha Tun** 🦁🔥
