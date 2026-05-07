# 🦁 Lion-Eye: High-Performance Network Intelligence

<p align="center">
  <img src="https://github.com/user-attachments/assets/a6fb715e-9e31-4a91-b571-fef71e0bca01" width="850" alt="Lion-Eye Scanner">
</p>

**Lion-Eye** is a lightweight, CLI-based network OSINT and diagnostic tool built with Python and Scapy. It provides real-time visibility into local network traffic with a clean, interactive dashboard designed for speed and clarity.

---

## ✨ Key Features

*   🔍 **Smart Discovery**: Dual-pass scanning for 100% device detection (ARP, NetBIOS, mDNS).
*   🏹 **Hunt Mode**: Real-time interactive dashboard showing live traffic and protocol distribution.
*   👻 **Ghost Mode**: Stealth monitoring focusing on TLS/HTTPS domains and app hits.
*   🌪️ **ARP Killer**: Instantly isolate your machine by disconnecting all other devices on the network.
*   🛡️ **L7 Intelligence**: Deep packet inspection for DNS queries, SNI extraction, and session tokens.
*   🚑 **Self-Healing**: Robust cleanup logic ensures the network is restored instantly upon exit (`CTRL+C`).

---

## 🚀 Quick Start

### 1. Requirements (Linux)
Ensure you have Python 3.10+ and the necessary system headers installed:
```bash
sudo apt-get update && sudo apt-get install -y python3-pip python3-venv libpcap-dev
2. InstallationBash# Clone the project
git clone [https://github.com/MyoThihaTun68/lion_eye.git](https://github.com/MyoThihaTun68/lion_eye.git)
cd lion_eye

# Setup environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
chmod +x lion
🛠️ Usage Guide (Root Required)ActionCommandDisconnect All Devicessudo ./lion killerStealth Monitoringsudo ./lion scan --ghostFull Traffic Analysissudo ./lion scan --huntKick Specific Targetsudo ./lion scan --kickManual ARP Spoofsudo ./lion arp -t [IP] -g [GW] --ghost📸 Dashboard Preview📁 Output & LoggingActivity Log: Human-readable logs saved to lion_eye_activity.txt.Packet Export: Use the -o filename.pcap flag to save traffic for analysis in Wireshark.⚖️ Legal DisclaimerThis tool is for educational and authorized security testing purposes only. Unauthorized use on networks without explicit permission is illegal. Use responsibly.Developed by Myo Thiha Tun 🦁🔥
---

### Why this works:
*   **Visual Hierarchy**: I used centered images to break up the text and make the "pro" dashboard shots stand out.
*   **Scanability**: The command table makes it easy for users to know exactly what to type without reading paragraphs.
*   **Professional Tone**: It sounds like a high-end security tool while staying "simple and clean."

Go ahead and update your **README.md** with this code. Your GitHub profile is going to look amazing with this project on it!
