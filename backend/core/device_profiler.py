"""
Lion-Eye OSINT - Device Intelligence Profiler
Analyzes traffic patterns and tracks DNS hijacks.
"""
from collections import Counter
import subprocess
from colorama import Fore, Style
from .config import APP_MAP

class DeviceProfiler:
    """
    Analyzes network traffic to build a profile of a target device.
    Tracks application usage, data consumption, and security status.
    """
    def __init__(self, target_ip, target_mac):
        self.target_ip  = target_ip
        self.target_mac = target_mac.lower() if target_mac else ""
        self.detected_apps = set()
        self.app_hits = Counter()
        self.total_bytes = 0
        self.dns_hijacks = [] # Store recent hijacks
        self.last_signal = "Calculating..."
        self.cookies = 0
        self.auth_tokens = 0
        self.tls_active = False

    def add_hijack_log(self, domain, target):
        log = f"{domain} -> {target}"
        if log not in self.dns_hijacks:
            self.dns_hijacks.insert(0, log)
            self.dns_hijacks = self.dns_hijacks[:3] # Keep last 3

    def feed(self, src, dst, service, length, dst_name, port=None, ttl=None, payload=None):
        self.total_bytes += length
        
        if port == 443 or service == "HTTPS":
            self.tls_active = True
            
        if dst_name:
            d_lower = dst_name.lower()
            for app, keywords in APP_MAP.items():
                if any(kw in d_lower for kw in keywords):
                    self.detected_apps.add(app)
                    self.app_hits[app] += 1
        
        # Parse payload for session sniffing
        if payload:
            try:
                p_str = payload.decode('utf-8', errors='ignore')
                if "Cookie: " in p_str or "Set-Cookie: " in p_str:
                    self.cookies += 1
                if "Authorization: " in p_str or "Bearer " in p_str:
                    self.auth_tokens += 1
            except:
                pass

    def get_wifi_range(self):
        try:
            cmd = ["iw", "dev", "wlp1s0", "station", "get", self.target_mac]
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            for line in res.split('\n'):
                if "signal:" in line:
                    sig = line.split(':')[1].strip()
                    dbm = int(sig.split()[0])
                    if dbm > -50: return f"{Fore.GREEN}Strong (~1-3m){Style.RESET_ALL}"
                    if dbm > -65: return f"{Fore.YELLOW}Medium (~5-10m){Style.RESET_ALL}"
                    return f"{Fore.RED}Weak (>15m){Style.RESET_ALL}"
        except: pass
        return f"{Fore.WHITE}Estimated (Active Flow){Style.RESET_ALL}"

    def render_card(self):
        apps = ", ".join(list(self.detected_apps)[:4]) if self.detected_apps else "Scanning..."
        range_info = self.get_wifi_range()
        hijacks = ", ".join(self.dns_hijacks) if self.dns_hijacks else "None"
        
        data_str = f"{self.total_bytes / 1_048_576:.1f} MB" if self.total_bytes > 1_048_576 else f"{self.total_bytes / 1024:.1f} KB"
        
        cap_val = f"{self.cookies} HTTP Cookies / {self.auth_tokens} Auth Tokens"
        int_val = f"User is active on {list(self.detected_apps)[0] if self.detected_apps else 'Network'}"
        
        enc_val = "TLS 1.3 (Active 🔒)" if self.tls_active else "None (Insecure 🔓)"
        
        hit_strs = []
        for i, (app, count) in enumerate(self.app_hits.most_common(2)):
            icon = "🔵" if i == 0 else "🔴"
            hit_strs.append(f"{icon} {app} ({count} hits)")
        dom_hits = ", ".join(hit_strs) if hit_strs else "Scanning..."
        
        intercept_val = "Waiting for Downgrade / Insecure Link"
        status_val = "Target is Encrypted (Use SSLStrip to Capture)" if self.tls_active else "Target is Insecure (Capturing Payload)"

        card = (
            f"  {Fore.GREEN}{Style.BRIGHT}┌─── 🧠 TARGET INTELLIGENCE ────────────────────────────────────┐{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Target     :{Style.RESET_ALL} {Fore.CYAN}{self.target_ip:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}MAC Address:{Style.RESET_ALL} {Fore.CYAN}{self.target_mac:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Apps Found :{Style.RESET_ALL} {Fore.MAGENTA}{apps:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}WiFi Range :{Style.RESET_ALL} {range_info:<55}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}────────────────────────────────────────────────────────────{Style.RESET_ALL} {Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.YELLOW}🛡️ ATTACK MODULE: SESSION SNIFFER (ACTIVE 🟢){Style.RESET_ALL}               {Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Captured   :{Style.RESET_ALL} {Fore.RED}{cap_val:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Encryption :{Style.RESET_ALL} {Fore.CYAN}{enc_val:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Domain Hits:{Style.RESET_ALL} {dom_hits:<46}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Intercept  :{Style.RESET_ALL} {Fore.YELLOW}{intercept_val:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Status     :{Style.RESET_ALL} {Fore.RED}{status_val:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Insight    :{Style.RESET_ALL} {Fore.CYAN}{int_val:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}────────────────────────────────────────────────────────────{Style.RESET_ALL} {Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}DNS Hijacks:{Style.RESET_ALL} {Fore.RED}{hijacks:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}│{Style.RESET_ALL}  {Fore.WHITE}Data Used  :{Style.RESET_ALL} {Fore.CYAN}{data_str:<46}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}\n"
            f"  {Fore.GREEN}{Style.BRIGHT}└───────────────────────────────────────────────────────────────┘{Style.RESET_ALL}"
        )
        return card
