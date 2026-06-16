"""
Lion-Eye DNS Query Logger
Passively captures and displays all DNS queries on the local network in real-time.
No traffic is modified or intercepted — this is a read-only intelligence module.
"""

import time
import os
from datetime import datetime
from collections import defaultdict, OrderedDict
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR
from tabulate import tabulate
from colorama import Fore, Style
from utils.helpers import print_info, print_success, print_warning, print_error
from .config import APP_MAP


# ─────────────────────────────────────────────────────────
# Noise filter: domains that are system/telemetry background traffic
# ─────────────────────────────────────────────────────────

NOISE_KEYWORDS = {
    # Reverse lookups
    "in-addr.arpa", "ip6.arpa",
    # Browser/OS telemetry & internal
    "safebrowsing.", "beacons.", "telemetry.", "diagnostics.",
    "settings-win.", "update.googleapis", "connectivitycheck.",
    "captive.apple.", "gstatic.com", "ocsp.", "crl.",
    "push.apple.", "courier.push.", "time.apple.",
    "windowsupdate.", "msedge.net", "events.data.microsoft",
    "activity.windows.", "vortex.data.microsoft",
    # NTP, mDNS noise
    "pool.ntp.org", "time.windows.com", "_dns.",
    # CDN internal
    "e13678.dscb.", "e1863.dscx.", "cs9.wac.", "a]",
    # Local network
    ".local", ".lan", ".home", ".internal",
}


class DNSLogger:
    """
    Passively sniffs DNS queries on the network and presents them
    in a live-updating dashboard with app categorization and statistics.
    Filters out background noise to highlight real website visits.
    """

    def __init__(self, interface, output_file=None, filter_ip=None):
        self.interface = interface
        self.output_file = output_file or "dns_queries.log"
        self.filter_ip = filter_ip  # Optional: only log queries from this IP

        # ── Live state ───────────────────────────────────────
        self.query_log = []           # All captured queries (dicts)
        self.domain_hits = defaultdict(int)  # domain -> count
        self.client_hits = defaultdict(int)  # source IP -> count
        self.app_hits = defaultdict(int)     # App name -> count
        self.website_visits = OrderedDict()  # clean domain -> {time, src, count}
        self.total_queries = 0
        self.noise_filtered = 0
        self.start_time = None

    # ─────────────────────────────────────────────────────────
    # Domain Intelligence
    # ─────────────────────────────────────────────────────────

    def _classify_app(self, domain):
        """Match a domain against APP_MAP keywords to identify the application."""
        domain_lower = domain.lower()
        for app_name, keywords in APP_MAP.items():
            for kw in keywords:
                if kw in domain_lower:
                    return app_name
        return None

    def _is_noise(self, domain, qtype):
        """Check if a domain is background noise / telemetry."""
        domain_lower = domain.lower()
        # PTR reverse lookups are always noise for the website view
        if qtype == "PTR":
            return True
        for noise in NOISE_KEYWORDS:
            if noise in domain_lower:
                return True
        return False

    def _extract_website(self, domain):
        """Extract the clean base website from a full domain.
        e.g. 'www.facebook.com' -> 'facebook.com'
             'edge-star-mini-shv-01-sin6.facebook.com' -> 'facebook.com'
             'ogads-pa.clients6.google.com' -> 'google.com'
        """
        parts = domain.lower().strip(".").split(".")
        if len(parts) < 2:
            return domain.lower()

        # Known multi-part TLDs
        multi_tlds = {"co.uk", "com.au", "co.jp", "com.sg", "co.kr",
                      "com.mm", "co.th", "com.tw", "co.in", "com.br",
                      "org.uk", "net.au", "ac.uk", "gov.uk"}

        last_two = ".".join(parts[-2:])
        if last_two in multi_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
        return last_two

    # ─────────────────────────────────────────────────────────
    # File Logging
    # ─────────────────────────────────────────────────────────

    def _log_to_file(self, entry):
        """Append a single DNS query entry to the log file."""
        try:
            with open(self.output_file, "a") as f:
                f.write(
                    f"[{entry['time']}] {entry['src']:>15} -> "
                    f"{entry['domain']:<45} TYPE={entry['qtype']:<6} "
                    f"APP={entry['app'] or '-'}\n"
                )
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────
    # Packet Handler
    # ─────────────────────────────────────────────────────────

    def _handle_packet(self, packet):
        """Process a single captured DNS packet."""
        if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
            return

        dns_layer = packet[DNS]

        # Only process queries (QR=0) — skip responses
        if dns_layer.qr != 0:
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else "?.?.?.?"
        
        # Apply IP filter if set
        if self.filter_ip and src_ip != self.filter_ip:
            return

        try:
            domain = dns_layer.qd.qname.decode("utf-8", errors="ignore").strip(".")
        except Exception:
            domain = "???"

        # Map query type number to name
        qtype_map = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX",
                     16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
        qtype_num = dns_layer.qd.qtype
        qtype = qtype_map.get(qtype_num, str(qtype_num))

        app = self._classify_app(domain)
        now = datetime.now().strftime("%H:%M:%S")
        is_noise = self._is_noise(domain, qtype)

        entry = {
            "time": now,
            "src": src_ip,
            "domain": domain,
            "qtype": qtype,
            "app": app,
            "noise": is_noise,
        }

        # Update state
        self.total_queries += 1
        self.client_hits[src_ip] += 1

        if is_noise:
            self.noise_filtered += 1
        else:
            # Only add non-noise entries to the visible log
            self.query_log.append(entry)
            self.domain_hits[domain] += 1
            if app:
                self.app_hits[app] += 1

            # Track clean website visits
            website = self._extract_website(domain)
            if website in self.website_visits:
                self.website_visits[website]["count"] += 1
                self.website_visits[website]["last"] = now
            else:
                self.website_visits[website] = {
                    "first": now,
                    "last": now,
                    "src": src_ip,
                    "count": 1,
                    "app": app,
                }
            # Move to end (most recent)
            self.website_visits.move_to_end(website)

        # Always write to file (including noise, for full audit)
        self._log_to_file(entry)

        # Redraw dashboard
        self._draw_dashboard()

    # ─────────────────────────────────────────────────────────
    # Dashboard Rendering
    # ─────────────────────────────────────────────────────────

    def _draw_dashboard(self):
        """Clear terminal and render the full dashboard."""
        os.system("clear")
        elapsed = int(time.time() - self.start_time) if self.start_time else 0
        mins, secs = divmod(elapsed, 60)

        app_icons = {
            "Facebook": "🔵", "Instagram": "📸", "WhatsApp": "💬",
            "TikTok": "🎵", "YouTube": "🔴", "Netflix": "🎬",
            "Spotify": "🎧", "Telegram": "✈️", "Google": "🔍"
        }

        # ── Header ───────────────────────────────────────────
        print(f"{Fore.CYAN}{Style.BRIGHT}")
        print(f"  📡 LION-EYE DNS QUERY LOGGER")
        print(f"  Interface: {self.interface}    "
              f"Elapsed: {mins:02d}:{secs:02d}    "
              f"Total: {self.total_queries}  "
              f"Filtered: {self.noise_filtered} noise")
        if self.filter_ip:
            print(f"  Filtering: {self.filter_ip} only")
        print(f"  Log File : {self.output_file}")
        print(f"{Style.RESET_ALL}")

        # ── 🌐 WEBSITE VISITS (the main feature) ─────────────
        visits = list(self.website_visits.items())
        if visits:
            # Show most recent 12 visits (reversed so newest is on top)
            recent_visits = visits[-12:]
            recent_visits.reverse()
            
            print(f"{Fore.GREEN}{Style.BRIGHT}  🌐 WEBSITE VISITS (Real Browsing Activity){Style.RESET_ALL}")
            visit_table = []
            for website, info in recent_visits:
                app = info.get("app")
                icon = app_icons.get(app, "🌐") if app else "🌐"
                app_str = f"{icon} {app}" if app else f"{Fore.WHITE}-{Style.RESET_ALL}"
                
                visit_table.append([
                    f"{Fore.WHITE}{info['first']}{Style.RESET_ALL}",
                    f"{Fore.CYAN}{info['src']}{Style.RESET_ALL}",
                    f"{Fore.GREEN}{Style.BRIGHT}{website}{Style.RESET_ALL}",
                    f"{Fore.YELLOW}{info['count']}{Style.RESET_ALL}",
                    app_str,
                ])

            print(tabulate(
                visit_table,
                headers=[
                    f"{Fore.YELLOW}First Seen{Style.RESET_ALL}",
                    f"{Fore.YELLOW}Client IP{Style.RESET_ALL}",
                    f"{Fore.YELLOW}Website{Style.RESET_ALL}",
                    f"{Fore.YELLOW}Hits{Style.RESET_ALL}",
                    f"{Fore.YELLOW}App{Style.RESET_ALL}",
                ],
                tablefmt="fancy_grid"
            ))
        else:
            print(f"{Fore.YELLOW}  ⏳ Waiting for DNS queries...{Style.RESET_ALL}")

        # ── Recent Raw Queries (last 8, compact) ─────────────
        recent = self.query_log[-8:]
        if recent:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  📋 RECENT QUERIES (Raw){Style.RESET_ALL}")
            for e in recent:
                app_tag = ""
                if e["app"]:
                    icon = app_icons.get(e["app"], "📱")
                    app_tag = f" {icon}{e['app']}"
                print(f"  {Fore.WHITE}{e['time']} {Fore.CYAN}{e['src']:<16}"
                      f"{Fore.GREEN}{e['domain'][:55]:<55} "
                      f"{Fore.WHITE}{e['qtype']:<5}"
                      f"{Fore.YELLOW}{app_tag}{Style.RESET_ALL}")

        # ── Top Clients ──────────────────────────────────────
        top_clients = sorted(self.client_hits.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_clients:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  👥 MOST ACTIVE CLIENTS{Style.RESET_ALL}")
            for ip, count in top_clients:
                print(f"  {Fore.CYAN}{ip:<18} {Fore.YELLOW}{count} queries{Style.RESET_ALL}")

        # ── App Summary ──────────────────────────────────────
        if self.app_hits:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  📱 APP ACTIVITY{Style.RESET_ALL}")
            for app, count in sorted(self.app_hits.items(), key=lambda x: x[1], reverse=True):
                icon = app_icons.get(app, "📱")
                print(f"  {icon} {Fore.WHITE}{app:<15} {Fore.YELLOW}{count} hits{Style.RESET_ALL}")

        # ── DoH Warning ──────────────────────────────────────
        if self.total_queries > 5 and len(self.website_visits) == 0:
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}"
                  f"  ⚠️  No websites detected. Browser may be using DNS-over-HTTPS (DoH).\n"
                  f"      Disable DoH in browser settings to see full DNS traffic.\n"
                  f"      Chrome: chrome://settings/security → Disable 'Use secure DNS'\n"
                  f"      Firefox: about:preferences → Network → Disable DNS over HTTPS"
                  f"{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}  Press CTRL+C to stop logging{Style.RESET_ALL}")

    # ─────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────

    def start(self):
        """Start the passive DNS query logger."""
        print_info(f"Starting DNS Query Logger on {self.interface}...")
        print_info(f"Logging to: {self.output_file}")
        if self.filter_ip:
            print_info(f"Filtering queries from: {self.filter_ip}")
        print_warning("Press CTRL+C to stop.\n")

        self.start_time = time.time()

        # Write header to log file
        try:
            with open(self.output_file, "a") as f:
                f.write(f"\n{'='*70}\n")
                f.write(f"Lion-Eye DNS Logger — Started {datetime.now().isoformat()}\n")
                f.write(f"Interface: {self.interface}\n")
                if self.filter_ip:
                    f.write(f"Filter: {self.filter_ip}\n")
                f.write(f"{'='*70}\n")
        except Exception as e:
            print_warning(f"Could not write to log file: {e}")

        try:
            sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self._handle_packet,
                store=0  # Don't store packets in memory
            )
        except PermissionError:
            print_error("Permission denied. Run with sudo privileges.")
        except KeyboardInterrupt:
            pass
        finally:
            print(f"\n{Fore.GREEN}[+] DNS Logger stopped.{Style.RESET_ALL}")
            print_success(f"Total queries captured: {self.total_queries}")
            print_success(f"Noise filtered: {self.noise_filtered}")
            print_success(f"Websites detected: {len(self.website_visits)}")
            print_success(f"Log saved to: {self.output_file}")
            print_success(f"Unique clients: {len(self.client_hits)}")
