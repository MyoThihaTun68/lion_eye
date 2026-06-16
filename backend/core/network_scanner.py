from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, wrpcap, raw
from tabulate import tabulate
from colorama import Fore, Style
from utils.helpers import print_info, print_success, print_error, print_warning, get_device_name
from .config import PORT_MAP
from .nicknames import NicknameManager
import socket
import netifaces
import os
import time

class NetworkScanner:
    """
    Handles network discovery and packet sniffing.
    Supports dual-pass scanning for higher accuracy.
    """
    def __init__(self, interface):
        self.interface = interface
        self.hostname_cache = {}
        self.nicknames = NicknameManager()
        
    def get_hostname(self, ip):
        """Resolve IP to hostname with local caching."""
        if ip in self.hostname_cache:
            return self.hostname_cache[ip]
        name = get_device_name(ip)
        self.hostname_cache[ip] = name
        return name

    def get_vendor(self, mac):
        """Perform full offline MAC OUI lookup using mac-vendor-lookup."""
        try:
            from mac_vendor_lookup import MacLookup, VendorNotFoundError
            # Instantiate and fetch
            vendor = MacLookup().lookup(mac)
            # Clean up long vendor names
            if len(vendor) > 20:
                vendor = vendor.split(',')[0].split(' ')[0]
            return vendor
        except Exception:
            return "Generic/Unknown"

    def passive_fingerprint(self, clients, timeout=10):
        """Passively listen to mDNS and SSDP to identify device types."""
        print_info(f"Listening for mDNS/SSDP broadcasts for advanced fingerprinting ({timeout}s)...")
        fingerprints = {c['ip']: "Unknown (Quiet)" for c in clients}
        
        def packet_handler(packet):
            if IP in packet and UDP in packet:
                src_ip = packet[IP].src
                if src_ip in fingerprints:
                    try:
                        payload = raw(packet)
                        # mDNS (5353)
                        if packet[UDP].dport == 5353 or packet[UDP].sport == 5353:
                            if b"Apple TV" in payload: fingerprints[src_ip] = "Apple TV"
                            elif b"_googlecast" in payload or b"Chromecast" in payload: fingerprints[src_ip] = "Chromecast"
                            elif b"Roku" in payload: fingerprints[src_ip] = "Roku TV"
                            elif b"_printer" in payload or b"_ipp" in payload: fingerprints[src_ip] = "Network Printer"
                            elif b"_spotify-connect" in payload: fingerprints[src_ip] = "Smart Speaker (Spotify)"
                            elif b"_airplay" in payload: fingerprints[src_ip] = "Apple Device (AirPlay)"
                        # SSDP (1900)
                        elif packet[UDP].dport == 1900 or packet[UDP].sport == 1900:
                            if b"Roku" in payload: fingerprints[src_ip] = "Roku Device"
                            elif b"Sonos" in payload: fingerprints[src_ip] = "Sonos Speaker"
                            elif b"Smart TV" in payload or b"SmartTV" in payload: fingerprints[src_ip] = "Smart TV"
                    except Exception:
                        pass

        try:
            sniff(iface=self.interface, filter="udp port 5353 or udp port 1900", prn=packet_handler, timeout=timeout)
        except PermissionError:
            pass
            
        for c in clients:
            c['vendor'] = self.get_vendor(c['mac'])
            c['type'] = fingerprints.get(c['ip'], "Unknown (Quiet)")
        
        return clients

    def get_ip_range(self):
        """Calculate the local network range (CIDR) for scanning."""
        try:
            addrs = netifaces.ifaddresses(self.interface)
            ip_info = addrs[netifaces.AF_INET][0]
            ip_addr = ip_info['addr']
            parts = ip_addr.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception as e:
            print_error(f"Could not determine IP range for interface {self.interface}: {e}")
            return None

    def scan_network(self):
        """Scan the network twice and return a merged list of discovered clients to improve detection accuracy."""
        print_info(f"Starting network scan on interface: {self.interface}")
        ip_range = self.get_ip_range()
        if not ip_range:
            return []

        # First pass (quick)
        print_info(f"Scanning range (first pass): {ip_range} ...")
        clients_first = self._perform_scan(ip_range, timeout=3)

        # Second pass (longer) to catch missed devices
        print_info(f"Scanning range (second pass, longer timeout) ...")
        clients_second = self._perform_scan(ip_range, timeout=6)

        # Merge while preserving unique IPs
        merged = {c['ip']: c for c in clients_first}
        for c in clients_second:
            merged.setdefault(c['ip'], c)
        return list(merged.values())

    def _perform_scan(self, ip_range, timeout=3):
        """Helper to perform a single ARP scan with the given timeout."""
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        try:
            result = srp(packet, timeout=timeout, verbose=0, iface=self.interface)[0]
        except PermissionError:
            print_error("Permission denied. Run with sudo privileges.")
            return []
        clients = []
        for _, received in result:
            hostname = self.get_hostname(received.psrc)
            clients.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'name': hostname
            })
        return clients

    def print_hosts(self, clients):
        """Pretty-print discovered hosts with an index for interactive selection."""
        if not clients:
            print_warning("No active devices found on the network.")
            return

        # Annotate with nicknames
        self.nicknames.mark_clients(clients)

        print_success(f"Found {len(clients)} active device(s)\n")
        table_data = []
        for i, c in enumerate(clients):
            # Build display name: nickname > hostname > IP
            nick = c.get('nickname')
            hostname = c.get('name', c['ip'])
            if nick:
                display_name = f"{Fore.GREEN}★ {nick}{Style.RESET_ALL}"
            else:
                display_name = f"{Fore.YELLOW}? {hostname}{Style.RESET_ALL}"

            table_data.append([
                f"[{i+1}]",
                c['ip'],
                display_name,
                c['mac'],
                c.get('vendor', 'N/A'),
                c.get('type', 'N/A'),
            ])

        print(tabulate(
            table_data,
            headers=["#", "IP Address", "Nickname / Hostname", "MAC Address", "Vendor", "Device Type"],
            tablefmt="fancy_grid"
        ))
        # Legend
        unknown = sum(1 for c in clients if not c.get('nickname'))
        if unknown:
            print(f"  {Fore.YELLOW}[?] {unknown} unknown device(s) — label them with: sudo ./lion nick set <MAC> \"Name\"{Style.RESET_ALL}")

    def start_sniffing(self, count=100, output_file=None):
        """Standalone sniffer for general network analysis."""
        print_info(f"Starting packet sniffing on {self.interface} (capturing {count} packets)...")
        print_info("Analyzing services and resolving hostnames (this may take a moment)...")
        
        captured_packets = []
        packets_summary = []
        
        def packet_handler(packet):
            captured_packets.append(packet)
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                src_display = self.get_hostname(src_ip)
                dst_display = self.get_hostname(dst_ip)
                
                proto_num = packet[IP].proto
                service = "OTHER"
                protocol = str(proto_num)

                if TCP in packet:
                    protocol = "TCP"
                    sport, dport = packet[TCP].sport, packet[TCP].dport
                    service = PORT_MAP.get(dport, PORT_MAP.get(sport, "TCP-OTHER"))
                elif UDP in packet:
                    protocol = "UDP"
                    sport, dport = packet[UDP].sport, packet[UDP].dport
                    service = PORT_MAP.get(dport, PORT_MAP.get(sport, "UDP-OTHER"))
                
                length = len(packet)
                packets_summary.append([src_display, dst_display, protocol, service, length])

        try:
            sniff(iface=self.interface, prn=packet_handler, count=count)
        except PermissionError:
            print_error("Permission denied. Run with sudo privileges.")
            return

        print_success("Packet capture complete.")
        
        if output_file:
            try:
                wrpcap(output_file, captured_packets)
                print_success(f"Packets saved to {output_file}")
            except Exception as e:
                print_error(f"Failed to save PCAP: {e}")

        print("\n" + tabulate(
            packets_summary[:50],
            headers=["Source", "Destination", "Proto", "Service", "Len"],
            tablefmt="fancy_grid"
        ))
        if len(packets_summary) > 50:
            print_info(f"... and {len(packets_summary) - 50} more packets.")

    # ─────────────────────────────────────────────────────────
    # Auto-Rescan Watcher
    # ─────────────────────────────────────────────────────────

    def watch_network(self, interval=60):
        """
        Continuously re-scan the network every `interval` seconds.
        Highlights devices that JOINED (🟢) or LEFT (🔴) since the last scan.
        Uses saved nicknames to label known vs unknown devices.
        """
        print_info(f"Starting Network Watcher on {self.interface} (interval: {interval}s)")
        print_warning("Press CTRL+C to stop watching.\n")

        previous_macs = {}   # mac -> client dict from last scan
        scan_count = 0
        event_log = []       # List of (time, event, mac, ip, name)

        try:
            while True:
                scan_count += 1
                now = time.strftime("%H:%M:%S")
                os.system("clear")

                # ── Header ───────────────────────────────────────
                print(f"{Fore.CYAN}{Style.BRIGHT}")
                print(f"  👁️  LION-EYE NETWORK WATCHER")
                print(f"  Interface: {self.interface}    "
                      f"Interval: {interval}s    "
                      f"Scan #{scan_count}    "
                      f"Last scan: {now}")
                print(f"{Style.RESET_ALL}")

                # ── Perform scan (quiet, single pass for speed) ──
                ip_range = self.get_ip_range()
                if not ip_range:
                    time.sleep(interval)
                    continue

                current_clients = self._perform_scan(ip_range, timeout=4)
                self.nicknames.mark_clients(current_clients)
                current_macs = {c['mac']: c for c in current_clients}

                # ── Diff: detect joins and leaves ────────────────
                joined = {mac: c for mac, c in current_macs.items() if mac not in previous_macs}
                left   = {mac: c for mac, c in previous_macs.items() if mac not in current_macs}

                for mac, c in joined.items():
                    label = c.get('nickname') or c.get('name') or c['ip']
                    event_log.append((now, "JOIN", mac, c['ip'], label))
                    if scan_count > 1:  # Don't alert on first scan
                        print(f"  {Fore.GREEN}🟢 NEW DEVICE JOINED: {label} ({c['ip']}) [{mac}]{Style.RESET_ALL}")

                for mac, c in left.items():
                    label = c.get('nickname') or c.get('name') or c['ip']
                    event_log.append((now, "LEAVE", mac, c['ip'], label))
                    print(f"  {Fore.RED}🔴 DEVICE LEFT: {label} ({c['ip']}) [{mac}]{Style.RESET_ALL}")

                # ── Current Devices Table ─────────────────────────
                table_data = []
                for c in sorted(current_clients, key=lambda x: x['ip']):
                    nick = c.get('nickname')
                    label = f"{Fore.GREEN}★ {nick}{Style.RESET_ALL}" if nick else \
                            f"{Fore.YELLOW}? {c.get('name', c['ip'])}{Style.RESET_ALL}"
                    # Status badge
                    if c['mac'] in joined and scan_count > 1:
                        status = f"{Fore.GREEN}🟢 NEW{Style.RESET_ALL}"
                    else:
                        status = f"{Fore.WHITE}●  OK{Style.RESET_ALL}"

                    table_data.append([status, c['ip'], label, c['mac']])

                print(tabulate(
                    table_data,
                    headers=["Status", "IP Address", "Nickname / Hostname", "MAC Address"],
                    tablefmt="fancy_grid"
                ))
                print(f"  {Fore.CYAN}Total online: {len(current_clients)} device(s){Style.RESET_ALL}")

                # ── Event Log (last 10 events) ────────────────────
                if event_log:
                    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  📋 EVENT LOG (Recent){Style.RESET_ALL}")
                    for evt_time, evt_type, mac, ip, label in event_log[-10:]:
                        if evt_type == "JOIN":
                            icon = f"{Fore.GREEN}🟢 JOINED{Style.RESET_ALL}"
                        else:
                            icon = f"{Fore.RED}🔴 LEFT  {Style.RESET_ALL}"
                        print(f"  [{evt_time}] {icon}  {Fore.WHITE}{label:<25}{Style.RESET_ALL} "
                              f"{Fore.CYAN}{ip:<16}{Style.RESET_ALL} {mac}")

                # ── Summary Stats ─────────────────────────────────
                known_count = sum(1 for c in current_clients if c.get('nickname'))
                unknown_count = len(current_clients) - known_count
                print(f"\n  {Fore.GREEN}★ Known: {known_count}{Style.RESET_ALL}  "
                      f"{Fore.YELLOW}? Unknown: {unknown_count}{Style.RESET_ALL}  "
                      f"{Fore.CYAN}Total joins: {sum(1 for e in event_log if e[1]=='JOIN')}  "
                      f"{Fore.RED}Total leaves: {sum(1 for e in event_log if e[1]=='LEAVE')}{Style.RESET_ALL}")

                if unknown_count:
                    print(f"  {Fore.YELLOW}Tip: Label unknowns →  sudo ./lion nick set <MAC> \"Name\"{Style.RESET_ALL}")

                print(f"\n  {Fore.YELLOW}Next scan in {interval}s... Press CTRL+C to stop{Style.RESET_ALL}")

                # Update state for next scan
                previous_macs = current_macs
                time.sleep(interval)

        except KeyboardInterrupt:
            print(f"\n{Fore.GREEN}[+] Watcher stopped after {scan_count} scan(s).{Style.RESET_ALL}")
            print(f"[+] Total events: {len(event_log)} "
                  f"({sum(1 for e in event_log if e[1]=='JOIN')} joins, "
                  f"{sum(1 for e in event_log if e[1]=='LEAVE')} leaves)")
