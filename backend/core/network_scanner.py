from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, wrpcap
from tabulate import tabulate
from utils.helpers import print_info, print_success, print_error, print_warning, get_device_name
from .config import PORT_MAP
import socket
import netifaces
import os

class NetworkScanner:
    """
    Handles network discovery and packet sniffing.
    Supports dual-pass scanning for higher accuracy.
    """
    def __init__(self, interface):
        self.interface = interface
        self.hostname_cache = {}
        
    def get_hostname(self, ip):
        """Resolve IP to hostname with local caching."""
        if ip in self.hostname_cache:
            return self.hostname_cache[ip]
        name = get_device_name(ip)
        self.hostname_cache[ip] = name
        return name

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

        print_success(f"Found {len(clients)} active device(s)\n")
        table_data = [
            [f"[{i+1}]", c['ip'], c['name'], c['mac']]
            for i, c in enumerate(clients)
        ]
        print(tabulate(
            table_data,
            headers=["#", "IP Address", "Hostname", "MAC Address"],
            tablefmt="fancy_grid"
        ))

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
