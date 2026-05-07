from scapy.all import sniff, IP, UDP, DNS, DNSQR
from utils.helpers import print_info, print_success, print_error
from tabulate import tabulate

class DNSInterceptor:
    def __init__(self, interface):
        self.interface = interface
        self.records = []
        
    def start(self):
        print_info(f"Starting DNS Interception on interface {self.interface}...")
        print_info("Listening for DNS queries (Press CTRL+C to stop)")
        
        def process_dns_packet(packet):
            if packet.haslayer(DNSQR):
                try:
                    qname = packet[DNSQR].qname.decode('utf-8')
                    src_ip = packet[IP].src
                    self.records.append([src_ip, qname])
                    print(f"[DNS] Source: {src_ip} -> Query: {qname}")
                except Exception:
                    pass

        try:
            sniff(iface=self.interface, filter="udp port 53", prn=process_dns_packet, store=0)
        except PermissionError:
            print_error("Permission denied. Run with sudo privileges to intercept DNS.")
        except KeyboardInterrupt:
            self.stop()
            
    def stop(self):
        print_info("\nStopping DNS Interception...")
        if self.records:
            print_success("Intercepted DNS Queries Summary:")
            # limit to last 50
            print("\n" + tabulate(self.records[-50:], headers=["Source IP", "Query"], tablefmt="fancy_grid"))
        else:
            print_info("No DNS queries intercepted.")
