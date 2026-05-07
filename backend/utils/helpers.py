import netifaces
import socket
from colorama import Fore, Style
from scapy.all import IP, UDP, DNS, DNSQR, sr1, NBNSQueryRequest
import threading

def get_default_interface():
    try:
        # Get the default gateway interface for IPv4
        default_gateway = netifaces.gateways()['default'][netifaces.AF_INET]
        return default_gateway[1]
    except Exception:
        return None

def print_banner():
    banner = rf"""{Fore.CYAN}{Style.BRIGHT}
  _      _               ______                ____   _____ _____ _   _ _______ 
 | |    (_)             |  ____|              / __ \ / ____|_   _| \ | |__   __|
 | |     _  ___  _ __   | |__  _   _  ___    | |  | | (___   | | |  \| |  | |   
 | |    | |/ _ \| '_ \  |  __|| | | |/ _ \   | |  | |\___ \  | | | . ` |  | |   
 | |____| | (_) | | | | | |___| |_| |  __/   | |__| |____) |_| |_| |\  |  | |   
 |______|_|\___/|_| |_| |______\__, |\___|    \____/|_____/|_____|_| \_|  |_|   
                                __/ |                                           
                               |___/                                            

    {Fore.GREEN}[+] High-Performance CLI Network Intelligence Engine
    {Fore.GREEN}[+] Developed by Myo Thiha Tun
    {Style.RESET_ALL}"""
    print(banner)

def print_info(msg):
    print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")

def print_success(msg):
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

def print_warning(msg):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def print_error(msg):
    print(f"{Fore.RED}[X] {msg}{Style.RESET_ALL}")

def get_device_name(ip, timeout=1):
    """
    Tries to resolve an IP to a human-readable name using:
    1. Reverse DNS
    2. NetBIOS (NBNS)
    3. mDNS (Multicast DNS)
    """
    name = ip # Default to IP

    # 1. Try Reverse DNS
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass

    # 2. Try NetBIOS (for Windows/Samba devices)
    try:
        # NetBIOS Name Service (NBNS) query
        nbns_query = IP(dst=ip)/UDP(sport=137, dport=137)/NBNSQueryRequest(QUESTION_NAME="*", QUESTION_TYPE="NBSTAT")
        ans = sr1(nbns_query, timeout=timeout, verbose=0)
        if ans and ans.haslayer("NBNSNodeStatusResponse"):
            # Extract name from response
            nb_name = ans.getlayer("NBNSNodeStatusResponse").NAME_STR.strip()
            if nb_name:
                return nb_name.decode('utf-8', errors='ignore').strip()
    except Exception:
        pass

    # 3. Try mDNS (for Apple/Linux/Modern devices)
    try:
        # Construct PTR query for reverse mDNS
        ptr_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        mdns_query = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname=ptr_name, qtype="PTR"))
        ans = sr1(mdns_query, timeout=timeout, verbose=0)
        if ans and ans.haslayer(DNS) and ans.ancount > 0:
            mdns_name = ans.an.rdata.decode('utf-8', errors='ignore').strip('.')
            if mdns_name:
                return mdns_name
    except Exception:
        pass

    return name
