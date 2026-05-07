import argparse
import sys
import os
from colorama import init, Fore, Style
from core.network_scanner import NetworkScanner
from core.arp_spoofer import ARPSpoofer
from core.dns_interceptor import DNSInterceptor
from core.bandwidth_monitor import BandwidthMonitor
from core.l7_parser import L7Analyzer
from core.config import KNOWN_SERVICES
from utils.helpers import (
    print_banner, get_default_interface,
    print_info, print_error, print_success, print_warning
)

init(autoreset=True)

# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────


def get_gateway_ip(interface):
    """Return the default gateway IP for the given interface."""
    import netifaces
    try:
        gateways = netifaces.gateways()
        for gw_ip, gw_iface, _ in gateways.get(netifaces.AF_INET, []):
            if gw_iface == interface:
                return gw_ip
        default = gateways.get("default", {}).get(netifaces.AF_INET)
        if default:
            return default[0]
    except Exception:
        pass
    return None


def _resolve_interface(args):
    """Auto-detect the network interface when not explicitly given."""
    if not getattr(args, "interface", None):
        args.interface = get_default_interface()
        if not args.interface:
            print_error("Could not auto-detect network interface. Use -i to specify one.")
            sys.exit(1)
        print_info(f"Auto-detected interface: {args.interface}")


def _add_hunt_filter_args(parser):
    """Add --only and --ignore filter flags to a subparser."""
    parser.add_argument(
        "--only", metavar="SERVICE",
        help="Show ONLY packets matching this service (e.g. HTTPS, DNS, HTTP, SSH)."
    )
    parser.add_argument(
        "--ignore", metavar="SERVICE", nargs="+",
        help="Hide packets matching these services (e.g. --ignore DNS NTP)."
    )


def _apply_hunt_filters(spoofer, args):
    """Transfer CLI filter args into the ARPSpoofer instance."""
    if getattr(args, "only", None):
        service = args.only.upper()
        if service not in KNOWN_SERVICES:
            print_warning(f"Unknown service '{service}'. Known: {', '.join(sorted(KNOWN_SERVICES))}")
        spoofer.filter_only = service

    if getattr(args, "ignore", None):
        for svc in args.ignore:
            svc_upper = svc.upper()
            if svc_upper not in KNOWN_SERVICES:
                print_warning(f"Unknown service '{svc_upper}'. Known: {', '.join(sorted(KNOWN_SERVICES))}")
            spoofer.filter_ignore.add(svc_upper)


# ─────────────────────────────────────────────────────────
# Interactive Workflows
# ─────────────────────────────────────────────────────────

def select_target(interface):
    """Scan and return a single target dictionary or None."""
    while True:
        scanner = NetworkScanner(interface)
        clients = scanner.scan_network()
        scanner.print_hosts(clients)

        if not clients:
            print_warning("No devices found on the network. Press 'r' to try again or 'q' to quit.")

        print()
        while True:
            try:
                choice = input(
                    f"{Fore.CYAN}[?] Enter device number (1-{len(clients)} if any), 'r' to reload, or 'q' to quit: {Style.RESET_ALL}"
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return None

            if choice == "q":
                return None
            elif choice == "r":
                print("\n[*] Rescanning network...")
                break  # Exit inner loop to rescan

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(clients):
                    return clients[idx]
            except ValueError:
                pass

            print_warning("Invalid choice. Please enter a valid number, 'r', or 'q'.")


def launch_hunt(interface, target, args):
    target_ip = target["ip"]
    print_success(f"Targeting: {target_ip} ({target['name']})")
    
    gateway_ip = get_gateway_ip(interface)
    if not gateway_ip:
        print_error("Could not determine gateway IP.")
        return

    spoofer = ARPSpoofer(
        interface, 
        target_ip, 
        gateway_ip, 
        output_file=getattr(args, 'output', None),
        message=getattr(args, 'message', None),
        redirect_url=getattr(args, 'spoof', None),
        dns_map=getattr(args, 'map', None)
    )
    _apply_hunt_filters(spoofer, args)
    
    if getattr(args, 'ghost', False):
        spoofer.ghost_mode()
    else:
        spoofer.hunt()


def launch_kick(interface, target):
    target_ip = target["ip"]
    print_success(f"Disconnecting: {target_ip} ({target['name']})")
    
    gateway_ip = get_gateway_ip(interface)
    if not gateway_ip:
        print_error("Could not determine gateway IP.")
        return

    spoofer = ARPSpoofer(interface, target_ip, gateway_ip)
    spoofer.kick()


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Lion-Eye OSINT - Network Intelligence Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available Modules")

    # ── scan ──────────────────────────────────────────────
    scanner_parser = subparsers.add_parser(
        "scan", help="Network Discovery and Packet Sniffing"
    )
    scanner_parser.add_argument(
        "-i", "--interface", help="Network interface. Auto-detected if omitted."
    )
    scanner_parser.add_argument(
        "--sniff", action="store_true", help="Start packet sniffing"
    )
    scanner_parser.add_argument(
        "--hunt", action="store_true", help="Scan → Pick → Hunt (Full UI)"
    )
    scanner_parser.add_argument(
        "--ghost", action="store_true", help="Scan → Pick → Ghost (Silent/Redirect UI)"
    )
    scanner_parser.add_argument(
        "--kick", action="store_true", help="Scan → Pick → Kick (Disconnect target)"
    )
    scanner_parser.add_argument("-o", "--output", help="Save to PCAP")
    scanner_parser.add_argument("--message", help="Inject JS alert message (HTTP only)")
    scanner_parser.add_argument("--spoof", help="Redirect target to this URL (HTTP only)")
    scanner_parser.add_argument("--map", help="DNS Mapping (e.g. facebook.com:google.com)")
    _add_hunt_filter_args(scanner_parser)

    # ── arp (Manually specified hunt/spoof) ───────────────
    arp_parser = subparsers.add_parser("arp", help="ARP Spoofing Module")
    arp_parser.add_argument("-i", "--interface", help="Network interface.")
    arp_parser.add_argument("-t", "--target",  required=True, help="Target IP")
    arp_parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    arp_parser.add_argument("--hunt", action="store_true", help="Start live dashboard hunt")
    arp_parser.add_argument("--ghost", action="store_true", help="Start silent redirection mode")
    arp_parser.add_argument("--message", help="Inject JS alert message (HTTP only)")
    arp_parser.add_argument("--spoof", help="Redirect target to this URL (HTTP only)")
    arp_parser.add_argument("--map", help="DNS Mapping (e.g. facebook.com:google.com)")
    _add_hunt_filter_args(arp_parser)

    # ── kick (Direct disconnect) ──────────────────────────
    kick_parser = subparsers.add_parser("kick", help="Disconnect a target from the network")
    kick_parser.add_argument("-i", "--interface", help="Network interface.")
    kick_parser.add_argument("-t", "--target", required=True, help="Target IP address to kick")
    kick_parser.add_argument("-g", "--gateway", help="Gateway IP (auto-detected if omitted)")

    # ── Other modules (DNS, Bandwidth, L7) ────────────────
    subparsers.add_parser("dns", help="DNS Interceptor")
    subparsers.add_parser("bandwidth", help="Bandwidth Monitor")
    l7_parser = subparsers.add_parser("l7", help="Layer 7 Deep Analysis")
    l7_parser.add_argument("-c", "--count", type=int, default=200)
    l7_parser.add_argument("-f", "--filter", default="all")

    # ── killer ────────────────────────────────────────────
    subparsers.add_parser("killer", help="ARP Killer (Kick ALL devices off network)")


    args = parser.parse_args()

    try:
        if not args.command:
            parser.print_help()
            sys.exit(0)

        _resolve_interface(args)

        if args.command == "scan":
            if args.hunt or getattr(args, 'ghost', False):
                target = select_target(args.interface)
                if target: launch_hunt(args.interface, target, args)
            elif args.kick:
                target = select_target(args.interface)
                if target: launch_kick(args.interface, target)
            elif args.sniff:
                scanner = NetworkScanner(args.interface)
                scanner.start_sniffing(output_file=args.output)
            else:
                scanner = NetworkScanner(args.interface)
                clients = scanner.scan_network()
                scanner.print_hosts(clients)

        elif args.command == "arp":
            spoofer = ARPSpoofer(
                args.interface, 
                args.target, 
                args.gateway, 
                output_file=getattr(args, 'output', None),
                message=getattr(args, 'message', None),
                redirect_url=getattr(args, 'spoof', None),
                dns_map=getattr(args, 'map', None)
            )
            if args.hunt:
                _apply_hunt_filters(spoofer, args)
                spoofer.hunt()
            elif getattr(args, 'ghost', False):
                spoofer.ghost_mode()
            else:
                spoofer.start_poisoning()

        elif args.command == "kick":
            gw = args.gateway or get_gateway_ip(args.interface)
            if not gw:
                print_error("Could not detect gateway. Use -g to specify.")
                sys.exit(1)
            spoofer = ARPSpoofer(args.interface, args.target, gw)
            spoofer.kick()

        elif args.command == "dns":
            DNSInterceptor(args.interface).start()
        elif args.command == "bandwidth":
            BandwidthMonitor(args.interface).start()
        elif args.command == "l7":
            L7Analyzer(args.interface, count=args.count, filter_proto=args.filter).start()

        elif args.command == "killer":
            scanner = NetworkScanner(args.interface)
            clients = scanner.scan_network()
            if not clients:
                print_error("No devices found to kick.")
                sys.exit(1)
            
            gw = get_gateway_ip(args.interface)
            spoofer = ARPSpoofer(args.interface, "0.0.0.0", gw)
            spoofer.kick_all(clients)


    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user. Cleaning up...{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[X] An error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
