import os
import time
from scapy.all import IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from utils.helpers import print_info, print_success, print_error

class L7Analyzer:
    def __init__(self, interface=None, count=0, filter_proto=None):
        self.interface = interface
        self.count = count
        self.filter_proto = filter_proto
        # JS to inject
        self.js_payload = "<script>alert('Lion-Eye has identified this traffic!');</script>"
        self.last_urls = []

    def start(self):
        from scapy.all import sniff
        print_info(f"Starting Layer 7 deep inspection on {self.interface}...")
        sniff(iface=self.interface, prn=self.process_packet, count=self.count, store=False)

    def process_packet(self, pkt):
        """Analyze Layer 7 content for image URLs and injection points."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        # ── 1. Image URL Extractor (Live) ─────────────────────
        if pkt.haslayer(HTTPRequest):
            try:
                host = pkt[HTTPRequest].Host.decode()
                path = pkt[HTTPRequest].Path.decode()
                url = host + path
                
                # Check if the requested path looks like an image
                image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg']
                if any(ext in path.lower() for ext in image_extensions):
                    full_url = f"http://{url}"
                    if full_url not in self.last_urls:
                        print_success(f"Target viewing image: {full_url}")
                        self.last_urls.append(full_url)
                        
                        # Log to the common text log
                        with open("lion_eye_activity.txt", "a") as f:
                            f.write(f"[{time.strftime('%H:%M:%S')}] [IMAGE_VIEW] {full_url}\n")

                        # Keep only last 10 to avoid memory bloat
                        if len(self.last_urls) > 10:
                            self.last_urls.pop(0)
            except Exception:
                pass

        # ── 2. JS Injection Logic ─────────────────────────────
        # Identified points are handled by the separate NetfilterQueue thread if active
        
    def get_injection_script(self):
        """Returns the script to be injected."""
        return self.js_payload
