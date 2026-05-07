import psutil
import time
from tabulate import tabulate
from utils.helpers import print_info, print_success, print_error, print_warning

class BandwidthMonitor:
    def __init__(self, interface):
        self.interface = interface
        
    def get_bytes(self):
        try:
            net_io = psutil.net_io_counters(pernic=True)
            if self.interface not in net_io:
                print_error(f"Interface {self.interface} not found.")
                return None, None
            
            stats = net_io[self.interface]
            return stats.bytes_sent, stats.bytes_recv
        except Exception as e:
            print_error(f"Error accessing network stats: {e}")
            return None, None

    def start(self):
        print_info(f"Starting Bandwidth Monitor on {self.interface}...")
        print_warning("Press CTRL+C to stop.")
        
        bytes_sent, bytes_recv = self.get_bytes()
        if bytes_sent is None:
            return
            
        try:
            while True:
                time.sleep(1)
                new_sent, new_recv = self.get_bytes()
                
                send_speed = new_sent - bytes_sent
                recv_speed = new_recv - bytes_recv
                
                bytes_sent, bytes_recv = new_sent, new_recv
                
                # Format bytes to KB or MB
                def format_speed(b):
                    if b < 1024:
                        return f"{b} B/s"
                    elif b < 1024 * 1024:
                        return f"{b / 1024:.2f} KB/s"
                    else:
                        return f"{b / (1024 * 1024):.2f} MB/s"
                
                table = [
                    ["Upload", format_speed(send_speed)],
                    ["Download", format_speed(recv_speed)]
                ]
                
                print("\033c", end="") # Clear terminal
                from utils.helpers import print_banner
                print_banner()
                print_info(f"Monitoring Interface: {self.interface}\n")
                print(tabulate(table, headers=["Direction", "Speed"], tablefmt="fancy_grid"))
                
        except KeyboardInterrupt:
            print_info("\nStopping Bandwidth Monitor.")
