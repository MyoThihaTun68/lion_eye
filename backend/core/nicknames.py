"""
Lion-Eye Device Nickname Manager
Saves user-defined labels for devices by MAC address into a local JSON config file.
"""

import json
import os
from colorama import Fore, Style
from utils.helpers import print_info, print_success, print_warning, print_error

# Default location: same directory as lion_eye.py
NICKNAME_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "device_nicknames.json")


class NicknameManager:
    """
    Manages a persistent JSON file mapping MAC addresses to user-defined nicknames.
    
    File format:
    {
        "08:f8:bc:74:20:9c": {"name": "Boss's MacBook", "note": "Finance dept"},
        "90:f9:70:86:28:21": {"name": "Main Router",    "note": ""}
    }
    """

    def __init__(self, filepath=None):
        self.filepath = filepath or NICKNAME_FILE
        self._data = {}
        self._load()

    # ─────────────────────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────────────────────

    def _load(self):
        """Load nicknames from JSON file. Creates empty file if missing."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r") as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, IOError):
                print_warning("Nickname file corrupt — starting fresh.")
                self._data = {}
        else:
            self._data = {}

    def _save(self):
        """Persist current nickname data to JSON file."""
        try:
            with open(self.filepath, "w") as f:
                json.dump(self._data, f, indent=2)
        except IOError as e:
            print_error(f"Could not save nicknames: {e}")

    # ─────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────

    def get(self, mac):
        """Return nickname string for a MAC, or None if not set."""
        mac_key = mac.lower()
        entry = self._data.get(mac_key)
        return entry["name"] if entry else None

    def get_display(self, mac, fallback=None):
        """Return nickname if set, else fallback (e.g. hostname or IP)."""
        nick = self.get(mac)
        return f"★ {nick}" if nick else (fallback or mac)

    def set(self, mac, name, note=""):
        """Add or update a nickname for a MAC address."""
        mac_key = mac.lower()
        self._data[mac_key] = {"name": name.strip(), "note": note.strip()}
        self._save()
        print_success(f"Nickname saved: {mac_key} → \"{name}\"")

    def remove(self, mac):
        """Remove a nickname entry."""
        mac_key = mac.lower()
        if mac_key in self._data:
            removed = self._data.pop(mac_key)
            self._save()
            print_success(f"Removed nickname: \"{removed['name']}\" ({mac_key})")
        else:
            print_warning(f"No nickname found for {mac_key}")

    def list_all(self):
        """Pretty-print all saved nicknames."""
        if not self._data:
            print_warning("No nicknames saved yet.")
            print_info("Add one with:  sudo ./lion nick set <MAC> \"<Name>\"")
            return

        from tabulate import tabulate
        rows = [
            [
                f"{Fore.CYAN}{mac}{Style.RESET_ALL}",
                f"{Fore.GREEN}★ {entry['name']}{Style.RESET_ALL}",
                f"{Fore.WHITE}{entry.get('note', '')}{Style.RESET_ALL}"
            ]
            for mac, entry in self._data.items()
        ]
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  📛 SAVED DEVICE NICKNAMES{Style.RESET_ALL}\n")
        print(tabulate(rows, headers=["MAC Address", "Nickname", "Note"], tablefmt="fancy_grid"))
        print(f"\n  {Fore.YELLOW}Total: {len(self._data)} device(s){Style.RESET_ALL}\n")

    def is_known(self, mac):
        """Return True if this MAC has a saved nickname (trusted/known device)."""
        return mac.lower() in self._data

    def mark_clients(self, clients):
        """
        Annotate a list of client dicts with 'nickname' and 'known' fields.
        Modifies the list in-place and returns it.
        """
        for c in clients:
            nick = self.get(c['mac'])
            c['nickname'] = nick
            c['known'] = nick is not None
        return clients
