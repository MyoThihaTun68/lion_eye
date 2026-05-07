# Lion-Eye Intelligence Config
from colorama import Fore, Style

# ─────────────────────────────────────────────────────────
# Application & Service Mapping
# ─────────────────────────────────────────────────────────

APP_MAP = {
    "Facebook": ["facebook", "fbcdn", "messenger"],
    "Instagram": ["instagram", "cdninstagram"],
    "WhatsApp": ["whatsapp", "wa.me"],
    "TikTok": ["tiktok", "byteoversea", "ibyteimg"],
    "YouTube": ["youtube", "googlevideo", "ytimg"],
    "Netflix": ["netflix", "nflxvideo"],
    "Spotify": ["spotify"],
    "Telegram": ["telegram", "t.me"],
    "Google": ["google", "1e100.net", "gstatic"],
}

KNOWN_SERVICES = {
    "DNS", "HTTP", "HTTPS", "FTP", "FTP-DATA", "SSH", "TELNET",
    "SMTP", "SMTP-SUB", "POP3", "POP3S", "IMAP", "IMAPS",
    "NTP", "DHCP-S", "DHCP-C", "SMB", "SYSLOG", "IPP",
    "MQTT", "MYSQL", "POSTGRES", "REDIS", "RDP", "SIP",
    "HTTP-ALT", "HTTPS-ALT"
}

PORT_MAP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP-S", 68: "DHCP-C", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 514: "SYSLOG",
    587: "SMTP-SUB", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1883: "MQTT", 3306: "MYSQL", 3389: "RDP", 5060: "SIP",
    5432: "POSTGRES", 6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}

# ─────────────────────────────────────────────────────────
# UI Themes
# ─────────────────────────────────────────────────────────

THEME = {
    "primary": Fore.GREEN,
    "secondary": Fore.CYAN,
    "warning": Fore.YELLOW,
    "error": Fore.RED,
    "info": Fore.WHITE,
    "accent": Fore.MAGENTA,
    "bold": Style.BRIGHT,
    "reset": Style.RESET_ALL
}
