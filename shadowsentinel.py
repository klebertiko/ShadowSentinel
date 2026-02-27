#!/usr/bin/env python3
"""
SHADOW SENTINEL v2.0 - Stealth Network Threat Detection
The guardian that operates in the shadows, invisible to attackers.

Author: Kleber Tiko aka: Nightwolf
License: GPL-3.0
Requirements: scapy, rich, psutil

CRITICAL: Requires root/administrator privileges
"""

import sys
import os
import time
import signal
import argparse
import json
import threading
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Set, Deque

try:
    from scapy.all import (
        sniff, ARP, IP, TCP, UDP, ICMP, DNS, conf,
        wrpcap, get_if_list
    )
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import psutil
except ImportError as e:
    print(f"[FATAL] Missing dependency: {e}")
    print("Install: pip3 install scapy rich psutil")
    sys.exit(1)


# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

class Config:
    """Centralized configuration with security best practices
    
    STEALTH MODE DESIGN:
    - Shadow Sentinel operates in pure passive mode
    - Uses promiscuous mode to capture all packets
    - NEVER sends packets (zero network footprint)
    - Undetectable by attackers performing reconnaissance
    """
    
    # Detection Thresholds (adjustable via CLI)
    ARP_CACHE_TIMEOUT = 300  # 5 minutes
    PORT_SCAN_THRESHOLD = 15  # ports in window
    PORT_SCAN_WINDOW = 10     # seconds
    SYN_FLOOD_THRESHOLD = 50  # SYN packets in window
    SYN_FLOOD_WINDOW = 5      # seconds
    ICMP_FLOOD_THRESHOLD = 100
    DNS_TUNNEL_THRESHOLD = 50  # queries per host
    
    # Memory Management
    TRACKER_CLEANUP_INTERVAL = 60  # seconds
    MAX_TRACKER_SIZE = 10000
    
    # Logging
    LOG_DIR = Path("./logs")
    PCAP_DIR = Path("./pcaps")
    ALERT_LOG = "alerts.json"
    SESSION_LOG = "session.log"
    
    # Interface
    REFRESH_RATE = 2  # Hz
    PACKET_BUFFER = 100


# ============================================================================
# PRIVILEGE VALIDATION
# ============================================================================

def check_privileges() -> bool:
    """Validate root/admin privileges with platform detection"""
    try:
        if os.name == 'posix':
            if os.geteuid() != 0:
                return False
        elif os.name == 'nt':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return False
        return True
    except Exception as e:
        console.print(f"[red]Error checking privileges: {e}[/]")
        return False


# ============================================================================
# THREAT DETECTION ENGINE
# ============================================================================

class ThreatDetector:
    """Thread-safe threat detection with temporal analysis"""
    
    def __init__(self):
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "ARP Spoofing": 0,
            "Port Scan": 0,
            "SYN Flood": 0,
            "ICMP Flood": 0,
            "DNS Tunneling": 0,
            "Suspicious Payload": 0
        }
        
        # Time-windowed trackers (using deque for O(1) operations)
        self.arp_cache: Dict[str, tuple] = {}  # ip -> (mac, timestamp)
        self.port_scans: Dict[str, Deque] = defaultdict(lambda: deque(maxlen=100))
        self.syn_floods: Dict[str, Deque] = defaultdict(lambda: deque(maxlen=200))
        self.icmp_floods: Dict[str, Deque] = defaultdict(lambda: deque(maxlen=200))
        self.dns_queries: Dict[str, int] = defaultdict(int)
        
        # Alert history for deduplication
        self.recent_alerts: Deque = deque(maxlen=100)
        
        # Packet capture for forensics
        self.suspicious_packets = []
        
        # Statistics
        self.total_packets = 0
        self.last_cleanup = time.time()
        
    def cleanup_old_data(self):
        """Periodic memory cleanup to prevent exhaustion"""
        now = time.time()
        
        with self.lock:
            # Clean ARP cache
            expired = [ip for ip, (_, ts) in self.arp_cache.items() 
                      if now - ts > Config.ARP_CACHE_TIMEOUT]
            for ip in expired:
                del self.arp_cache[ip]
            
            # Clean time-windowed data
            cutoff_port = now - Config.PORT_SCAN_WINDOW
            cutoff_syn = now - Config.SYN_FLOOD_WINDOW
            cutoff_icmp = now - Config.SYN_FLOOD_WINDOW
            
            for ip in list(self.port_scans.keys()):
                self.port_scans[ip] = deque(
                    [t for t in self.port_scans[ip] if t[1] > cutoff_port],
                    maxlen=100
                )
                if not self.port_scans[ip]:
                    del self.port_scans[ip]
            
            for ip in list(self.syn_floods.keys()):
                self.syn_floods[ip] = deque(
                    [t for t in self.syn_floods[ip] if t > cutoff_syn],
                    maxlen=200
                )
                if not self.syn_floods[ip]:
                    del self.syn_floods[ip]
                    
            for ip in list(self.icmp_floods.keys()):
                self.icmp_floods[ip] = deque(
                    [t for t in self.icmp_floods[ip] if t > cutoff_icmp],
                    maxlen=200
                )
                if not self.icmp_floods[ip]:
                    del self.icmp_floods[ip]
            
            # Reset DNS counters periodically
            if now - self.last_cleanup > 300:  # 5 minutes
                self.dns_queries.clear()
                self.last_cleanup = now
    
    def log_alert(self, threat_type: str, message: str, severity: str = "HIGH"):
        """Thread-safe alert logging with deduplication"""
        alert_hash = hash(f"{threat_type}{message[:50]}")
        
        if alert_hash in self.recent_alerts:
            return  # Duplicate alert, skip
        
        with self.lock:
            self.recent_alerts.append(alert_hash)
            
            alert = {
                "timestamp": datetime.now().isoformat(),
                "threat": threat_type,
                "severity": severity,
                "message": message
            }
            
            # Append to JSON log
            log_file = Config.LOG_DIR / Config.ALERT_LOG
            try:
                with open(log_file, 'a') as f:
                    f.write(json.dumps(alert) + '\n')
            except Exception as e:
                console.log(f"[red]Log write error: {e}[/]")
    
    def detect_arp_spoofing(self, pkt) -> bool:
        """Detect ARP cache poisoning attacks"""
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:  # is-at response
            return False
        
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        now = time.time()
        
        with self.lock:
            if src_ip in self.arp_cache:
                cached_mac, _ = self.arp_cache[src_ip]
                if cached_mac != src_mac:
                    self.stats["ARP Spoofing"] += 1
                    msg = f"ARP Spoofing: {src_ip} changed MAC {cached_mac} → {src_mac}"
                    self.log_alert("ARP Spoofing", msg, "CRITICAL")
                    self.suspicious_packets.append(pkt)
                    return True
            
            self.arp_cache[src_ip] = (src_mac, now)
        return False
    
    def detect_port_scan(self, pkt) -> bool:
        """Detect port scanning with temporal analysis"""
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return False
        
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        now = time.time()
        
        with self.lock:
            self.port_scans[src_ip].append((dst_port, now))
            
            # Count unique ports in time window
            cutoff = now - Config.PORT_SCAN_WINDOW
            recent_ports = {port for port, ts in self.port_scans[src_ip] if ts > cutoff}
            
            if len(recent_ports) > Config.PORT_SCAN_THRESHOLD:
                self.stats["Port Scan"] += 1
                msg = f"Port Scan: {src_ip} scanned {len(recent_ports)} ports in {Config.PORT_SCAN_WINDOW}s"
                self.log_alert("Port Scan", msg, "HIGH")
                self.suspicious_packets.append(pkt)
                self.port_scans[src_ip].clear()  # Reset to avoid spam
                return True
        return False
    
    def detect_syn_flood(self, pkt) -> bool:
        """Detect SYN flood attacks"""
        if not (pkt.haslayer(TCP) and pkt[TCP].flags & 0x02):  # SYN flag
            return False
        
        src_ip = pkt[IP].src
        now = time.time()
        
        with self.lock:
            self.syn_floods[src_ip].append(now)
            
            # Count SYNs in time window
            cutoff = now - Config.SYN_FLOOD_WINDOW
            recent_syns = sum(1 for ts in self.syn_floods[src_ip] if ts > cutoff)
            
            if recent_syns > Config.SYN_FLOOD_THRESHOLD:
                self.stats["SYN Flood"] += 1
                msg = f"SYN Flood: {src_ip} sent {recent_syns} SYNs in {Config.SYN_FLOOD_WINDOW}s"
                self.log_alert("SYN Flood", msg, "CRITICAL")
                self.suspicious_packets.append(pkt)
                self.syn_floods[src_ip].clear()
                return True
        return False
    
    def detect_icmp_flood(self, pkt) -> bool:
        """Detect ICMP flood (ping flood)"""
        if not pkt.haslayer(ICMP):
            return False
        
        src_ip = pkt[IP].src
        now = time.time()
        
        with self.lock:
            self.icmp_floods[src_ip].append(now)
            
            cutoff = now - Config.SYN_FLOOD_WINDOW
            recent_icmp = sum(1 for ts in self.icmp_floods[src_ip] if ts > cutoff)
            
            if recent_icmp > Config.ICMP_FLOOD_THRESHOLD:
                self.stats["ICMP Flood"] += 1
                msg = f"ICMP Flood: {src_ip} sent {recent_icmp} ICMP packets in {Config.SYN_FLOOD_WINDOW}s"
                self.log_alert("ICMP Flood", msg, "HIGH")
                self.suspicious_packets.append(pkt)
                self.icmp_floods[src_ip].clear()
                return True
        return False
    
    def detect_dns_tunneling(self, pkt) -> bool:
        """Detect potential DNS tunneling"""
        if not (pkt.haslayer(DNS) and pkt.haslayer(UDP)):
            return False
        
        src_ip = pkt[IP].src
        
        with self.lock:
            self.dns_queries[src_ip] += 1
            
            if self.dns_queries[src_ip] > Config.DNS_TUNNEL_THRESHOLD:
                self.stats["DNS Tunneling"] += 1
                msg = f"DNS Tunneling: {src_ip} made {self.dns_queries[src_ip]} queries (threshold: {Config.DNS_TUNNEL_THRESHOLD})"
                self.log_alert("DNS Tunneling", msg, "MEDIUM")
                self.dns_queries[src_ip] = 0  # Reset
                return True
        return False
    
    def detect_suspicious_payload(self, pkt) -> bool:
        """Detect suspicious payloads using regex for common attack vectors."""
        if not pkt.haslayer(TCP) or not hasattr(pkt[TCP], 'payload'):
            return False

        try:
            payload = bytes(pkt[TCP].payload).decode('utf-8', errors='ignore')
        except (UnicodeDecodeError, AttributeError):
            return False

        patterns = {
            "SQL Injection": re.compile(r"(\'|\")\s*(union|select|insert|update|delete|drop)", re.IGNORECASE),
            "XSS": re.compile(r"<script|<img\s+src\s*=\s*['\"]\s*javascript:", re.IGNORECASE),
            "Path Traversal": re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE),
            "Command Injection": re.compile(r";\s*(cat|ls|dir|whoami|uname|cmd\.exe)", re.IGNORECASE),
            "Log4Shell": re.compile(r"\$\{jndi:(ldap|rmi|dns):", re.IGNORECASE)
        }

        for category, pattern in patterns.items():
            match = pattern.search(payload)
            if match:
                with self.lock:
                    self.stats["Suspicious Payload"] += 1
                src_ip = pkt[IP].src
                msg = f"Suspicious Payload ({category}): {src_ip} → Pattern '{match.group(0)}' detected"
                self.log_alert("Suspicious Payload", msg, "HIGH")
                self.suspicious_packets.append(pkt)
                return True
        
        return False
    
    def process_packet(self, pkt):
        """Main packet processing pipeline
        
        STEALTH OPERATION:
        - Only analyzes incoming packets
        - Never generates responses
        - Maintains zero network footprint
        """
        with self.lock:
            self.total_packets += 1
        
        # Run all detection modules
        self.detect_arp_spoofing(pkt)
        self.detect_port_scan(pkt)
        self.detect_syn_flood(pkt)
        self.detect_icmp_flood(pkt)
        self.detect_dns_tunneling(pkt)
        self.detect_suspicious_payload(pkt)
        
        # Periodic cleanup
        if time.time() - self.last_cleanup > Config.TRACKER_CLEANUP_INTERVAL:
            self.cleanup_old_data()
    
    def get_stats(self) -> dict:
        """Thread-safe statistics retrieval"""
        with self.lock:
            return self.stats.copy()
    
    def save_pcap(self):
        """Save suspicious packets for forensic analysis"""
        if not self.suspicious_packets:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = Config.PCAP_DIR / f"shadow_capture_{timestamp}.pcap"
        
        try:
            wrpcap(str(pcap_file), self.suspicious_packets)
            console.print(f"[green]✓[/] Saved {len(self.suspicious_packets)} suspicious packets to {pcap_file}")
        except Exception as e:
            console.print(f"[red]✗[/] PCAP save error: {e}")


# ============================================================================
# USER INTERFACE
# ============================================================================

console = Console()

def generate_banner():
    """ASCII art banner"""
    banner = """[bold red]
    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
    ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
    ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ 
    
    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝[/bold red]
    [bold white]           SHADOW SENTINEL v2.0 - Stealth Edition[/bold white]
    [dim]       The Guardian Operating in the Shadows of Your Network[/dim]
    """
    return Panel(banner, border_style="blue", expand=False)


def make_dashboard(detector: ThreatDetector, interface: str):
    """Generate real-time dashboard"""
    stats = detector.get_stats()
    
    # Threat table
    table = Table(title=f"🌑 Shadow Sentinel: {interface} [STEALTH MODE]", show_header=True, 
                  header_style="bold magenta")
    table.add_column("Threat Vector", style="cyan", width=20)
    table.add_column("Detections", justify="right", style="yellow")
    table.add_column("Status", justify="center", width=15)
    
    for threat, count in stats.items():
        if count == 0:
            status = "[green]✓ SAFE[/green]"
        elif count < 5:
            status = "[yellow]⚠ WATCH[/yellow]"
        else:
            status = "[bold red blink]🚨 ALERT[/bold red blink]"
        
        table.add_row(threat, str(count), status)
    
    # System stats
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    
    info_table = Table(show_header=False, box=None)
    info_table.add_column("Metric", style="dim")
    info_table.add_column("Value", style="bold white")
    
    info_table.add_row("⏱  Uptime", str(datetime.now().strftime('%H:%M:%S')))
    info_table.add_row("📦 Packets", f"{detector.total_packets:,}")
    info_table.add_row("💾 Memory", f"{mem:.1f}%")
    info_table.add_row("⚙️  CPU", f"{cpu:.1f}%")
    info_table.add_row("👁️  Mode", "[bold green]STEALTH[/] (0 pkts sent)")
    
    layout = Layout()
    layout.split_column(
        Layout(table, name="threats"),
        Layout(info_table, name="stats", size=7)
    )
    
    return Panel(layout, border_style="blue", title="[bold]Dashboard[/bold]")


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class SentinelApp:
    """Main application controller"""
    
    def __init__(self, interface: str, filter_expr: str):
        self.interface = interface
        self.filter = filter_expr
        self.detector = ThreatDetector()
        self.running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Graceful shutdown handler"""
        console.print("\n[yellow]⚠ Shutdown signal received...[/]")
        self.running = False
    
    def setup_environment(self):
        """Initialize directories and logging"""
        Config.LOG_DIR.mkdir(exist_ok=True)
        Config.PCAP_DIR.mkdir(exist_ok=True)
        
        # Create session log
        session_file = Config.LOG_DIR / Config.SESSION_LOG
        with open(session_file, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Shadow Sentinel Session Start: {datetime.now()}\n")
            f.write(f"Interface: {self.interface}\n")
            f.write(f"Filter: {self.filter}\n")
            f.write(f"Mode: STEALTH (Passive Monitoring)\n")
            f.write(f"{'='*60}\n")
    
    def run(self):
        """Main execution loop"""
        console.clear()
        console.print(generate_banner())
        
        self.setup_environment()
        
        console.print(f"\n[bold green]✓[/] Monitoring interface: [bold white]{self.interface}[/] [dim](stealth mode)[/]")
        console.print(f"[bold green]✓[/] BPF Filter: [bold white]{self.filter}[/]")
        console.print(f"[bold green]✓[/] Logs: [bold white]{Config.LOG_DIR}[/]")
        console.print(f"[bold blue]ℹ[/] Operating in [bold green]STEALTH MODE[/] - No packets transmitted")
        console.print(f"[bold blue]ℹ[/] Press [bold red]Ctrl+C[/bold red] to stop\n")
        
        self.running = True
        
        with Live(make_dashboard(self.detector, self.interface), 
                  refresh_per_second=Config.REFRESH_RATE, 
                  console=console) as live:
            try:
                while self.running:
                    # Sniff in small batches to allow UI updates
                    sniff(
                        iface=self.interface,
                        prn=self.detector.process_packet,
                        filter=self.filter,
                        store=0,
                        timeout=1
                    )
                    live.update(make_dashboard(self.detector, self.interface))
                    
            except KeyboardInterrupt:
                pass
            finally:
                self.shutdown()
    
    def shutdown(self):
        """Cleanup and save state"""
        console.print("\n[bold yellow]🛑 Shutting down...[/]")
        
        # Save suspicious packets
        self.detector.save_pcap()
        
        # Final statistics
        stats = self.detector.get_stats()
        total_threats = sum(stats.values())
        
        console.print(f"\n[bold white]Session Summary:[/]")
        console.print(f"  • Total Packets: {self.detector.total_packets:,}")
        console.print(f"  • Total Threats: {total_threats}")
        console.print(f"  • Logs saved to: {Config.LOG_DIR}")
        
        console.print("\n[bold green]✓ Shadow Sentinel terminated successfully[/]")
        console.print("[dim]The guardian returns to the shadows...[/dim]")


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description="Shadow Sentinel v2.0 - Stealth Network IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 shadow_sentinel.py -i eth0
  sudo python3 shadow_sentinel.py -i wlan0 -f "tcp port 80"
  sudo python3 shadow_sentinel.py --list-interfaces
        """
    )
    
    parser.add_argument('-i', '--interface', 
                        help='Network interface to monitor')
    parser.add_argument('-f', '--filter', 
                        default='ip or arp',
                        help='BPF filter expression (default: "ip or arp")')
    parser.add_argument('-l', '--list-interfaces', 
                        action='store_true',
                        help='List available network interfaces')
    parser.add_argument('--port-threshold', 
                        type=int, 
                        default=Config.PORT_SCAN_THRESHOLD,
                        help='Port scan detection threshold')
    parser.add_argument('--syn-threshold', 
                        type=int, 
                        default=Config.SYN_FLOOD_THRESHOLD,
                        help='SYN flood detection threshold')
    
    args = parser.parse_args()
    
    # List interfaces
    if args.list_interfaces:
        console.print("[bold]Available Network Interfaces:[/]")
        for iface in get_if_list():
            console.print(f"  • {iface}")
        sys.exit(0)
    
    # Privilege check
    if not check_privileges():
        console.print("[bold red]✗ ERROR:[/] Shadow Sentinel requires root/administrator privileges")
        console.print("  [dim]Stealth mode needs promiscuous access to network interface[/]")
        console.print("  Run with: [bold white]sudo python3 shadow_sentinel.py[/]")
        sys.exit(1)
    
    # Apply custom thresholds
    Config.PORT_SCAN_THRESHOLD = args.port_threshold
    Config.SYN_FLOOD_THRESHOLD = args.syn_threshold
    
    # Determine interface
    interface = args.interface or conf.iface
    
    if not interface:
        console.print("[bold red]✗ ERROR:[/] No network interface specified")
        console.print("  Use: [bold white]-i <interface>[/] or [bold white]--list-interfaces[/]")
        sys.exit(1)
    
    # Launch application
    app = SentinelApp(interface, args.filter)
    app.run()


if __name__ == "__main__":
    main()
