#!/usr/bin/env python3
"""
Shadow Sentinel v2.0 - Automated Security Testing Suite
Validates all detection mechanisms and performance metrics with programmatic assertions.
"""

import sys
import time
import threading
import subprocess
import os
import json
from datetime import datetime
from scapy.all import *

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class TestSuite:
    """Comprehensive and automated testing framework for Shadow Sentinel"""

    def __init__(self, target_ip="127.0.0.1", interface="lo"):
        self.target = target_ip
        self.interface = interface
        self.sentinel_process = None
        self.log_file = "logs/alerts.json"
        self.tests_passed = 0
        self.tests_failed = 0
        self.test_results = []

    def start_sentinel(self):
        """Start the Shadow Sentinel process in the background"""
        self.print_header("SETUP: Starting Shadow Sentinel")
        try:
            # Ensure log directory exists and alerts file is clean
            os.makedirs("logs", exist_ok=True)
            self.clear_alerts()

            cmd = [
                "sudo", sys.executable, "shadowsentinel.py",
                "-i", self.interface
            ]
            self.sentinel_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(3)  # Allow time for initialization
            if self.sentinel_process.poll() is None:
                self.print_test("Start Shadow Sentinel", "PASS", f"Process started with PID: {self.sentinel_process.pid}")
                return True
            else:
                stderr = self.sentinel_process.stderr.read()
                self.print_test("Start Shadow Sentinel", "FAIL", f"Process failed to start. Error: {stderr}")
                return False
        except Exception as e:
            self.print_test("Start Shadow Sentinel", "FAIL", str(e))
            return False

    def stop_sentinel(self):
        """Stop the Shadow Sentinel process"""
        self.print_header("TEARDOWN: Stopping Shadow Sentinel")
        if self.sentinel_process and self.sentinel_process.poll() is None:
            try:
                # Use sudo to terminate, as it was started with sudo
                subprocess.run(["sudo", "kill", str(self.sentinel_process.pid)], check=True)
                self.sentinel_process.wait(timeout=5)
                self.print_test("Stop Shadow Sentinel", "PASS", f"Process {self.sentinel_process.pid} terminated.")
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                self.print_test("Stop Shadow Sentinel", "FAIL", f"Failed to terminate process {self.sentinel_process.pid}. Error: {e}")
                # Force kill if graceful termination fails
                subprocess.run(["sudo", "kill", "-9", str(self.sentinel_process.pid)], check=False)
        else:
            self.print_test("Stop Shadow Sentinel", "WARN", "Process was not running.")
        self.clear_alerts()

    def clear_alerts(self):
        """Clear the alert log file"""
        if os.path.exists(self.log_file):
            os.remove(self.log_file)

    def verify_alert(self, threat_type: str, timeout: int = 5) -> bool:
        """Check for a specific threat type in the alert log file"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if os.path.exists(self.log_file):
                try:
                    with open(self.log_file, 'r') as f:
                        for line in f:
                            try:
                                alert = json.loads(line)
                                if alert.get("threat") == threat_type:
                                    return True
                            except json.JSONDecodeError:
                                continue # Ignore malformed lines
                except IOError:
                    pass # File may not be fully written, try again
            time.sleep(0.5)
        return False

    def print_header(self, text):
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{text:^70}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

    def print_test(self, name, status, message=""):
        if status == "PASS":
            icon = "✓"
            color = Colors.OKGREEN
            if "detection" in name.lower(): self.tests_passed += 1
        elif status == "FAIL":
            icon = "✗"
            color = Colors.FAIL
            if "detection" in name.lower(): self.tests_failed += 1
        else:
            icon = "⚠"
            color = Colors.WARNING

        print(f"{color}{icon} {name:.<50} {status}{Colors.ENDC}")
        if message:
            print(f"  {Colors.OKCYAN}→ {message}{Colors.ENDC}")

        if "detection" in name.lower():
            self.test_results.append({
                "name": name, "status": status, "message": message,
                "timestamp": datetime.now().isoformat()
            })

    def test_arp_spoofing(self):
        self.print_header("TEST 1: ARP Spoofing Detection")
        self.clear_alerts()
        try:
            send(ARP(op=2, psrc="192.168.1.100", hwsrc="aa:bb:cc:dd:ee:01"), verbose=0)
            time.sleep(0.5)
            send(ARP(op=2, psrc="192.168.1.100", hwsrc="aa:bb:cc:dd:ee:02"), verbose=0)

            if self.verify_alert("ARP Spoofing"):
                self.print_test("ARP Spoofing Detection", "PASS", "Detected MAC address change for the same IP.")
            else:
                self.print_test("ARP Spoofing Detection", "FAIL", "Failed to detect ARP cache poisoning.")
        except Exception as e:
            self.print_test("ARP Spoofing Detection", "FAIL", str(e))

    def test_port_scan(self):
        self.print_header("TEST 2: Port Scan Detection")
        self.clear_alerts()
        try:
            ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]
            for port in ports:
                send(IP(dst=self.target)/TCP(dport=port, flags="S"), verbose=0)

            if self.verify_alert("Port Scan"):
                self.print_test("Port Scan Detection", "PASS", f"Detected scan of {len(ports)} ports.")
            else:
                self.print_test("Port Scan Detection", "FAIL", "Failed to detect rapid port scan.")
        except Exception as e:
            self.print_test("Port Scan Detection", "FAIL", str(e))

    def test_syn_flood(self):
        self.print_header("TEST 3: SYN Flood Detection")
        self.clear_alerts()
        try:
            count = 60
            for i in range(count):
                send(IP(dst=self.target)/TCP(dport=80, flags="S", sport=random.randint(1024, 65535)), verbose=0)

            if self.verify_alert("SYN Flood"):
                self.print_test("SYN Flood Detection", "PASS", f"Detected {count} SYN packet flood.")
            else:
                self.print_test("SYN Flood Detection", "FAIL", "Failed to detect SYN flood.")
        except Exception as e:
            self.print_test("SYN Flood Detection", "FAIL", str(e))

    def test_suspicious_payload(self):
        self.print_header("TEST 4: Suspicious Payload Detection")
        self.clear_alerts()
        try:
            payload = "' OR '1'='1"
            pkt = IP(dst=self.target)/TCP(dport=80)/Raw(load=f"GET /search?q={payload} HTTP/1.1\r\n\r\n")
            send(pkt, verbose=0)

            if self.verify_alert("Suspicious Payload"):
                self.print_test("Suspicious Payload Detection (SQLi)", "PASS", "Detected SQL injection pattern.")
            else:
                self.print_test("Suspicious Payload Detection (SQLi)", "FAIL", "Failed to detect SQL injection.")
        except Exception as e:
            self.print_test("Suspicious Payload Detection (SQLi)", "FAIL", str(e))

    def run_all_tests(self):
        print(f"\n{Colors.BOLD}{Colors.HEADER}╔═══════════════════════════════════════════════════════════════════╗")
        print("║         SHADOW SENTINEL v2.0 - AUTOMATED TEST SUITE             ║")
        print("╚═══════════════════════════════════════════════════════════════════╝{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Target: {self.target} | Interface: {self.interface}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")

        if not self.start_sentinel():
            self.print_summary()
            return

        try:
            self.test_arp_spoofing()
            self.test_port_scan()
            self.test_syn_flood()
            self.test_suspicious_payload()
        finally:
            self.stop_sentinel()
            self.print_summary()

    def print_summary(self):
        total = self.tests_passed + self.tests_failed
        pass_rate = (self.tests_passed / total * 100) if total > 0 else 0
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}TEST SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
        
        print(f"Total Tests:     {total}")
        print(f"{Colors.OKGREEN}✓ Passed:        {self.tests_passed}{Colors.ENDC}")
        print(f"{Colors.FAIL}✗ Failed:        {self.tests_failed}{Colors.ENDC}")
        print(f"Pass Rate:       {pass_rate:.1f}%")

        status = "NEEDS IMPROVEMENT"
        status_color = Colors.FAIL
        if pass_rate >= 95:
            status = "EXCELLENT"
            status_color = Colors.OKGREEN
        elif pass_rate >= 70:
            status = "GOOD"
            status_color = Colors.WARNING
        
        print(f"\n{status_color}Overall Status: {status}{Colors.ENDC}\n")
        
        results_file = "test_results.json"
        with open(results_file, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(), "total_tests": total,
                "passed": self.tests_passed, "failed": self.tests_failed,
                "pass_rate": pass_rate, "results": self.test_results
            }, f, indent=2)
        
        print(f"{Colors.OKCYAN}✓ Results saved to: {results_file}{Colors.ENDC}\n")


def main():
    if os.geteuid() != 0:
        print(f"{Colors.FAIL}✗ ERROR: This test suite requires root privileges.{Colors.ENDC}")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="Shadow Sentinel Automated Testing Suite")
    parser.add_argument('-t', '--target', default='127.0.0.1', help='Target IP for testing')
    parser.add_argument('-i', '--interface', default='lo' if 'linux' in sys.platform else 'lo0', help='Network interface for testing')
    args = parser.parse_args()
    
    print(f"\n{Colors.WARNING}⚠  WARNING: This will generate attack-like traffic on interface '{args.interface}'{Colors.ENDC}")
    response = input(f"{Colors.BOLD}Continue? (yes/no): {Colors.ENDC}")
    
    if response.lower() != 'yes':
        print("Aborted.")
        sys.exit(0)
    
    suite = TestSuite(target_ip=args.target, interface=args.interface)
    suite.run_all_tests()


if __name__ == "__main__":
    main()
