# 💀 SHADOWSENTINEL v1.0

**The Guardian That Operates in the Shadows**

```
   _____ _               _                _____            _   _            _ 
  / ____| |             | |              / ____|          | | (_)          | |
 | (___ | |__   __ _  __| | _____      _| (___   ___ _ __ | |_ _ _ __   ___| |
  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  ____) | | | | (_| | (_| | (_) \ V  V / ____) |  __/ | | | |_| | | | |  __/ |
 |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_____/ \___|_| |_|\__|_|_| |_|\___|_|
                                                                                   
```

**Stealth Network Intrusion Detection System (IDS) with Advanced Deep Packet Inspection (DPI)**

Shadow Sentinel operates as an invisible guardian, leveraging Deep Packet Inspection to detect a wide range of network threats without revealing its presence. Designed for high performance and stealth, it ensures your network is monitored for ARP spoofing, port scans, SYN floods, and other malicious activities, all while maintaining a zero-footprint operation.

Developed by: **Kleber Tiko** aka: **Nightwolf**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-A+-brightgreen.svg)](#security)
[![Stealth](https://img.shields.io/badge/Mode-Stealth-black.svg)](#the-stealth-advantage)

---

## 🎭 The Stealth Advantage

**Traditional IDS Problems:**
- ❌ Active probing can be detected by attackers.
- ❌ Generates response packets that reveal its presence.
- ❌ Can be fingerprinted and bypassed.
- ❌ Becomes a target itself.

**Shadow Sentinel Solution:**
- ✅ **Pure Passive Monitoring**: Zero network footprint.
- ✅ **Invisible Operation**: No packets sent, only receives.
- ✅ **Undetectable**: Attackers don't know they're being watched.
- ✅ **Stealth Mode**: Operates silently in the background.

---

## 🎯 Core Detection Capabilities

| Threat Vector | Detection Method |
|---------------|------------------|
| **ARP Spoofing** | MAC tracking |
| **Port Scanning** | Temporal analysis |
| **SYN Flood** | Rate-based (50/5s) |
| **ICMP Flood** | Packet counting |
| **DNS Tunneling** | Query frequency |
| **Malicious Payloads**| Regex-based pattern matching (SQLi, XSS, etc.) |

### Advanced Features

- ✅ **Thread-Safe Architecture**: Concurrent detection without race conditions.
- ✅ **Memory Management**: Bounded structures prevent exhaustion attacks.
- ✅ **Forensic PCAP**: Automatic capture of suspicious packets.
- ✅ **Structured JSON Logging**: For easy SIEM integration.
- ✅ **Real-time Dashboard**: A beautiful and informative terminal UI.
- ✅ **Configurable Thresholds**: Adapt to your network's profile.
- ✅ **High Performance**: Capable of processing over 45,000 packets/second.

---

## 🚀 Quick Start

### Prerequisites

- **Operating System:** Linux (Ubuntu 20.04+, Kali 2023+, Debian 11+)
- **Python:** 3.8 or higher
- **Privileges:** `root` or `sudo` (required for promiscuous mode).
- **Dependencies:** `libpcap`, `python3-pip`

### Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-repo/shadow-sentinel.git
    cd shadow-sentinel
    ```

2.  **System Dependencies (for Debian/Ubuntu)**
    ```bash
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv libpcap-dev
    ```

3.  **Set up a Virtual Environment**
    ```bash
    # Create a virtual environment
    python3 -m venv .venv

    # Activate it
    source .venv/bin/activate

    # To deactivate later, simply run:
    # deactivate
    ```

4.  **Install Python Packages**
    ```bash
    # Install dependencies from requirements.txt
    pip install -r requirements.txt
    ```

5.  **Verify Installation**
    ```bash
    # The script needs root privileges to access the network interface
    sudo python3 shadow_sentinel.py --list-interfaces
    ```

---

## 🎯 Usage

### Basic Monitoring

```bash
# Start Shadow Sentinel on the primary interface
sudo python3 shadow_sentinel.py -i eth0

# Monitor with a custom BPF filter (e.g., only TCP traffic)
sudo python3 shadow_sentinel.py -i eth0 -f "tcp"

# Monitor only HTTP/HTTPS traffic
sudo python3 shadow_sentinel.py -i eth0 -f "tcp port 80 or tcp port 443"
```

### Adjusting Sensitivity

```bash
# Less sensitive (higher thresholds to reduce false positives)
sudo python3 shadow_sentinel.py -i eth0 --port-threshold 25 --syn-threshold 100

# More sensitive (lower thresholds)
sudo python3 shadow_sentinel.py -i eth0 --port-threshold 5 --syn-threshold 20
```

---

## 🧪 Automated Testing

This project includes a fully automated test suite that programmatically validates all detection mechanisms.

### Running the Tests

```bash
# Navigate to the project directory
cd ShadowSentinel

# Run the test suite
# The suite requires root privileges to send packets and run the sentinel
sudo python3 test_suite.py -i <your-interface>
```

The test suite will:
1.  Start an instance of Shadow Sentinel in the background.
2.  Execute a series of attack simulations (e.g., ARP spoofing, port scans).
3.  **Programmatically verify** that the correct alerts were logged in `logs/alerts.json`.
4.  Shut down the sentinel and print a detailed report.

---

## 🛡️ Security Analysis Summary

A thorough security analysis of a previous version of this tool revealed several critical vulnerabilities. **Version 2.0 has been completely refactored to address these issues.**

| Vulnerability | Status in v2.0 | Mitigation |
|---|---|---|
| **Memory Exhaustion DoS** | ✅ **Fixed** | Implemented bounded data structures (`collections.deque` with `maxlen`) and periodic cleanup. |
| **Race Conditions** | ✅ **Fixed** | All access to shared data is protected by a global `threading.Lock`. |
| **Privilege Bypass** | ✅ **Fixed** | The application now strictly enforces `root` privileges and will exit if they are not present. |
| **Static Threshold Bypass**| ✅ **Fixed**| Detection now uses temporal analysis (sliding windows) instead of simple counters. |
| **Insufficient Logging** | ✅ **Fixed** | All alerts are logged to a persistent JSON file (`logs/alerts.json`) for forensic analysis. |

For more details, please refer to the `SECURITY_ANALYSIS.md` file (in Portuguese).

---

## 📊 Performance

Benchmark results on an Intel i7-10700K @ 3.8GHz:

| Metric | Value |
|---|---|
| **Throughput** | ~45,000 packets/second |
| **CPU Usage** | 12-18% (single core) |
| **Memory Usage**| 80-150 MB (steady state) |
| **Network Footprint**| **0 packets sent (True Stealth)** |

---

## 🤝 Contributing

Contributions are welcome! Please maintain the core stealth principles:
-   Do not add any features that send packets on the monitored interface.
-   Keep the network footprint at zero.
-   Optimize for passive detection and low resource usage.

---

## 📄 License

This project is licensed under the GNU General Public License v3.0. See the `LICENSE` file for details.
