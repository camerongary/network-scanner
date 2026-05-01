#!/usr/bin/env python3

import os
import nmap
import json
import threading
import time
import requests
from datetime import datetime
from flask import Flask, render_template, jsonify
from pathlib import Path

app = Flask(__name__)

# Configuration
NETWORK = "192.168.12.0/24"  # Network to scan
SCAN_INTERVAL = 3600  # Scan every hour (in seconds)
RESULTS_FILE = "/app/scan_data/results.json"
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')
# Global state
scan_data = {
    "devices": [],
    "last_scan": None,
    "scan_in_progress": False,
    "previous_devices": [],  # Track devices from last scan
    "new_devices": [],  # Track newly discovered devices
    "history": []  # Track historical scan data
}
scan_lock = threading.Lock()


def perform_nmap_scan():
    """Execute nmap scan and update results"""
    global scan_data
    
    # Use a lock file to prevent multiple simultaneous scans across workers
    lock_file = Path("/tmp/nmap_scan.lock")
    try:
        # Try to create lock file (non-blocking)
        if lock_file.exists():
            # Check if lock is stale (older than 2 hours)
            import time
            age = time.time() - lock_file.stat().st_mtime
            if age < 7200:  # 2 hours
                print(f"[{datetime.now()}] Scan already in progress, skipping...")
                return
            else:
                lock_file.unlink()  # Remove stale lock
        
        # Create lock file
        lock_file.touch()
        
        with scan_lock:
            scan_data["scan_in_progress"] = True
        
        print(f"[{datetime.now()}] Starting nmap scan of {NETWORK}...")
        
        # Create nmap scanner instance
        nm = nmap.PortScanner()
        
        # Run OS detection scan with service version detection
        # --max-retries=1: Reduce retries for speed
        # -T4: Aggressive timing (faster but less accurate on slow networks)
        # --max-parallelism=100: Parallel scanning
        # -O: Enable OS detection
        # -sV: Probe open ports to determine service/version
        # --script smb-os-discovery: Additional OS detection via SMB
        # --script-timeout=5s: Timeout for scripts
        nm.scan(NETWORK, arguments="-O -sV -T4 --max-retries=1 --script=smb-os-discovery --script-timeout=5s")
        
        devices = []
        
        # Process scan results
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                device_info = {
                    "ip": host,
                    "hostname": nm[host].hostname(),
                    "mac": "",
                    "vendor": "",
                    "os": "Unknown",
                    "device_type": "Unknown",
                    "ports": [],
                    "services": []
                }
                
                # Extract MAC address and vendor if available
                if "mac" in nm[host]["addresses"]:
                    device_info["mac"] = nm[host]["addresses"]["mac"]
                    # Try to get vendor from MAC OUI
                    device_info["vendor"] = get_vendor_from_mac(device_info["mac"])
                
                # Extract OS information using osmatch()
                try:
                    os_matches = nm[host].osmatch()
                    if os_matches and len(os_matches) > 0:
                        device_info["os"] = os_matches[0]['name']
                        device_info["device_type"] = classify_device_type(os_matches[0]['name'])
                except (AttributeError, KeyError, IndexError):
                    # OS detection not available for this host - try to infer from services
                    pass
                
                # If no OS detected yet, try to infer from services
                if device_info["os"] == "Unknown":
                    device_info["os"] = infer_os_from_services(
                        nm[host], 
                        vendor=device_info["vendor"],
                        hostname=device_info["hostname"]
                    )
                    if device_info["os"] != "Unknown":
                        device_info["device_type"] = classify_device_type(device_info["os"])
                
                # Extract services information
                try:
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            if nm[host][proto][port]['state'] == 'open':
                                service_info = {
                                    "port": port,
                                    "protocol": proto,
                                    "state": nm[host][proto][port]['state'],
                                    "service": nm[host][proto][port].get('name', 'unknown'),
                                    "version": nm[host][proto][port].get('version', ''),
                                    "product": nm[host][proto][port].get('product', '')
                                }
                                device_info["services"].append(service_info)
                except (AttributeError, KeyError):
                    # Service detection not available
                    pass
                
                devices.append(device_info)
        
        # Compare with previous scan to find new devices
        previous_ips = set(d['ip'] for d in scan_data.get('previous_devices', []))
        current_ips = set(d['ip'] for d in devices)
        new_device_ips = current_ips - previous_ips
        
        new_devices = [d for d in devices if d['ip'] in new_device_ips]
        
        # Build historical record
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "device_count": len(devices),
            "new_devices_count": len(new_devices),
            "device_types": {},
            "services_total": sum(len(d.get('services', [])) for d in devices)
        }
        
        # Count devices by type
        for device in devices:
            device_type = device.get('device_type', 'Unknown')
            history_entry["device_types"][device_type] = history_entry["device_types"].get(device_type, 0) + 1
        
        with scan_lock:
            scan_data["previous_devices"] = scan_data["devices"]  # Save current as previous
            scan_data["devices"] = sorted(devices, key=lambda x: x["ip"])
            scan_data["new_devices"] = new_devices
            scan_data["last_scan"] = datetime.now().isoformat()
            scan_data["scan_in_progress"] = False
            
            # Add to history (keep last 100 scans)
            scan_data["history"].append(history_entry)
            if len(scan_data["history"]) > 100:
                scan_data["history"] = scan_data["history"][-100:]
            
            print(f"[{datetime.now()}] History entries: {len(scan_data['history'])}")
        
        # Save results to file for persistence
        save_results()
        
        # Send Slack notification
        send_slack_notification(devices, new_devices)
        
        if new_devices:
            print(f"[{datetime.now()}] Scan completed. Found {len(devices)} devices ({len(new_devices)} new).")
        else:
            print(f"[{datetime.now()}] Scan completed. Found {len(devices)} devices.")
        
    except Exception as e:
        print(f"[{datetime.now()}] Error during scan: {str(e)}")
        with scan_lock:
            scan_data["scan_in_progress"] = False
    finally:
        # Remove lock file
        lock_file = Path("/tmp/nmap_scan.lock")
        try:
            if lock_file.exists():
                lock_file.unlink()
        except Exception as e:
            print(f"[{datetime.now()}] Error removing lock file: {str(e)}")


def infer_os_from_services(host_data, vendor="", hostname=""):
    """Infer OS from detected services, vendor info, and hostnames"""
    try:
        services_found = []
        ports_detected = []
        
        # Collect all services and ports
        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            for port in ports:
                service = host_data[proto][port].get('name', '').lower()
                product = host_data[proto][port].get('product', '').lower()
                if service:
                    services_found.append(service)
                    ports_detected.append(int(port))
                if product:
                    services_found.append(product)
        
        services_str = " ".join(services_found)
        vendor_lower = vendor.lower()
        hostname_lower = hostname.lower()
        
        # Check vendor first - very reliable indicator
        if "apple" in vendor_lower:
            if 554 in ports_detected or 7000 in ports_detected:
                return "macOS or iOS (RTSP + Apple vendor)"
            elif 22 in ports_detected:
                return "macOS or Linux (SSH + Apple vendor)"
            else:
                return "macOS or iOS Device (Apple vendor)"
        
        if "microsoft" in vendor_lower or "windows" in vendor_lower:
            return "Windows OS (Microsoft vendor)"
        
        # Check hostname patterns
        if any(x in hostname_lower for x in ["macbook", "mac-", "imac", "macmini"]):
            return "macOS (Hostname pattern)"
        
        if any(x in hostname_lower for x in ["iphone", "ipad", "ipod"]):
            return "iOS Device (Hostname pattern)"
        
        if any(x in hostname_lower for x in ["android", "droid"]):
            return "Android Device (Hostname pattern)"
        
        if any(x in hostname_lower for x in ["-pc", "-laptop", "-desktop", "windows"]):
            return "Windows PC (Hostname pattern)"
        
        # Service-based detection (refined)
        if 'ssh' in services_str:
            if 'openssh' in services_str:
                if any(x in services_str for x in ['ubuntu', 'debian', 'fedora', 'centos', 'redhat']):
                    return "Linux - Desktop/Server (SSH variant detected)"
                return "Linux/Unix-like OS (SSH detected)"
            elif 'libssh' in services_str:
                return "Embedded Linux (libssh detected)"
        
        if 'rdp' in services_str or 'microsoft-ds' in services_str:
            return "Windows OS (RDP/SMB detected)"
        
        if 'smb' in services_str or 'netbios' in services_str:
            return "Windows OS (SMB/NetBIOS detected)"
        
        # RTSP typically indicates Apple or IP camera
        if 'rtsp' in services_str:
            if 'http' in services_str or 'https' in services_str:
                return "Apple Device or IP Camera (RTSP + Web server)"
            return "Apple Device or IP Camera (RTSP detected)"
        
        # Bonjour/mDNS is strong Apple/Linux indicator
        if 'mdns' in services_str or 'bonjour' in services_str or 'avahi' in services_str:
            if 'ssh' in services_str:
                return "macOS or Linux with mDNS (Bonjour)"
            return "macOS or iOS (mDNS/Bonjour detected)"
        
        # Check for specific Apple services
        if any(x in services_str for x in ['afp', 'afpovertcp', 'adisk']):
            return "macOS (AFP/File Sharing detected)"
        
        # Printer detection
        if any(x in services_str for x in ['ipp', 'lpdx', 'jetdirect', 'printer', 'lpd']):
            return "Network Printer"
        
        # Camera/NVR detection
        if any(x in services_str for x in ['rtsp', 'rtmp', 'mjpeg', 'onvif', 'hikvision']):
            return "IP Camera or NVR"
        
        # NAS detection
        if any(x in services_str for x in ['nfs', 'smb', 'afp', 'rsync', 'sshfs']):
            if len(services_found) >= 2:
                return "Network Storage (NAS)"
        
        # Router/Firewall detection
        if any(x in services_str for x in ['upnp', 'miniupnp', 'ssdp']):
            return "Router or Network Device (UPnP)"
        
        # Multiple common services suggest full OS
        if len(services_found) >= 3:
            if 'ssh' in services_str and 'http' in services_str:
                return "Linux-based Server/NAS"
            return "Full OS with multiple services"
        
    except Exception as e:
        pass
    
    return "Unknown"


def classify_device_type(os_string):
    """Classify device type based on OS detection"""
    os_lower = os_string.lower()
    
    # Check for specific device types first
    if "printer" in os_lower or "network printer" in os_lower:
        return "Printer"
    elif "camera" in os_lower or "ip camera" in os_lower or "nvr" in os_lower:
        return "IP Camera"
    elif "nas" in os_lower or "network storage" in os_lower:
        return "NAS Device"
    elif "router" in os_lower or "gateway" in os_lower or "firewall" in os_lower:
        return "Router/Firewall"
    elif "switch" in os_lower or "network device" in os_lower:
        return "Network Switch"
    elif "upnp" in os_lower or "upnp" in os_lower:
        return "Network Device"
    
    # Check for Windows variants
    elif "windows" in os_lower:
        if "server" in os_lower:
            return "Windows Server"
        elif "11" in os_lower or "10" in os_lower or "8" in os_lower or "7" in os_lower:
            return "Windows PC"
        return "Windows PC"
    
    # Check for Apple products
    elif "macos" in os_lower or "mac os" in os_lower or "osx" in os_lower or "os x" in os_lower:
        if "server" in os_lower:
            return "macOS Server"
        return "macOS"
    elif "ios" in os_lower or "iphone" in os_lower or "ipad" in os_lower or "ipod" in os_lower:
        return "iOS Device"
    
    # Check for Linux/Unix
    elif "linux" in os_lower:
        if "embedded" in os_lower:
            return "Embedded Linux"
        elif "server" in os_lower or "ubuntu" in os_lower or "debian" in os_lower:
            return "Linux Server"
        return "Linux Device"
    elif "unix" in os_lower or "freebsd" in os_lower or "openbsd" in os_lower:
        return "Unix Device"
    
    # Check for mobile/embedded
    elif "android" in os_lower:
        return "Android Device"
    elif "embedded" in os_lower or "firmware" in os_lower:
        return "Embedded Device"
    
    # Check for hypervisors
    elif "hyperv" in os_lower or "hyper-v" in os_lower:
        return "Virtual Machine (Hyper-V)"
    elif "virtualbox" in os_lower:
        return "Virtual Machine (VirtualBox)"
    elif "vmware" in os_lower or "esxi" in os_lower:
        return "Virtual Machine (VMware)"
    elif "kvm" in os_lower or "qemu" in os_lower:
        return "Virtual Machine (KVM)"
    
    else:
        return "Unknown Device"


def get_vendor_from_mac(mac_address):
    """Get vendor from MAC address using OUI database"""
    # Comprehensive MAC OUI database (first 6 characters)
    oui_database = {
        "00:1A:2B": "Intel",
        "00:25:86": "Apple",
        "00:90:F5": "Netgear",
        "BC:5F:F4": "TP-Link",
        "34:29:8F": "Cisco",
        "AC:DE:48": "Apple",
        "00:16:CB": "Apple",
        "00:17:F2": "Apple",
        "00:1E:52": "Apple",
        "00:1F:5B": "Apple",
        "00:21:E9": "Apple",
        "00:22:41": "Apple",
        "00:23:32": "Apple",
        "00:24:36": "Apple",
        "00:25:00": "Apple",
        "00:26:08": "Apple",
        "00:27:10": "Apple",
        "00:3E:52": "Apple",
        "A4:D1:D2": "Apple",
        "B8:8D:12": "Apple",
        "D4:6E:0E": "Apple",
        "F8:FF:C2": "Apple",
        "CA:3C:D5": "Apple (likely MacBook/iDevice)",
        "58:55:CA": "Apple",
        "3C:15:C2": "Apple",
        "00:0B:85": "Symantec",
        "00:0C:F1": "Dell",
        "00:0D:29": "Cisco",
        "00:0E:0C": "Hewlett-Packard",
        "00:15:E9": "Hewlett-Packard",
        "00:16:EC": "Dell",
        "00:19:B9": "Extreme Networks",
        "00:1C:23": "Ricoh",
        "00:1D:6B": "Canon",
        "00:1E:6D": "Xerox",
        "00:20:4A": "Sun Microsystems",
        "00:22:B0": "Ricoh",
        "00:24:BE": "Sophos",
        "00:25:9C": "Supermicro",
        "00:3A:9C": "Supermicro",
        "00:50:F2": "Microsoft",
        "52:54:00": "KVM (Virtual Machine)",
        "08:00:27": "Oracle VirtualBox",
        "00:0F:4B": "VMware",
        "00:50:56": "VMware",
        "44:38:39": "Hyper-V",
        "54:52:A8": "QEMU",
        "AA:BB:CC": "Cisco (Emulated)",
        "00:1A:4F": "Juniper",
        "00:1B:63": "Arista",
        "00:1C:14": "Brocade",
        "00:E0:F7": "Kingston",
        "00:E0:98": "Linksys",
        "00:04:ED": "Linksys",
        "1C:7E:E5": "TP-Link",
        "88:F7:C7": "TP-Link",
        "84:16:F9": "TP-Link",
        "C4:6E:1F": "Asus",
        "00:0B:6B": "Nortel",
        "00:11:6B": "Nortel",
        "00:12:6B": "Nortel",
        "00:19:2F": "Intel",
        "00:1F:A0": "Intel",
        "00:25:B3": "Intel",
        "00:30:05": "Lexmark",
        "00:1E:68": "Lexmark",
        "00:00:0C": "Cisco",
        "00:01:42": "DEC",
        "00:01:63": "DEC",
        "EC:10:7B": "Samsung",
        "5C:BB:F6": "Samsung",
        "B0:72:BF": "LG",
        "50:46:5D": "LG",
        "BC:F5:AC": "Amazon (AWS EC2/Fire devices)",
        "06:A2:92": "Google",
        "00:24:3D": "Broadcom",
        "00:18:39": "Nvidia",
        "00:1A:8A": "NVidia",
        "00:1B:A9": "NVidia",
        "00:1D:72": "NVidia",
        "00:25:B5": "NVidia",
        "00:25:86": "Apple Inc",
        "00:26:18": "Raspberry Pi Foundation",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Foundation",
        "00:08:A1": "Apple (AirPort)",
        "00:0D:93": "Actiontec",
        "00:1A:64": "Belkin",
        "00:1C:4A": "Belkin",
        "00:1C:6F": "Netgear",
        "00:26:F3": "Netgear",
        "00:2A:10": "Netgear",
        "00:3E:98": "Netgear",
        "AC:22:0B": "Netgear",
        "C0:3E:0F": "Netgear",
        "D8:EB:97": "Netgear",
        "E0:55:3D": "Netgear",
        "F8:D1:11": "Netgear",
        "00:12:17": "Linksys",
        "00:15:2B": "Linksys",
        "00:18:39": "Linksys",
        "00:1A:2A": "Linksys",
        "00:1C:10": "Linksys",
        "00:1D:AA": "Linksys",
        "00:22:B0": "Linksys",
        "00:25:5E": "Linksys",
        "00:26:5A": "Linksys",
        "08:86:3B": "Linksys",
        "74:31:70": "Linksys",
        "90:4C:E5": "Linksys",
        "E0:91:F5": "TP-Link",
        "00:50:43": "3Com",
        "00:04:AC": "IBM",
        "00:08:C7": "Compaq",
        "00:04:38": "Sony",
        "00:04:4B": "Epson",
        "00:04:7F": "Kyocera",
        "00:04:EB": "Fujitsu",
        "00:05:02": "Okidata",
        "00:05:87": "Nortel",
        "00:06:5A": "STMicroelectronics",
        "00:07:01": "Cisco Systems",
        "00:07:EB": "Arris (formerly Motorola/Linkabit)",
        "00:08:22": "Netscape",
        "00:09:B7": "Polycom",
        "00:0A:95": "Sony Ericsson",
        "00:0C:74": "AVM",
        "00:0D:BC": "Alcatel-Lucent",
        "00:0D:FE": "Printerworks",
        "00:0E:35": "Anixter",
        "00:0E:4C": "Symbol Technologies",
        "00:0E:A3": "GlobeComm Systems",
        "00:0F:1F": "GlobespanVirata",
        "00:0F:66": "ShoreTel",
        "00:0F:A3": "Jetstream",
        "00:10:00": "Huawei",
        "00:10:4B": "3Com",
        "00:10:5A": "Avaya",
        "00:10:7A": "Plantronics",
        "00:10:A4": "Proxim Wireless",
        "00:10:B0": "Seiko Instruments",
        "00:10:DC": "Compaq Computer",
        "00:10:F6": "AST Research",
        "00:11:09": "Microsoft",
        "00:11:11": "Asante",
        "00:11:15": "Tranzeo",
        "00:11:24": "Novell",
        "00:11:3A": "Comtech EF Data",
        "00:11:43": "Proxim",
        "00:11:5B": "Proxim",
        "00:11:88": "Proxim",
        "00:11:95": "Proxim",
        "00:11:F7": "3M",
        "00:12:79": "Actpro",
        "00:12:8C": "Asante",
        "00:12:BB": "Quantum Bridge",
        "00:12:C9": "Nortel Networks",
    }
    
    if mac_address:
        prefix = mac_address[:8].upper()
        # Try exact match first
        if prefix in oui_database:
            return oui_database[prefix]
        
        # Try case-insensitive match
        for key, value in oui_database.items():
            if key.lower() == prefix.lower():
                return value
    
    return "Unknown"


def save_results():
    """Save scan results to JSON file"""
    try:
        # Ensure directory exists
        Path(RESULTS_FILE).parent.mkdir(parents=True, exist_ok=True)
        with scan_lock:
            with open(RESULTS_FILE, 'w') as f:
                json.dump(scan_data, f, indent=2)
    except Exception as e:
        print(f"Error saving results: {str(e)}")


def load_results():
    """Load previous scan results if available"""
    global scan_data
    try:
        if Path(RESULTS_FILE).exists():
            with open(RESULTS_FILE, 'r') as f:
                loaded_data = json.load(f)
                # Ensure all required fields exist
                scan_data["devices"] = loaded_data.get("devices", [])
                scan_data["previous_devices"] = loaded_data.get("previous_devices", [])
                scan_data["new_devices"] = loaded_data.get("new_devices", [])
                scan_data["last_scan"] = loaded_data.get("last_scan", None)
                scan_data["scan_in_progress"] = False
                scan_data["history"] = loaded_data.get("history", [])
                print(f"Loaded previous scan results from {RESULTS_FILE}")
                print(f"History entries: {len(scan_data['history'])}")
    except Exception as e:
        print(f"Error loading results: {str(e)}")


def send_slack_notification(devices, new_devices=None):
    """Send scan results to Slack"""
    try:
        if not SLACK_WEBHOOK:
            return
        
        if new_devices is None:
            new_devices = []
        
        # Group devices by type
        devices_by_type = {}
        for device in devices:
            device_type = device.get('device_type', 'Unknown')
            if device_type not in devices_by_type:
                devices_by_type[device_type] = []
            devices_by_type[device_type].append(device)
        
        # Build message blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔍 Network Scan Complete",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Scan Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n*Network:* {NETWORK}\n*Total Devices:* {len(devices)}"
                }
            },
            {
                "type": "divider"
            }
        ]
        
        # Add new devices section if any
        if new_devices:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"✨ *New Devices Found:* {len(new_devices)}"
                }
            })
            
            for device in new_devices:
                services = device.get('services', [])
                device_text = f"🆕 *{device['ip']}* - {device['device_type']}\n  Hostname: {device.get('hostname', 'N/A')}"
                
                if services:
                    services_list = ", ".join([f"{svc['port']}/{svc['protocol']}" for svc in services])
                    device_text += f"\n  Services: {services_list}"
                
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": device_text
                    }
                })
            
            blocks.append({
                "type": "divider"
            })
        
        # Add device summary by type
        for device_type in sorted(devices_by_type.keys()):
            count = len(devices_by_type[device_type])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{device_type}*: {count} device{'s' if count != 1 else ''}"
                }
            })
        
        blocks.append({
            "type": "divider"
        })
        
        # Add top devices
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Recent Devices:*"
            }
        })
        
        for device in devices[:10]:  # Show top 10 devices
            services = device.get('services', [])
            services_text = f"{len(services)} service{'s' if len(services) != 1 else ''}"
            device_text = f"• *{device['ip']}* - {device['device_type']}\n  OS: {device['os']}\n  Hostname: {device.get('hostname', 'N/A')}"
            
            # Add services list
            if services:
                services_list = ", ".join([f"{svc['port']}/{svc['protocol']}" for svc in services])
                device_text += f"\n  Services: {services_list}"
                
                # Add service details if available
                service_details = []
                for svc in services:
                    detail = f"{svc['port']}/{svc['protocol']} ({svc.get('service', 'unknown')})"
                    if svc.get('version'):
                        detail += f" - {svc['version']}"
                    elif svc.get('product'):
                        detail += f" - {svc['product']}"
                    service_details.append(detail)
                
                if service_details:
                    device_text += "\n  Details:\n    " + "\n    ".join(service_details[:5])  # Limit to 5 services
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": device_text
                }
            })
        
        # Send to Slack
        payload = {"blocks": blocks}
        response = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        
        if response.status_code == 200:
            print(f"[{datetime.now()}] Slack notification sent successfully")
        else:
            print(f"[{datetime.now()}] Failed to send Slack notification: {response.status_code}")
    
    except Exception as e:
        print(f"[{datetime.now()}] Error sending Slack notification: {str(e)}")



def periodic_scan_thread():
    """Background thread that runs periodic scans"""
    # Run initial scan immediately
    perform_nmap_scan()
    
    # Then run periodic scans
    while True:
        time.sleep(SCAN_INTERVAL)
        perform_nmap_scan()


@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')


@app.route('/api/devices')
def get_devices():
    """API endpoint to get current scan results"""
    with scan_lock:
        return jsonify(scan_data)


@app.route('/api/scan-now', methods=['POST'])
def scan_now():
    """API endpoint to trigger a scan immediately"""
    if scan_data["scan_in_progress"]:
        return jsonify({"status": "already_running"}), 409
    
    # Run scan in background thread
    thread = threading.Thread(target=perform_nmap_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "scan_started"})


@app.route('/api/history')
def get_history():
    """API endpoint to get historical scan data"""
    with scan_lock:
        return jsonify({
            "history": scan_data.get("history", []),
            "total_scans": len(scan_data.get("history", []))
        })


def startup_scanner():
    """Initialize the scanner on app startup"""
    try:
        # Load previous results
        load_results()
        
        # Start background scanning thread
        scan_thread = threading.Thread(target=periodic_scan_thread)
        scan_thread.daemon = True
        scan_thread.start()
        
        print(f"[{datetime.now()}] Network Scanner initialized for {NETWORK}")
    except Exception as e:
        print(f"[{datetime.now()}] Error initializing scanner: {str(e)}")


# Initialize on first request
@app.before_request
def init_scanner():
    """Run scanner initialization on first request"""
    if not hasattr(app, '_scanner_initialized'):
        app._scanner_initialized = True
        startup_scanner()


if __name__ == '__main__':
    # Development mode - load and start scanner
    startup_scanner()
    
    # Start Flask development server
    print(f"Starting Network Scanner for {NETWORK}")
    app.run(host='0.0.0.0', port=5000, debug=False)
