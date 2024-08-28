from scapy.all import *
import os

# wifi_probe_sniffer.py
#
# Description:
# ------------
# wifi_probe_sniffer.py is a Python script designed to sniff WiFi probe request packets
# using the `scapy` library. Probe requests are sent by WiFi-enabled devices to search
# for known WiFi networks (SSIDs) they have previously connected to. This script captures
# these probe requests, extracts the SSID and MAC address of the device sending the request,
# and logs the information to a file named 'detected_ssids.txt'. It can be used in penetration
# testing, security auditing, or general WiFi environment reconnaissance to understand
# the behavior of nearby WiFi-enabled devices.
#
# Usage:
# ------
# The script can be executed directly from the command line. Before running the script,
# ensure that the wireless network interface is in monitor mode. The script will set the
# specified interface to monitor mode if it's not already configured. The interface to be
# used should be specified in the script.
#
# Example: Run the script to sniff WiFi probe requests
#   python wifi_probe_sniffer.py
#
# Ensure that the specified network interface is in monitor mode (e.g., wlan0mon).
#
# Dependencies:
# -------------
# - Python 3.x: Ensure Python is installed on your system.
# - scapy: A powerful Python library for packet manipulation. Install it via pip:
#     pip install scapy
# - Network Interface in Monitor Mode: A wireless network interface capable of monitor mode
#   is required to capture probe requests. Use a compatible WiFi adapter and set it to
#   monitor mode using the script or manually with tools like `airmon-ng`.
#
# Configuration:
# --------------
# - Monitor Mode: Before running the script, set your wireless network interface to monitor
#   mode. This can typically be done using the following commands:
#     sudo ip link set wlan0 down
#     sudo iw dev wlan0 set type monitor
#     sudo ip link set wlan0 up
#   Replace 'wlan0' with your actual interface name.
#
# Notes:
# ------
# - Sniffing WiFi probe requests may raise privacy concerns and may be subject to legal
#   restrictions. Use this script only in controlled environments where you have explicit
#   permission to conduct penetration testing and security research.
# - The script requires root privileges to set the interface to monitor mode and to sniff
#   packets. Ensure you execute the script with the necessary permissions (e.g., using sudo).
# - Customize the interface name to match the actual monitor mode interface used in your
#   testing scenario.
#
# Author: brkn404
# Date: 2024-08-28

def set_monitor_mode(interface):
    """
    Set the specified network interface to monitor mode.

    This function uses system commands to configure the wireless network interface
    to monitor mode, allowing it to capture all WiFi traffic, including probe requests.

    Args:
        interface (str): The network interface to set to monitor mode.
    """
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw dev {interface} set type monitor")
    os.system(f"sudo ip link set {interface} up")
    print(f"[INFO] {interface} set to monitor mode.")

def packet_handler(packet):
    """
    Callback function to process each captured packet.

    This function checks if the captured packet is a WiFi probe request. If it is, the
    function extracts the SSID and MAC address of the device sending the request. It
    logs unique SSIDs and their corresponding MAC addresses to a file.

    Args:
        packet (scapy.packet.Packet): The captured packet to be processed.
    """
    if packet.haslayer(Dot11ProbeReq):
        ssid = packet.info.decode('utf-8', 'ignore')
        mac = packet.addr2
        if ssid and ssid not in ssid_list:
            ssid_list.add(ssid)
            print(f"[INFO] Detected SSID: {ssid} from {mac}")
            with open("detected_ssids.txt", "a") as file:
                file.write(f"SSID: {ssid}, MAC: {mac}\n")

# Main function
if __name__ == "__main__":
    interface = "wlan0mon"  # Replace with your monitor-mode interface name

    # Set the WiFi adapter to monitor mode
    set_monitor_mode(interface)

    # Create a set to store detected SSIDs
    ssid_list = set()

    print(f"[INFO] Starting packet capture on {interface}...")

    try:
        # Start sniffing
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping packet capture.")
        print("[INFO] SSIDs saved to detected_ssids.txt")
