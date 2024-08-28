from scapy.all import *
import argparse
import logging
import sys

# rogue_ap_detection.py
#
# Description:
# ------------
# rogue_ap_detection.py is a Python script designed to detect rogue WiFi access points
# by scanning the environment for access points and comparing them against a predefined
# whitelist of known, legitimate APs. Rogue access points pose a significant security risk
# as they can be used to capture sensitive information or allow unauthorized access to a network.
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the
# network interface that will be used for packet sniffing, which should be in monitor mode.
#
# sudo airmon-ng start wlan0
#
# Example: Run the script to detect rogue access points on a specified interface
#   python rogue_ap_detection.py --interface wlan0mon
#
# Replace 'wlan0mon' with the actual monitor-mode interface name you wish to use.
#
# Dependencies:
# -------------
# - Python 3.x: Make sure Python is installed on your system.
# - Scapy: A powerful Python library for packet manipulation. Install it via pip:
#     pip install scapy
# - Network Interface in Monitor Mode: A wireless network interface capable of monitor mode
#   is required to capture WiFi traffic. Use a compatible WiFi adapter and set it to
#   monitor mode using tools like `airmon-ng`.
#
# Logging:
# --------
# The script logs detected APs and any identified rogue APs to a file named
# 'rogue_ap_detection.log'. This log file will be created in the same directory as the script
# and can be used for auditing and analysis.
#
# Notes:
# ------
# - The script requires root privileges to capture WiFi packets. Ensure you execute
#   the script with the necessary permissions (e.g., using sudo).
# - Ensure that the specified network interface is set to monitor mode before running
#   the script.
# - Customize the whitelist of known APs to match your network environment.
# - The script is designed for use in environments where monitoring network traffic
#   is allowed. Always respect privacy and legal considerations when using such tools.
#
# Author: brkn404
# Date: 2024-08-28

# Define a whitelist of known legitimate APs (MAC addresses and SSIDs)
known_aps = {
    "00:11:22:33:44:55": "Home Network",
    "66:77:88:99:AA:BB": "Office Network"
}

def setup_logging():
    """
    Set up logging to a file named 'rogue_ap_detection.log' to record information
    about detected APs and any identified rogue APs.
    
    This function initializes logging with INFO level, meaning that all INFO,
    WARNING, ERROR, and CRITICAL level logs will be recorded. The log format
    includes the timestamp, log level, and message.
    """
    logging.basicConfig(
        filename='rogue_ap_detection.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )
    logging.info("Logging setup complete.")

def packet_handler(packet):
    """
    Callback function to process each captured packet.

    This function checks if the captured packet is a beacon frame or probe response,
    indicating the presence of an access point. It then checks if the detected AP
    is in the whitelist. If not, it logs the AP as a potential rogue AP.

    Args:
        packet (scapy.packet.Packet): The captured packet to be processed.
    """
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        bssid = packet.addr2
        ssid = packet.info.decode('utf-8', 'ignore') if packet.info else "Hidden SSID"
        if bssid not in known_aps:
            log_entry = f"Rogue AP detected: SSID: {ssid}, BSSID: {bssid}"
            print(f"[ALERT] {log_entry}")
            logging.warning(log_entry)
        else:
            log_entry = f"Known AP: SSID: {ssid}, BSSID: {bssid} ({known_aps[bssid]})"
            print(f"[INFO] {log_entry}")
            logging.info(log_entry)

def main():
    """
    Main function to handle argument parsing and initiate the packet sniffing.

    This function sets up logging, parses command-line arguments, and starts
    the packet sniffing process using the specified network interface.
    """
    setup_logging()

    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Detect rogue access points on a specified interface.")
    parser.add_argument("--interface", required=True, help="Network interface in monitor mode to use for sniffing.")

    args = parser.parse_args()

    interface = args.interface

    logging.info(f"Starting rogue AP detection on {interface}...")

    try:
        # Start sniffing packets on the specified interface
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping AP scan.")
        logging.info("AP scan stopped by user.")
    except Exception as e:
        logging.error(f"Error during AP scan: {str(e)}")
        print(f"Error: Could not complete AP scan. {str(e)}")

if __name__ == "__main__":
    main()
