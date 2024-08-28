from scapy.all import *
import argparse
import logging
import sys

# wifi_signal_mapper.py
#
# Description:
# ------------
# wifi_signal_mapper.py is a Python script designed to log the signal strength (RSSI) of
# detected WiFi networks by capturing beacon frames using the Scapy library. The script
# can be used to map WiFi signal coverage in various locations, helping identify dead zones
# or areas with weak WiFi signals. The logged data can be analyzed to optimize network placement
# and improve overall network performance.
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the
# network interface that will be used for packet sniffing, which should be in monitor mode.
#
# Example: Run the script to map WiFi signal strength on a specified interface
#   python wifi_signal_mapper.py --interface wlan0mon
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
# The script logs detected WiFi networks and their signal strength to a file named
# 'wifi_signal_mapper.log'. This log file will be created in the same directory as the script
# and can be used for auditing and analysis.
#
# Notes:
# ------
# - The script requires root privileges to capture WiFi packets. Ensure you execute
#   the script with the necessary permissions (e.g., using sudo).
# - Ensure that the specified network interface is set to monitor mode before running
#   the script.
# - The script is designed for use in environments where monitoring network traffic
#   is allowed. Always respect privacy and legal considerations when using such tools.
#
# Author: brkn404
# Date: 2024-08-28

def setup_logging():
    """
    Set up logging to a file named 'wifi_signal_mapper.log' to record information
    about detected WiFi networks and their signal strength.
    
    This function initializes logging with INFO level, meaning that all INFO,
    WARNING, ERROR, and CRITICAL level logs will be recorded. The log format
    includes the timestamp, log level, and message.
    """
    logging.basicConfig(
        filename='wifi_signal_mapper.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )
    logging.info("Logging setup complete.")

def packet_handler(packet):
    """
    Callback function to process each captured packet.

    This function checks if the captured packet is a beacon frame. If it is,
    the function extracts the SSID, BSSID, and RSSI (signal strength) of the
    WiFi network and logs the information.

    Args:
        packet (scapy.packet.Packet): The captured packet to be processed.
    """
    if packet.haslayer(Dot11Beacon):
        ssid = packet.info.decode('utf-8', 'ignore') if packet.info else "Hidden SSID"
        bssid = packet.addr2
        rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A"
        log_entry = f"SSID: {ssid}, BSSID: {bssid}, Signal: {rssi} dBm"
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
    parser = argparse.ArgumentParser(description="Map WiFi signal strength on a specified interface.")
    parser.add_argument("--interface", required=True, help="Network interface in monitor mode to use for sniffing.")

    args = parser.parse_args()

    interface = args.interface

    logging.info(f"Starting WiFi signal strength mapping on {interface}...")

    try:
        # Start sniffing packets on the specified interface
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping packet capture.")
        logging.info("Packet capture stopped by user.")
    except Exception as e:
        logging.error(f"Error during packet sniffing: {str(e)}")
        print(f"Error: Could not complete packet sniffing. {str(e)}")

if __name__ == "__main__":
    main()
