from scapy.all import *
import argparse
import logging
import sys

# wifi_sniffer.py
#
# Description:
# ------------
# wifi_sniffer.py is a Python script designed to capture and log WiFi network traffic,
# including beacon frames, probe requests, and data packets. The script uses the Scapy
# library to sniff packets on a specified wireless interface. It is useful for analyzing
# network traffic, identifying devices, and understanding the nature of wireless
# communication in the area.
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the
# network interface that will be used for packet sniffing, which should be in monitor mode.
#
# sudo airmon-ng start wlan0
#
# Example: Run the script to sniff WiFi traffic on a specified interface
#   python wifi_sniffer.py --interface wlan0mon
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
# The script logs detected packets and any errors encountered during the packet sniffing
# process to a file named 'wifi_sniffer.log'. This log file will be created in the same
# directory as the script and can be used for auditing and analysis.
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
    Set up logging to a file named 'wifi_sniffer.log' to record information
    about detected packets and any errors that occur.
    
    This function initializes logging with INFO level, meaning that all INFO,
    WARNING, ERROR, and CRITICAL level logs will be recorded. The log format
    includes the timestamp, log level, and message.
    """
    logging.basicConfig(
        filename='wifi_sniffer.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )
    logging.info("Logging setup complete.")

def packet_handler(packet):
    """
    Callback function to process each captured packet.

    This function checks if the captured packet is a beacon frame, probe request,
    or data frame. It extracts relevant information such as SSID, MAC addresses,
    and packet type, and logs the information.

    Args:
        packet (scapy.packet.Packet): The captured packet to be processed.
    """
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:  # Beacon frame
            ssid = packet.info.decode('utf-8', 'ignore')
            bssid = packet.addr2
            log_entry = f"Beacon frame: SSID: {ssid}, BSSID: {bssid}"
            print(f"[INFO] {log_entry}")
            logging.info(log_entry)
        elif packet.haslayer(Dot11ProbeReq):
            ssid = packet.info.decode('utf-8', 'ignore')
            mac = packet.addr2
            log_entry = f"Probe Request: SSID: {ssid}, MAC: {mac}"
            print(f"[INFO] {log_entry}")
            logging.info(log_entry)
        elif packet.type == 2:  # Data frame
            source = packet.addr2
            destination = packet.addr1
            log_entry = f"Data frame: From {source} to {destination}"
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
    parser = argparse.ArgumentParser(description="Sniff WiFi network traffic on a specified interface.")
    parser.add_argument("--interface", required=True, help="Network interface in monitor mode to use for sniffing.")

    args = parser.parse_args()

    interface = args.interface

    logging.info(f"Starting WiFi sniffer on {interface}...")

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
