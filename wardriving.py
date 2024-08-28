from scapy.all import *
import gpsd
import argparse
import logging

# wardriving.py
#
# Description:
# ------------
# wardriving.py is a Python script designed to capture information about nearby WiFi networks
# during a wardriving session. It uses the Scapy library to sniff WiFi packets and the gpsd
# library to obtain GPS coordinates. The script logs the SSID, BSSID, signal strength (RSSI),
# security type, and location (latitude, longitude) of detected WiFi networks.
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the network
# interface that will be used for packet sniffing, which should be in monitor mode.
#
# Example: Run the script to capture WiFi data and GPS location
#   sudo python wardriving.py --interface wlan0mon
#
# Replace 'wlan0mon' with the actual monitor-mode interface name you wish to use.
#
# Dependencies:
# -------------
# - Python 3.x: Make sure Python is installed on your system.
# - Scapy: A powerful Python library for packet manipulation. Install it via pip:
#     pip install scapy
# - gpsd-py3: A Python interface to the GPSD daemon for GPS data. Install it via pip:
#     pip install gpsd-py3
# - Network Interface in Monitor Mode: A wireless network interface capable of monitor mode
#   is required to capture WiFi traffic. Use a compatible WiFi adapter and set it to
#   monitor mode using tools like `airmon-ng`.
#
# Logging:
# --------
# The script logs detected WiFi networks, including SSID, BSSID, RSSI, security type,
# and GPS coordinates, to a file named 'wardriving.log'. This log file will be created
# in the same directory as the script and can be used for auditing and analysis.
#
# Notes:
# ------
# - The script requires root privileges to capture WiFi packets. Ensure you execute
#   the script with the necessary permissions (e.g., using sudo).
# - Ensure that the specified network interface is set to monitor mode before running
#   the script.
# - The script is designed for use in environments where monitoring network traffic
#   and collecting location data is allowed. Always respect privacy and legal considerations
#   when using such tools.
#
# Author: brkn404
# Date: 2024-08-28

def setup_logging():
    """
    Set up logging to a file named 'wardriving.log' to record information
    about detected WiFi networks and their locations.
    
    This function initializes logging with INFO level, meaning that all INFO,
    WARNING, ERROR, and CRITICAL level logs will be recorded. The log format
    includes the timestamp, log level, and message.
    """
    logging.basicConfig(
        filename='wardriving.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )
    logging.info("Logging setup complete.")

def get_location():
    """
    Get the current GPS coordinates from the GPSD daemon.

    This function attempts to retrieve the current latitude and longitude
    from a GPS device using the gpsd-py3 library.

    Returns:
        tuple: A tuple containing (latitude, longitude). If GPS data is not
               available, returns (None, None).
    """
    try:
        packet = gpsd.get_current()
        return packet.lat, packet.lon
    except Exception as e:
        logging.warning(f"Could not get GPS data: {str(e)}")
        return None, None

def packet_handler(packet):
    """
    Callback function to process each captured packet.

    This function checks if the captured packet is a beacon frame, extracts the
    SSID, BSSID, RSSI, and security type of the WiFi network, and logs the information
    along with the current GPS coordinates.

    Args:
        packet (scapy.packet.Packet): The captured packet to be processed.
    """
    if packet.haslayer(Dot11Beacon):
        ssid = packet.info.decode('utf-8', 'ignore') if packet.info else "Hidden SSID"
        bssid = packet.addr2
        rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A"

        # Determine security type
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        if 'privacy' in cap:
            security = 'WPA/WPA2'
        else:
            security = 'Open'

        lat, lon = get_location()
        if lat and lon:
            log_entry = f"SSID: {ssid}, BSSID: {bssid}, Signal: {rssi} dBm, Security: {security}, Location: ({lat}, {lon})"
        else:
            log_entry = f"SSID: {ssid}, BSSID: {bssid}, Signal: {rssi} dBm, Security: {security}, Location: Not Available"
        
        print(f"[INFO] {log_entry}")
        logging.info(log_entry)

def main():
    """
    Main function to handle argument parsing and initiate the packet sniffing.

    This function sets up logging, connects to GPSD, parses command-line arguments,
    and starts the packet sniffing process using the specified network interface.
    """
    setup_logging()

    # Connect to the GPSD daemon
    try:
        gpsd.connect()
        logging.info("Connected to GPSD daemon.")
    except Exception as e:
        logging.error(f"Failed to connect to GPSD daemon: {str(e)}")
        print(f"Error: Could not connect to GPSD daemon. {str(e)}")
        sys.exit(1)

    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Wardriving script to capture WiFi data and GPS location.")
    parser.add_argument("--interface", required=True, help="Network interface in monitor mode to use for sniffing.")

    args = parser.parse_args()

    interface = args.interface

    logging.info(f"Starting wardriving on interface {interface}...")

    try:
        # Start sniffing packets on the specified interface
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping wardriving session.")
        logging.info("Wardriving session stopped by user.")
    except Exception as e:
        logging.error(f"Error during wardriving session: {str(e)}")
        print(f"Error: Could not complete wardriving session. {str(e)}")

if __name__ == "__main__":
    main()
