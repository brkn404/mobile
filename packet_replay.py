from scapy.all import *
import argparse
import logging
import sys

# packet_replay.py
#
# Description:
# ------------
# packet_replay.py is a Python script designed to capture, modify, and replay network packets
# using the Scapy library. This type of testing is useful for evaluating the resilience of
# network protocols and systems against replay attacks. The script captures a specified
# number of packets from a network, allows for modifications, and replays them back onto
# the network. It is useful for penetration testers and security researchers.
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the
# network interface that will be used for packet capture and replay, which should be
# in monitor mode, and the number of packets to capture and replay.
#
# Example: Run the script to capture and replay 10 packets on a specified interface
#   python packet_replay.py --interface wlan0mon --count 10
#
# Replace 'wlan0mon' with the actual monitor-mode interface name you wish to use.
#
# Dependencies:
# -------------
# - Python 3.x: Make sure Python is installed on your system.
# - Scapy: A powerful Python library for packet manipulation. Install it via pip:
#     pip install scapy
# - Network Interface in Monitor Mode: A wireless network interface capable of monitor mode
#   is required to capture and inject packets. Use a compatible WiFi adapter and set it to
#   monitor mode using tools like `airmon-ng`.
#
# Logging:
# --------
# The script logs captured packets and replay activities to a file named 'packet_replay.log'.
# This log file will be created in the same directory as the script and can be used for
# auditing and analysis.
#
# Notes:
# ------
# - The script requires root privileges to capture and replay packets. Ensure you execute
#   the script with the necessary permissions (e.g., using sudo).
# - Ensure that the specified network interface is set to monitor mode before running
#   the script.
# - The script is designed for use in environments where packet injection and replay
#   are allowed. Always respect privacy and legal considerations when using such tools.
#
# Author: brkn404
# Date: 2024-08-28

def setup_logging():
    """
    Set up logging to a file named 'packet_replay.log' to record information
    about captured and replayed packets and any errors that occur.
    
    This function initializes logging with INFO level, meaning that all INFO,
    WARNING, ERROR, and CRITICAL level logs will be recorded. The log format
    includes the timestamp, log level, and message.
    """
    logging.basicConfig(
        filename='packet_replay.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )
    logging.info("Logging setup complete.")

def packet_handler(packet, interface):
    """
    Callback function to process each captured packet.

    This function logs the captured packet, allows for modification, and replays
    the modified packet on the network.

    Args:
        packet (scapy.packet.Packet): The captured packet to be processed.
        interface (str): The network interface to use for replaying the packet.
    """
    if packet.haslayer(TCP):
        logging.info(f"Captured packet: {packet.summary()}")
        print(f"[INFO] Captured packet: {packet.summary()}")

        # Example modification: change the destination port to 8080
        packet[TCP].dport = 8080
        del packet[IP].chksum  # Remove checksum to allow recalculation
        del packet[TCP].chksum # Remove checksum to allow recalculation

        logging.info(f"Replaying modified packet: {packet.summary()}")
        print(f"[INFO] Replaying modified packet: {packet.summary()}")

        sendp(packet, iface=interface, verbose=False)  # Replay the modified packet

def main():
    """
    Main function to handle argument parsing and initiate packet capture and replay.

    This function sets up logging, parses command-line arguments, and starts
    the packet capture and replay process using the specified network interface.
    """
    setup_logging()

    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Capture and replay network packets on a specified interface.")
    parser.add_argument("--interface", required=True, help="Network interface in monitor mode to use for capturing and replaying packets.")
    parser.add_argument("--count", type=int, default=10, help="Number of packets to capture and replay (default: 10).")

    args = parser.parse_args()

    interface = args.interface
    packet_count = args.count

    logging.info(f"Starting packet capture on {interface} for replay...")

    try:
        # Start sniffing packets on the specified interface and replaying them
        sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, interface), count=packet_count, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping packet capture.")
        logging.info("Packet capture stopped by user.")
    except Exception as e:
        logging.error(f"Error during packet capture and replay: {str(e)}")
        print(f"Error: Could not complete packet capture and replay. {str(e)}")

if __name__ == "__main__":
    main()
