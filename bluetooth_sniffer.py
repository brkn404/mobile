import bluetooth
import argparse
import logging
import sys

# bluetooth_sniffer.py
#
# Description:
# ------------
# bluetooth_sniffer.py is a Python script designed to scan for nearby Bluetooth devices
# and log their details. It uses the PyBluez library to perform Bluetooth device discovery.
# The script is useful for penetration testing, security audits, and general reconnaissance
# to understand the Bluetooth environment around you. It logs detected devices, their names,
# MAC addresses, and device classes.
#
# Usage:
# ------
# The script can be executed directly from the command line. You can specify the
# duration of the Bluetooth scan using the --duration argument.
#
# Example 1: Run a Bluetooth scan for the default duration (8 seconds)
#   python bluetooth_sniffer.py
#
# Example 2: Run a Bluetooth scan for a specified duration (e.g., 10 seconds)
#   python bluetooth_sniffer.py --duration 10
#
# If you do not provide the --duration argument, the default value of 8 seconds
# will be used for the scan.
#
# Dependencies:
# -------------
# - Python 3.x: Make sure Python is installed on your system.
# - PyBluez: A Python module that enables Bluetooth communication. Install it via pip:
#     pip install pybluez
#
# Logging:
# --------
# The script logs all detected Bluetooth devices and any errors encountered
# during the scan to a file named 'bluetooth_sniffer.log'. This log file will be
# created in the same directory as the script and can be used for auditing
# and analysis.
#
# Notes:
# ------
# - The script requires Bluetooth capabilities on the machine it is run on.
# - Ensure that Bluetooth is enabled on your system and that you have the necessary
#   permissions to perform a Bluetooth scan.
# - The script is designed for use in environments where scanning for Bluetooth
#   devices is allowed. Always respect privacy and legal considerations when using
#   such tools.
#
# Author: brkn404
# Date: 2024-08-28

def setup_logging():
    """
    Set up logging to a file named 'bluetooth_sniffer.log' to record information
    about detected Bluetooth devices and any errors that occur.
    
    This function initializes logging with INFO level, meaning that all INFO,
    WARNING, ERROR, and CRITICAL level logs will be recorded. The log format
    includes the timestamp, log level, and message.
    """
    logging.basicConfig(
        filename='bluetooth_sniffer.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )
    logging.info("Logging setup complete.")

def bluetooth_scan(duration):
    """
    Perform a Bluetooth scan to discover nearby devices. Logs the details of each
    detected device.

    This function uses the bluetooth.discover_devices() method to perform the scan.
    It captures the name, address, and class of each detected Bluetooth device.
    The details are printed to the console and logged to 'bluetooth_sniffer.log'.

    Args:
        duration (int): Duration of the scan in seconds. Determines how long
                        the script will scan for Bluetooth devices.
    """
    print("[INFO] Scanning for Bluetooth devices...")
    logging.info("Starting Bluetooth scan.")

    try:
        # Perform the Bluetooth device discovery
        nearby_devices = bluetooth.discover_devices(duration=duration, lookup_names=True, lookup_class=True)
        if not nearby_devices:
            print("[INFO] No Bluetooth devices found.")
            logging.info("No Bluetooth devices found.")
        else:
            for addr, name, device_class in nearby_devices:
                device_info = f"Device: {name} - Address: {addr} - Class: {device_class}"
                print(f"[INFO] {device_info}")
                logging.info(device_info)
    except Exception as e:
        logging.error(f"Error during Bluetooth scan: {str(e)}")
        print(f"Error: Could not complete Bluetooth scan. {str(e)}")

def main():
    """
    Main function to handle argument parsing and initiate the Bluetooth scan.

    This function sets up logging, parses command-line arguments, and calls the
    bluetooth_scan() function with the specified duration. The default duration
    is 8 seconds if no duration is specified by the user.
    """
    setup_logging()

    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Scan for nearby Bluetooth devices.")
    parser.add_argument("--duration", type=int, default=8, help="Duration of the Bluetooth scan in seconds (default: 8).")

    args = parser.parse_args()

    logging.info("Bluetooth scanning script started.")
    
    # Perform the Bluetooth scan with the specified duration
    bluetooth_scan(args.duration)

if __name__ == "__main__":
    main()

