import subprocess

# rogue_ap.py
#
# Description:
# ------------
# rogue_ap.py is a Python script designed to create a rogue WiFi Access Point (AP) using
# the `hostapd` utility. A rogue AP mimics legitimate WiFi networks and can be used in
# penetration testing to capture network traffic, steal credentials, or test device behavior
# in response to unauthorized network connections. This script automates the setup of a
# rogue AP by specifying the network interface and the desired SSID (network name).
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the network
# interface to be used for the AP and the SSID that the rogue AP will broadcast.
#
# Example: Start a rogue AP on a specific interface with a given SSID
#   python rogue_ap.py
#
# The default interface is set to "wlan0", and the default SSID is "Free WiFi".
# These values can be modified within the script or by implementing additional argument parsing.
#
# Dependencies:
# -------------
# - Python 3.x: Ensure Python is installed on your system.
# - hostapd: A user-space daemon for access point and authentication servers. It must be installed
#   and configured on your system. hostapd is typically included in the repositories of most Linux
#   distributions. Install it using your package manager (e.g., apt-get, yum).
# - Network Interface: A wireless network interface that supports AP (Access Point) mode.
#   The interface must be capable of being configured as an AP, and it should not be in use
#   by other network services.
#
# Configuration:
# --------------
# - hostapd.conf: The script relies on a configuration file for hostapd located at
#   `/etc/hostapd/hostapd.conf`. Ensure this file exists and is correctly configured with
#   appropriate settings for the rogue AP, such as channel, security settings, and interface
#   driver. Example hostapd.conf settings include:
#       interface=wlan0
#       driver=nl80211
#       ssid=Free WiFi
#       hw_mode=g
#       channel=6
#       macaddr_acl=0
#       auth_algs=1
#       ignore_broadcast_ssid=0
#
# Notes:
# ------
# - The script requires root privileges to run hostapd and configure network interfaces.
#   Ensure you execute the script with the necessary permissions (e.g., using sudo).
# - Running a rogue AP may violate network security policies and regulations. Use this script
#   only in controlled environments where you have explicit permission to conduct penetration
#   testing and security research.
# - Customize the SSID and interface settings to match the requirements of your testing
#   scenario. You can extend the script to accept command-line arguments for greater flexibility.
#
# Author: brkn404
# Date: 2024-08-28

def start_rogue_ap(interface, ssid):
    """
    Start a rogue Access Point using hostapd with the specified interface and SSID.

    This function invokes the hostapd command-line utility to start an AP that broadcasts
    the specified SSID on the given network interface. The function uses a pre-existing
    hostapd configuration file, typically located at /etc/hostapd/hostapd.conf, which
    should be set up to use the provided interface and SSID.

    Args:
        interface (str): The network interface to use for the Access Point (e.g., "wlan0").
        ssid (str): The SSID (network name) to broadcast for the rogue AP.
    """
    print("[INFO] Starting rogue AP.")
    subprocess.run([
        "hostapd", "-B", "/etc/hostapd/hostapd.conf",
        f"-i {interface}", f"-ssid {ssid}"
    ])
    print(f"[INFO] Rogue AP '{ssid}' started on {interface}.")

# Example usage
if __name__ == "__main__":
    interface = "wlan0"  # WiFi interface in AP mode
    ssid = "Free WiFi"   # SSID of the rogue AP
    start_rogue_ap(interface, ssid)
