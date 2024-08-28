import subprocess
import re
import time

# rogue_tower.py
#
# Description:
# ------------
# rogue_tower.py is a Python script designed to detect potential IMSI catchers, also known
# as rogue cell towers, by monitoring cellular network parameters on a connected Android
# device. The script uses Android Debug Bridge (adb) to query the device's current network
# information, such as Mobile Country Code (MCC), Mobile Network Code (MNC), Cell ID (CID),
# and Location Area Code (LAC). If any anomalies are detected in these parameters (e.g.,
# unknown LAC/CID combinations), the script raises an alert indicating the possible presence
# of an IMSI catcher. This tool is useful for penetration testers, security researchers, and
# individuals concerned about mobile security.
#
# Usage:
# ------
# The script can be executed directly from the command line. It continuously monitors
# the network information and checks for anomalies every 60 seconds.
#
# Example: Run the script to monitor for potential IMSI catchers
#   python rogue_tower.py
#
# The script outputs alerts and network information if a possible IMSI catcher is detected.
# Otherwise, it reports that the network appears normal.
#
# Dependencies:
# -------------
# - Python 3.x: Ensure Python is installed on your system.
# - adb: Android Debug Bridge must be installed and configured on your system.
#   You can download adb from the official Android SDK platform tools:
#   https://developer.android.com/studio/releases/platform-tools
# - Android device: A rooted Android device with USB debugging enabled, connected to the
#   computer running the script.
#
# Logging:
# --------
# This version of the script does not include logging. To enhance the script, consider adding
# logging functionality to record network status and alerts to a log file for auditing and analysis.
#
# Notes:
# ------
# - The script requires a rooted Android device with adb access and USB debugging enabled.
# - The detection method used in this script is simplified and relies on hardcoded MCC/MNC
#   values. For more robust detection, integrate a database of known good values for LAC/CID
#   combinations.
# - The script continuously runs in a loop, checking for IMSI catchers every 60 seconds. Adjust
#   the sleep interval as needed based on your monitoring requirements.
# - Ensure you have the necessary permissions to monitor network parameters on the Android
#   device and comply with legal regulations regarding cellular network monitoring.
#
# Author: brkn404
# Date: 2024-08-28

def detect_imsi_catcher():
    """
    Detect potential IMSI catchers by checking the current cellular network information.

    This function uses adb to query the connected Android device for network information
    such as MCC, MNC, CID, and LAC. It checks for anomalies in these values to identify
    potential IMSI catchers. If an anomaly is detected, the function prints an alert
    message and the network information.

    The detection logic is simplified and checks for specific MCC/MNC combinations.
    More robust detection would involve a comprehensive database of known good values.
    """
    result = subprocess.run(['adb', 'shell', 'dumpsys', 'telephony.registry'], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    
    # Extract current network information
    network_info = {}
    for line in output.splitlines():
        if "mcc" in line or "mnc" in line or "cid" in line or "lac" in line:
            key, value = line.strip().split("=")
            network_info[key] = value

    # Check for anomalies in network info (e.g., unknown LAC/CID combinations)
    # This is a simplified version; real detection would use a database of known good values
    if network_info.get("mcc") != "310" or network_info.get("mnc") not in ["260", "410"]:
        print("[ALERT] Possible IMSI Catcher Detected!")
        print(f"Network info: {network_info}")
    else:
        print("[INFO] Network appears normal.")

if __name__ == "__main__":
    # Continuously monitor for IMSI catchers
    while True:
        detect_imsi_catcher()
        time.sleep(60)  # Check every minute
