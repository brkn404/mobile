import requests
import os
import sys
import argparse
import logging

# apk_scan.py
#
# Description:
# ------------
# apk_scan.py is a Python script designed to perform security scans on Android APK files
# using the Mobile Security Framework (MobSF). This script automates the process of uploading
# an APK file to a running MobSF server, initiating a scan, and retrieving the scan report.
# It is useful for penetration testers, security analysts, and developers who want to
# evaluate the security of Android applications.
#
# Usage:
# ------
# The script can be executed directly from the command line. You must specify the path
# to the APK file, the MobSF API key, and the MobSF server URL as command-line arguments.
#
# Example 1: Scan an APK with specific MobSF API key and server URL
#   python apk_scan.py /path/to/your_app.apk --api_key your_mobsf_api_key --server_url http://localhost:8000
#
# Example 2: Using actual values for testing
#   python apk_scan.py /path/to/your_app.apk --api_key 1234567890abcdef --server_url http://localhost:8000
#
# If any required arguments are missing, the script will display usage instructions and exit.
#
# Dependencies:
# -------------
# - Python 3.x: Ensure Python is installed on your system.
# - Requests library: A Python HTTP library for sending requests. Install it via pip:
#     pip install requests
# - MobSF: Mobile Security Framework must be installed and running. It can be installed from:
#     https://github.com/MobSF/Mobile-Security-Framework-MobSF
#
# Logging:
# --------
# The script logs all activities, including successful connections, scan results, and any
# errors encountered during execution, to a file named 'apk_scan.log'. This log file
# is created in the same directory as the script and is useful for audit and analysis.
#
# Notes:
# ------
# - The script requires a running instance of MobSF with an accessible API endpoint.
# - Ensure that the MobSF API key provided has the necessary permissions to perform scans.
# - The script is designed to work with the MobSF API version that includes endpoints for
#   uploading and scanning APK files.
# - This script should be run in environments where you have the legal right to scan the
#   APK files, and it adheres to applicable data privacy and security regulations.
#
# Author: brkn404
# Date: 2024-08-28

def setup_logging():
    """
    Set up logging to a file named 'apk_scan.log' to record information about
    script execution and any errors that occur.
    
    This function initializes logging with INFO level, which means that all INFO,
    WARNING, ERROR, and CRITICAL level logs will be recorded. The log format
    includes the timestamp, log level, and message.
    """
    logging.basicConfig(
        filename='apk_scan.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )
    logging.info("Logging setup complete.")

def validate_apk_path(apk_path):
    """
    Check if the provided APK file path exists. If not, log an error and exit.

    Args:
        apk_path (str): The path to the APK file to be scanned.

    This function ensures that the file specified by apk_path exists. If the file
    does not exist, the function logs an error message and exits the script with a
    status code of 1.
    """
    if not os.path.isfile(apk_path):
        logging.error(f"APK file does not exist: {apk_path}")
        print(f"Error: APK file does not exist at {apk_path}")
        sys.exit(1)

def validate_server_connection(server_url, api_key):
    """
    Check if the MobSF server is reachable by making a request to its health check endpoint.

    Args:
        server_url (str): The URL of the MobSF server.
        api_key (str): The API key for MobSF.

    This function sends a GET request to the MobSF server's health check endpoint
    to verify that the server is running and accessible. If the server responds with
    a status code other than 200, or if any network-related exception occurs, the
    function logs the error and exits the script with a status code of 1.
    """
    try:
        headers = {'Authorization': api_key}
        response = requests.get(f"{server_url}/api/v1/health_check", headers=headers)
        if response.status_code != 200:
            logging.error(f"Server health check failed: {response.text}")
            print(f"Error: Unable to connect to MobSF server at {server_url}")
            sys.exit(1)
        logging.info("Connected to MobSF server successfully.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Exception occurred: {str(e)}")
        print(f"Error: Unable to connect to MobSF server. Exception: {str(e)}")
        sys.exit(1)

def scan_apk(apk_path, api_key, server_url):
    """
    Perform an APK scan using MobSF by uploading the APK file to the server.

    Args:
        apk_path (str): The path to the APK file to be scanned.
        api_key (str): The API key for MobSF.
        server_url (str): The URL of the MobSF server.

    This function uploads the specified APK file to the MobSF server using a POST request
    and initiates a security scan. It prints and logs the scan report URL and scan status.
    If the request fails, an error message is logged and printed.
    """
    # Validate input file and server connectivity
    validate_apk_path(apk_path)
    validate_server_connection(server_url, api_key)
    
    # Prepare the file and headers for the request
    files = {'file': open(apk_path, 'rb')}
    headers = {'Authorization': api_key}
    
    try:
        # Make the request to the MobSF API to upload and scan the APK
        response = requests.post(f"{server_url}/api/v1/upload", files=files, headers=headers)
        response.raise_for_status()
        scan_data = response.json()
        
        # Output the scan results
        print(f"Scan Report URL: {scan_data['report_url']}")
        print(f"Scan Status: {scan_data['status']}")
        logging.info(f"Scan Report URL: {scan_data['report_url']}")
        logging.info(f"Scan Status: {scan_data['status']}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Exception occurred during APK scan: {str(e)}")
        print(f"Error: Exception occurred during APK scan: {str(e)}")

def main():
    """
    Main function to handle argument parsing and initiate the APK scan.

    This function sets up logging, parses command-line arguments, and calls the
    scan_apk() function with the specified arguments. It requires three arguments:
    the path to the APK file, the MobSF API key, and the MobSF server URL.
    """
    # Set up logging
    setup_logging()
    
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Scan an APK using MobSF.")
    parser.add_argument("apk_path", help="Path to the APK file to scan.")
    parser.add_argument("--api_key", required=True, help="MobSF API key.")
    parser.add_argument("--server_url", required=True, help="MobSF server URL, e.g., http://localhost:8000")

    args = parser.parse_args()

    logging.info("Starting APK scan.")
    
    # Perform the APK scan with provided arguments
    scan_apk(args.apk_path, args.api_key, args.server_url)

if __name__ == "__main__":
    main()
