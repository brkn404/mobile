Moto One 5G ACE

NetHunter is a mobile penetration testing platform based on Kali Linux, designed for Android devices, and it provides a range of tools and functionalities that make it suitable for tasks like WiFi sniffing, Bluetooth scanning, and wardriving.
Requirements and Setup for Running wardriving.py on NetHunter

To run the wardriving.py script on your Moto One 5G Ace using Kali NetHunter, you need to ensure the following:

    NetHunter Compatibility: Make sure your Moto One 5G Ace is fully compatible with Kali NetHunter, and that it is properly installed. NetHunter requires root access and kernel support for WiFi and other penetration testing features.

    WiFi Adapter with Monitor Mode: The internal WiFi adapter of most smartphones, including the Moto One 5G Ace, typically does not support monitor mode. However, you can use an external USB WiFi adapter that supports monitor mode. Common options include adapters with chipsets like the Atheros AR9271 or the Realtek RTL8812AU. These adapters can be connected using an OTG (On-The-Go) cable.

    GPS Capability: Your phone needs to have a GPS receiver, which most modern smartphones, including the Moto One 5G Ace, typically have. You will need to ensure that GPS is enabled and configured to provide location data to the script.

    Required Libraries: The scapy and gpsd-py3 libraries need to be installed in the NetHunter environment. Python, pip, and other dependencies should be set up correctly.

Step-by-Step Setup

Here's a step-by-step guide to setting up and running the wardriving.py script on your Moto One 5G Ace with NetHunter:

    Install and Configure NetHunter:

        Ensure NetHunter is installed and running on your Moto One 5G Ace.

        Root your device if you haven't done so already, as NetHunter requires root access.

        Update and upgrade the NetHunter installation:

        bash

    apt update && apt upgrade

Connect a Compatible WiFi Adapter:

    Use an OTG cable to connect a WiFi adapter that supports monitor mode to your Moto One 5G Ace.

    Verify that the WiFi adapter is recognized by running:

    bash

    ifconfig

    You should see the adapter listed as an interface (e.g., wlan1).

Install Required Libraries:

    Install scapy and gpsd-py3 in your NetHunter environment:

    bash

apt install python3-pip
pip3 install scapy gpsd-py3

Install GPSD if not already installed:

bash

    apt install gpsd gpsd-clients

Configure and Start GPSD:

    Start the GPSD service:

    bash

    gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock

    If using the internal GPS, you might need to configure GPSD to work with your phone’s GPS data source.

Set WiFi Adapter to Monitor Mode:

    Use airmon-ng to set the WiFi adapter into monitor mode:

    bash

    airmon-ng start wlan1

    This command will typically create a monitor mode interface (e.g., wlan1mon).

Run the Wardriving Script:

    Copy the wardriving.py script to your NetHunter environment.

    Run the script with the appropriate interface name:

    bash

        sudo python3 wardriving.py --interface wlan1mon

Troubleshooting

    WiFi Adapter Not Recognized: If the external WiFi adapter is not recognized, check OTG settings and compatibility. Some adapters require specific drivers that may need to be installed manually.

    GPS Not Providing Data: Ensure GPS is enabled on your phone. You may need to configure GPSD to properly communicate with the phone's GPS hardware.

    Permissions: Run the script and necessary commands with sudo to ensure sufficient permissions.

    Battery and Power: Running WiFi sniffing and GPS tracking can drain your phone's battery quickly. Consider connecting to a power source or using a battery pack.

