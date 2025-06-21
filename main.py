#!/usr/bin/env python3

import argparse
import socket
import struct
import fcntl
import logging
import subprocess
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the script.
    """
    parser = argparse.ArgumentParser(description="Discovers IPv6 link-local addresses on the network and pings them.")
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="Network interface to use for scanning.")
    parser.add_argument("-t", "--timeout", dest="timeout", type=int, default=1, help="Timeout for ping requests in seconds (default: 1).")
    parser.add_argument("-c", "--count", dest="count", type=int, default=1, help="Number of ping requests to send (default: 1).")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose output for debugging.")
    return parser.parse_args()


def get_mac_address(interface):
    """
    Gets the MAC address of the specified network interface.

    Args:
        interface (str): The name of the network interface.

    Returns:
        str: The MAC address of the interface, or None if an error occurs.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface.encode('utf-8')[:15]))
        mac_address = ':'.join('%02x' % b for b in info[18:24])
        return mac_address
    except Exception as e:
        logging.error(f"Error getting MAC address for {interface}: {e}")
        return None


def generate_link_local_addresses(interface):
    """
    Generates potential IPv6 link-local addresses based on the interface's MAC address.

    Args:
        interface (str): The name of the network interface.

    Yields:
        str: An IPv6 link-local address.
    """
    mac_address = get_mac_address(interface)
    if mac_address:
        try:
            # Convert MAC address to EUI-64 format
            oui, nic = mac_address.split(":", 3), mac_address.split(":", 3)[3:]
            eui64 = oui[0] + oui[1] + ":" + oui[2] + "ff:fe" + nic[0] + ":" + nic[1]
            
            # Flip the 7th bit of the first octet
            first_octet_int = int(eui64.split(":")[0], 16) ^ 2
            eui64_modified = str(hex(first_octet_int)[2:]) + ":" + ":".join(eui64.split(":")[1:])

            # Construct the link-local address
            link_local_address = "fe80::" + eui64_modified

            yield link_local_address + "%" + interface

        except Exception as e:
            logging.error(f"Error generating IPv6 link-local address: {e}")


def ping_ipv6(ipv6_address, timeout=1, count=1, verbose=False):
    """
    Pings an IPv6 address and returns True if successful, False otherwise.

    Args:
        ipv6_address (str): The IPv6 address to ping.
        timeout (int): Timeout for the ping request in seconds.
        count (int): Number of ping requests to send.
        verbose (bool): Enable verbose output.

    Returns:
        bool: True if the ping was successful, False otherwise.
    """
    try:
        # Using subprocess to execute ping6 command.
        command = ["ping6", "-c", str(count), "-i", "0.2", "-W", str(timeout), ipv6_address]  # -i interval, -W timeout
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            if verbose:
                logging.debug(f"Ping successful to {ipv6_address}:\n{stdout.decode()}")
            return True
        else:
            if verbose:
                logging.debug(f"Ping failed to {ipv6_address}:\n{stderr.decode()}")
            return False
    except FileNotFoundError:
        logging.error("ping6 command not found.  Please ensure it is installed and in your PATH.")
        sys.exit(1) # Exit due to missing dependency.
    except Exception as e:
        logging.error(f"Error pinging {ipv6_address}: {e}")
        return False

def is_valid_interface(interface):
    """
    Checks if the specified network interface exists.

    Args:
        interface (str): The name of the network interface.

    Returns:
        bool: True if the interface exists, False otherwise.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface.encode('utf-8')[:15]))
        return True
    except OSError:
        return False


def main():
    """
    Main function to scan for IPv6 link-local addresses and ping them.
    """
    args = setup_argparse()

    interface = args.interface
    timeout = args.timeout
    count = args.count
    verbose = args.verbose

    # Input validation: Check if interface exists
    if not is_valid_interface(interface):
        logging.error(f"Invalid interface: {interface}.  Please specify a valid network interface.")
        sys.exit(1)  # Exit if the interface is invalid.


    mac_address = get_mac_address(interface)
    if not mac_address:
        logging.error(f"Failed to retrieve MAC address for interface {interface}.  Unable to proceed.")
        sys.exit(1) # Exit if MAC address cannot be retrieved

    print(f"Scanning IPv6 link-local addresses on interface: {interface} (MAC: {mac_address})")

    # Create a list to store discovered hosts
    discovered_hosts = []

    # Iterate through potential link-local addresses
    for ipv6_address in generate_link_local_addresses(interface):
        if ping_ipv6(ipv6_address, timeout, count, verbose):
            print(f"Host found: IPv6={ipv6_address}, MAC={mac_address}")
            discovered_hosts.append({"ipv6": ipv6_address, "mac": mac_address})
        else:
            if verbose:
                logging.debug(f"No response from {ipv6_address}")

    if not discovered_hosts:
        print("No live hosts found on the local link.")

if __name__ == "__main__":
    # Example Usage
    # python3 net_ipv6_link_local_scanner.py -i eth0
    # python3 net_ipv6_link_local_scanner.py -i wlan0 -t 2 -c 3 -v
    main()