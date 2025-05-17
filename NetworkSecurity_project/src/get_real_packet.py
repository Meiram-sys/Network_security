#!/usr/bin/env python3
"""
Network Data Capture and Parsing Script

This script sequentially runs two Python scripts:
1. pcap.py - Captures network data in pcap format (requires sudo)
2. packet_parser.py - Parses the captured data into ML format
"""

import subprocess
import os
import sys
import time

def run_command(command, description):
    """Run a shell command and handle potential errors."""
    print(f"Starting: {description}")
    try:
        process = subprocess.run(command, check=True, shell=True)
        print(f"Successfully completed: {description}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error during {description}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during {description}: {e}")
        return False

def main():
    # Define paths to the scripts
    pcap_script = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/src/parser/pcap.py"
    parser_script = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/src/parser/packet_parser.py"
    
    # Verify that both scripts exist
    if not os.path.exists(pcap_script):
        print(f"Error: {pcap_script} does not exist.")
        return False
    
    if not os.path.exists(parser_script):
        print(f"Error: {parser_script} does not exist.")
        return False
    
    # Step 1: Run pcap.py with sudo
    capture_command = f"sudo python3 {pcap_script} -t 120"
    if not run_command(capture_command, "Network data capture"):
        print("Failed to capture network data. Stopping execution.")
        return False
    
    # Short delay to ensure the first process completes fully
    time.sleep(1)
    
    # Step 2: Run packet_parser.py
    parse_command = f"python3 {parser_script}"
    if not run_command(parse_command, "Data parsing"):
        print("Failed to parse network data.")
        return False
    
    print("All operations completed successfully.")
    return True

if __name__ == "__main__":
    sys.exit(0 if main() else 1)