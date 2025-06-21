#!/usr/bin/env python3
"""
Enhanced Network Data Capture and Parsing Script with DDoS
"""
import subprocess
import os
import sys
import time
import threading

def run_ddos_attack(duration=60):
    """Run DDoS attack in background"""
    ddos_script = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_project/Network_security/NetworkSecurity_project/src/parser/ddos_simulator.py"
    if os.path.exists(ddos_script):
        ddos_command = f"python3 {ddos_script} {duration}"
        print("Starting DDoS simulation...")
        subprocess.run(ddos_command, shell=True)
    else:
        print(f"DDoS script not found: {ddos_script}")

def main():
    pcap_script = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_project/Network_security/NetworkSecurity_project/src/parser/pcap.py"
    parser_script = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_project/Network_security/NetworkSecurity_project/src/parser/packet_parser.py"
    
    # Verify scripts exist
    for script in [pcap_script, parser_script]:
        if not os.path.exists(script):
            print(f"Error: {script} does not exist.")
            return False
    
    # Start DDoS attack in background
    ddos_thread = threading.Thread(target=run_ddos_attack, args=(90,))
    ddos_thread.daemon = True
    ddos_thread.start()
    
    # Wait for DDoS to start
    print("Waiting for DDoS to start...")
    time.sleep(3)
    
    # Capture packets from both interfaces using tcpdump directly
    output_file = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_project/Network_security/NetworkSecurity_project/src/parser/network_data/packet.pcap"
    
    capture_command = f"sudo tcpdump -i any -w {output_file} -G 60 -W 1"
    print("Starting packet capture on both lo0 and en0...")
    
    try:
        subprocess.run(capture_command, shell=True, check=True)
        print("Packet capture completed successfully")
    except subprocess.CalledProcessError as e:
        print(f"Error during packet capture: {e}")
        return False
    
    # Parse captured packets
    time.sleep(2)
    parse_command = f"python3 {parser_script}"
    print("Starting packet parsing...")
    try:
        subprocess.run(parse_command, shell=True, check=True)
        print("Packet parsing completed successfully")
    except subprocess.CalledProcessError as e:
        print(f"Error during packet parsing: {e}")
        return False
    
    print("All operations completed successfully.")
    return True

if __name__ == "__main__":
    sys.exit(0 if main() else 1)