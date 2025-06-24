#!/usr/bin/env python3
"""
Enhanced Network Data Capture and Parsing Script with DDoS
"""
import subprocess
import os
import sys
import time
import threading

def run_ddos_attack(project_root, duration=60):
    """Run DDoS attack in background"""
    ddos_script = os.path.join(project_root, "src", "parser", "ddos_simulator.py")
    
    if os.path.exists(ddos_script):
        ddos_command = f"python3 {ddos_script} {duration}"
        print("Starting DDoS simulation...")
        subprocess.run(ddos_command, shell=True)
    else:
        print(f"DDoS script not found: {ddos_script}")

def find_project_root():
    """Find NetworkSecurity_project directory"""
    current_dir = os.path.abspath(os.path.dirname(__file__))
    
    while current_dir != os.path.dirname(current_dir):
        if os.path.basename(current_dir) == "NetworkSecurity_project":
            return current_dir
        current_dir = os.path.dirname(current_dir)
    
    return None

def main():
    project_root = find_project_root()
    
    if not project_root:
        print("Error: Could not find NetworkSecurity_project directory")
        return False
    
    parser_script = os.path.join(project_root, "src", "parser", "packet_parser.py")
    output_file = os.path.join(project_root, "src", "parser", "network_data", "packet.pcap")
    
    # Create network_data directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Start DDoS attack in background
    ddos_thread = threading.Thread(target=run_ddos_attack, args=(project_root, 90))
    ddos_thread.daemon = True
    ddos_thread.start()
    
    # Wait for DDoS to start
    print("Waiting for DDoS to start...")
    time.sleep(3)
    
    # Capture packets from both interfaces using tcpdump directly
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