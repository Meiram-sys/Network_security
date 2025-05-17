#!/usr/bin/env python3
"""
Network Packet Capture Tool - Timeout via Python

This script captures network packets and saves them to a PCAP file.
"""

import argparse
import os
import subprocess
import time
from datetime import datetime
from threading import Timer

def capture_packets(interface=None, output_file=None, packet_count=None, 
                    timeout=None, bpf_filter=None, verbose=True):
    """
    Capture network packets using tcpdump with Python-based timeout.
    """
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/src/parser/network_data/packet.pcap"

    if verbose:
        print(f"Starting packet capture with tcpdump:")
        print(f"  Interface: {interface if interface else 'default'}")
        print(f"  Output file: {output_file}")
        if packet_count:
            print(f"  Packet limit: {packet_count}")
        if timeout:
            print(f"  Time limit: {timeout} seconds")
        if bpf_filter:
            print(f"  Filter: {bpf_filter}")
        print("\nPress Ctrl+C to stop capturing manually...")
        print("-" * 50)

    cmd = ["tcpdump", "-w", output_file]

    if interface:
        cmd.extend(["-i", interface])
    if packet_count:
        cmd.extend(["-c", str(packet_count)])
    if bpf_filter:
        cmd.append(bpf_filter)

    cmd.append("-n")  # Do not convert addresses

    if verbose:
        print(f"Running: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
        if timeout:
            timer = Timer(timeout, proc.terminate)
            timer.start()
        stderr = proc.communicate()[1]
        if timeout:
            timer.cancel()
        if verbose:
            print(stderr)
    except KeyboardInterrupt:
        if verbose:
            print("\nCapture stopped by user")

    if verbose:
        print("-" * 50)
        if os.path.exists(output_file):
            size = os.path.getsize(output_file)
            print(f"Capture complete: file size {size} bytes")
            print(f"Packets saved to {output_file}")
        else:
            print(f"Error: Output file {output_file} was not created")

def list_interfaces():
    """
    List available network interfaces using tcpdump, ip, or ifconfig.
    """
    print("Available network interfaces:")
    print("-" * 30)

    for cmd in [["tcpdump", "-D"], ["ip", "addr"], ["ifconfig"]]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(result.stdout)
                return
        except FileNotFoundError:
            continue

    print("Could not find any suitable command to list interfaces.")

def main():
    parser = argparse.ArgumentParser(description='Capture network packets to a PCAP file')
    parser.add_argument('-i', '--interface', help='Network interface to capture from')
    parser.add_argument('-o', '--output', help='Output PCAP file name')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-t', '--time', type=int, help='Capture duration in seconds')
    parser.add_argument('-f', '--filter', help='BPF filter (e.g., "tcp port 80")')
    parser.add_argument('-l', '--list', action='store_true', help='List available network interfaces')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output messages')

    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    capture_packets(
        interface=args.interface,
        output_file=args.output,
        packet_count=args.count,
        timeout=args.time,
        bpf_filter=args.filter,
        verbose=not args.quiet
    )

if __name__ == '__main__':
    main()
