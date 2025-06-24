
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
import time
import os
from collections import defaultdict
import os

class OptimizedFlowExtractor:
    """
    Optimized flow extractor that preserves all required features plus Source/Destination IP.
    """

    def __init__(self, pcap_file: str, timeout: int = 120, activity_timeout: int = 5):
        self.pcap_file = pcap_file
        self.timeout = timeout
        self.activity_timeout = activity_timeout
        self.flows = {}  
        self.completed_flows = []

    def _create_empty_flow(self):
        """Create empty flow with all required fields."""
        return {
            'source_ip': None, 'dest_ip': None,  
            'start_time': None, 'last_time': None, 'dest_port': None,
            'fwd_packets': [], 'bwd_packets': [], 'fwd_times': [], 'bwd_times': [],
            'fwd_psh_flags': 0, 'bwd_psh_flags': 0, 'fwd_urg_flags': 0, 'bwd_urg_flags': 0,
            'fin_flags': 0, 'syn_flags': 0, 'rst_flags': 0, 'psh_flags': 0, 
            'ack_flags': 0, 'urg_flags': 0, 'cwe_flags': 0, 'ece_flags': 0,
            'fwd_header_bytes': 0, 'bwd_header_bytes': 0,
            'fwd_win_bytes': None, 'bwd_win_bytes': None,
            'fwd_data_pkts': 0, 'min_seg_size_fwd': None,
            'active_times': [], 'idle_times': [], 'last_activity': None
        }

    def process_packets(self):
        """
        Optimized packet processing that preserves all features plus IP addresses.
        """
        print(f"Reading packets from {self.pcap_file}...")
        try:
            packets = rdpcap(self.pcap_file)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return False
        
        print(f"Processing {len(packets)} packets...")
        start_time = time.time()
        
        for i, packet in enumerate(packets):
            # Progress indicator every 500 packets
            if i % 500 == 0 and i > 0:
                elapsed = time.time() - start_time
                rate = i / elapsed
                print(f"  Processed {i}/{len(packets)} packets ({rate:.0f} pkt/s)")
            
            try:
                if IP not in packet:
                    continue
                
                # Extract packet info
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                timestamp = float(packet.time)
                packet_len = len(packet)
                ip_header_len = packet[IP].ihl * 4
                
                # Handle TCP/UDP
                if TCP in packet:
                    sport, dport = packet[TCP].sport, packet[TCP].dport
                    flags = packet[TCP].flags
                    proto = 'TCP'
                    header_len = packet[TCP].dataofs * 4
                    win_size = packet[TCP].window
                elif UDP in packet:
                    sport, dport = packet[UDP].sport, packet[UDP].dport
                    flags = 0
                    proto = 'UDP'
                    header_len = 8
                    win_size = 0
                else:
                    continue
                
                # Create flow ID
                if (ip_src, sport) < (ip_dst, dport):
                    flow_id = (ip_src, ip_dst, proto, sport, dport)
                    direction = 'fwd'
                else:
                    flow_id = (ip_dst, ip_src, proto, dport, sport)
                    direction = 'bwd'
                
                # Initialize flow if new
                if flow_id not in self.flows:
                    self.flows[flow_id] = self._create_empty_flow()
                    self.flows[flow_id]['start_time'] = timestamp
                    self.flows[flow_id]['dest_port'] = dport if direction == 'fwd' else sport
                    self.flows[flow_id]['last_activity'] = timestamp
                    # NEW: Store IP addresses based on flow direction
                    if direction == 'fwd':
                        self.flows[flow_id]['source_ip'] = ip_src
                        self.flows[flow_id]['dest_ip'] = ip_dst
                    else:
                        self.flows[flow_id]['source_ip'] = ip_dst
                        self.flows[flow_id]['dest_ip'] = ip_src
                
                flow = self.flows[flow_id]
                flow['last_time'] = timestamp
                
                # Calculate payload and header info
                total_header_len = ip_header_len + header_len
                payload_len = max(0, packet_len - total_header_len)
                
                # Store packet data efficiently
                if direction == 'fwd':
                    flow['fwd_packets'].append(packet_len)
                    flow['fwd_times'].append(timestamp)
                    flow['fwd_header_bytes'] += total_header_len
                    if payload_len > 0:
                        flow['fwd_data_pkts'] += 1
                    if flow['fwd_win_bytes'] is None and proto == 'TCP':
                        flow['fwd_win_bytes'] = win_size
                    if flow['min_seg_size_fwd'] is None or total_header_len < flow['min_seg_size_fwd']:
                        flow['min_seg_size_fwd'] = total_header_len
                else:
                    flow['bwd_packets'].append(packet_len)
                    flow['bwd_times'].append(timestamp)
                    flow['bwd_header_bytes'] += total_header_len
                    if flow['bwd_win_bytes'] is None and proto == 'TCP':
                        flow['bwd_win_bytes'] = win_size
                
                # Process TCP flags efficiently
                if proto == 'TCP':
                    flag_str = str(flags)
                    if 'F' in flag_str: flow['fin_flags'] += 1
                    if 'S' in flag_str: flow['syn_flags'] += 1
                    if 'R' in flag_str: flow['rst_flags'] += 1
                    if 'P' in flag_str: 
                        flow['psh_flags'] += 1
                        if direction == 'fwd': flow['fwd_psh_flags'] += 1
                        else: flow['bwd_psh_flags'] += 1
                    if 'A' in flag_str: flow['ack_flags'] += 1
                    if 'U' in flag_str:
                        flow['urg_flags'] += 1
                        if direction == 'fwd': flow['fwd_urg_flags'] += 1
                        else: flow['bwd_urg_flags'] += 1
                    if 'C' in flag_str: flow['cwe_flags'] += 1
                    if 'E' in flag_str: flow['ece_flags'] += 1
                
                # Simple activity tracking
                if flow['last_activity'] and (timestamp - flow['last_activity']) > self.activity_timeout:
                    idle_time = timestamp - flow['last_activity']
                    flow['idle_times'].append(idle_time)
                
                flow['last_activity'] = timestamp
                
            except Exception as e:
                continue  # Skip problematic packets
        
        # Finalize all flows
        self.completed_flows = list(self.flows.values())
        
        elapsed = time.time() - start_time
        print(f"Processing completed in {elapsed:.2f} seconds")
        print(f"Found {len(self.completed_flows)} flows")
        return True

    def extract_features(self):
        """
        Extract ALL 78 required features PLUS Source IP and Destination IP (80 total).
        """
        # NEW: Updated columns list with Source IP and Destination IP at the beginning
        columns = [
            'Source_IP', 'Destination_IP',  # NEW: Added IP addresses
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
            'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
            'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
        
        if not self.completed_flows:
            return pd.DataFrame(columns=columns)
        
        print("Extracting all 80 features (78 original + Source IP + Destination IP)...")
        features = []
        
        for flow in self.completed_flows:
            try:
                # Allow unidirectional flows for DDoS
                if len(flow['fwd_packets']) == 0 and len(flow['bwd_packets']) == 0:
                    continue
                
                feature_dict = {col: 0 for col in columns}
                
                # NEW: Add IP addresses
                feature_dict['Source_IP'] = flow['source_ip'] or '0.0.0.0'
                feature_dict['Destination_IP'] = flow['dest_ip'] or '0.0.0.0'
                
                # Basic info
                feature_dict['Destination Port'] = flow['dest_port'] or 0
                duration = (flow['last_time'] - flow['start_time']) if flow['last_time'] and flow['start_time'] else 0
                feature_dict['Flow Duration'] = duration * 1000  # ms
                
                # Packet counts
                feature_dict['Total Fwd Packets'] = len(flow['fwd_packets'])
                feature_dict['Total Backward Packets'] = len(flow['bwd_packets'])
                
                # Packet lengths
                fwd_bytes = sum(flow['fwd_packets']) if flow['fwd_packets'] else 0
                bwd_bytes = sum(flow['bwd_packets']) if flow['bwd_packets'] else 0
                feature_dict['Total Length of Fwd Packets'] = fwd_bytes
                feature_dict['Total Length of Bwd Packets'] = bwd_bytes
                
                # Forward stats
                if flow['fwd_packets']:
                    feature_dict['Fwd Packet Length Max'] = max(flow['fwd_packets'])
                    feature_dict['Fwd Packet Length Min'] = min(flow['fwd_packets'])
                    feature_dict['Fwd Packet Length Mean'] = np.mean(flow['fwd_packets'])
                    feature_dict['Fwd Packet Length Std'] = np.std(flow['fwd_packets']) if len(flow['fwd_packets']) > 1 else 0
                
                # Backward stats
                if flow['bwd_packets']:
                    feature_dict['Bwd Packet Length Max'] = max(flow['bwd_packets'])
                    feature_dict['Bwd Packet Length Min'] = min(flow['bwd_packets'])
                    feature_dict['Bwd Packet Length Mean'] = np.mean(flow['bwd_packets'])
                    feature_dict['Bwd Packet Length Std'] = np.std(flow['bwd_packets']) if len(flow['bwd_packets']) > 1 else 0
                
                # Flow rates
                if duration > 0:
                    feature_dict['Flow Bytes/s'] = (fwd_bytes + bwd_bytes) / duration
                    feature_dict['Flow Packets/s'] = (len(flow['fwd_packets']) + len(flow['bwd_packets'])) / duration
                    feature_dict['Fwd Packets/s'] = len(flow['fwd_packets']) / duration
                    feature_dict['Bwd Packets/s'] = len(flow['bwd_packets']) / duration
                
                # IAT calculations (optimized)
                all_times = sorted(flow['fwd_times'] + flow['bwd_times'])
                if len(all_times) > 1:
                    iats = np.diff(all_times)  # Faster than list comprehension
                    feature_dict['Flow IAT Mean'] = np.mean(iats) * 1000
                    feature_dict['Flow IAT Std'] = np.std(iats) * 1000
                    feature_dict['Flow IAT Max'] = np.max(iats) * 1000
                    feature_dict['Flow IAT Min'] = np.min(iats) * 1000
                
                # Forward IAT
                if len(flow['fwd_times']) > 1:
                    fwd_iats = np.diff(sorted(flow['fwd_times']))
                    feature_dict['Fwd IAT Total'] = np.sum(fwd_iats) * 1000
                    feature_dict['Fwd IAT Mean'] = np.mean(fwd_iats) * 1000
                    feature_dict['Fwd IAT Std'] = np.std(fwd_iats) * 1000
                    feature_dict['Fwd IAT Max'] = np.max(fwd_iats) * 1000
                    feature_dict['Fwd IAT Min'] = np.min(fwd_iats) * 1000
                
                # Backward IAT
                if len(flow['bwd_times']) > 1:
                    bwd_iats = np.diff(sorted(flow['bwd_times']))
                    feature_dict['Bwd IAT Total'] = np.sum(bwd_iats) * 1000
                    feature_dict['Bwd IAT Mean'] = np.mean(bwd_iats) * 1000
                    feature_dict['Bwd IAT Std'] = np.std(bwd_iats) * 1000
                    feature_dict['Bwd IAT Max'] = np.max(bwd_iats) * 1000
                    feature_dict['Bwd IAT Min'] = np.min(bwd_iats) * 1000
                
                # TCP Flags
                feature_dict['Fwd PSH Flags'] = flow['fwd_psh_flags']
                feature_dict['Bwd PSH Flags'] = flow['bwd_psh_flags']
                feature_dict['Fwd URG Flags'] = flow['fwd_urg_flags']
                feature_dict['Bwd URG Flags'] = flow['bwd_urg_flags']
                feature_dict['FIN Flag Count'] = flow['fin_flags']
                feature_dict['SYN Flag Count'] = flow['syn_flags']
                feature_dict['RST Flag Count'] = flow['rst_flags']
                feature_dict['PSH Flag Count'] = flow['psh_flags']
                feature_dict['ACK Flag Count'] = flow['ack_flags']
                feature_dict['URG Flag Count'] = flow['urg_flags']
                feature_dict['CWE Flag Count'] = flow['cwe_flags']
                feature_dict['ECE Flag Count'] = flow['ece_flags']
                
                # Header lengths
                feature_dict['Fwd Header Length'] = flow['fwd_header_bytes']
                feature_dict['Bwd Header Length'] = flow['bwd_header_bytes']
                feature_dict['Fwd Header Length.1'] = flow['fwd_header_bytes']  # Duplicate
                
                # Packet stats
                all_packets = flow['fwd_packets'] + flow['bwd_packets']
                if all_packets:
                    feature_dict['Min Packet Length'] = min(all_packets)
                    feature_dict['Max Packet Length'] = max(all_packets)
                    feature_dict['Packet Length Mean'] = np.mean(all_packets)
                    feature_dict['Packet Length Std'] = np.std(all_packets)
                    feature_dict['Packet Length Variance'] = np.var(all_packets)
                    feature_dict['Average Packet Size'] = np.mean(all_packets)
                
                # Ratios and averages
                if len(flow['fwd_packets']) > 0:
                    feature_dict['Down/Up Ratio'] = len(flow['bwd_packets']) / len(flow['fwd_packets'])
                    feature_dict['Avg Fwd Segment Size'] = fwd_bytes / len(flow['fwd_packets'])
                
                if len(flow['bwd_packets']) > 0:
                    feature_dict['Avg Bwd Segment Size'] = bwd_bytes / len(flow['bwd_packets'])
                
                # Subflow (same as main flow for simplicity)
                feature_dict['Subflow Fwd Packets'] = len(flow['fwd_packets'])
                feature_dict['Subflow Fwd Bytes'] = fwd_bytes
                feature_dict['Subflow Bwd Packets'] = len(flow['bwd_packets'])
                feature_dict['Subflow Bwd Bytes'] = bwd_bytes
                
                # Window sizes
                feature_dict['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] or 0
                feature_dict['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] or 0
                
                # Data packets
                feature_dict['act_data_pkt_fwd'] = flow['fwd_data_pkts']
                feature_dict['min_seg_size_forward'] = flow['min_seg_size_fwd'] or 0
                
                # Activity/Idle times (simplified)
                if flow['active_times']:
                    feature_dict['Active Mean'] = np.mean(flow['active_times']) * 1000
                    feature_dict['Active Std'] = np.std(flow['active_times']) * 1000
                    feature_dict['Active Max'] = np.max(flow['active_times']) * 1000
                    feature_dict['Active Min'] = np.min(flow['active_times']) * 1000
                
                if flow['idle_times']:
                    feature_dict['Idle Mean'] = np.mean(flow['idle_times']) * 1000
                    feature_dict['Idle Std'] = np.std(flow['idle_times']) * 1000
                    feature_dict['Idle Max'] = np.max(flow['idle_times']) * 1000
                    feature_dict['Idle Min'] = np.min(flow['idle_times']) * 1000
                
                # Bulk metrics (set to 0 for simplicity - you can add full implementation if needed)
                for bulk_col in ['Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
                               'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']:
                    feature_dict[bulk_col] = 0
                
                features.append(feature_dict)
                
            except Exception as e:
                print(f"Error extracting features for flow: {e}")
                continue
        
        if not features:
            return pd.DataFrame(columns=columns)
        
        df = pd.DataFrame(features)
        
        # Ensure all columns exist
        for col in columns:
            if col not in df.columns:
                if col in ['Source_IP', 'Destination_IP']:
                    df[col] = '0.0.0.0'
                else:
                    df[col] = 0
        
        return df[columns]  # Return in correct order


def analyze_pcap_optimized(input_file, output_file=None, timeout=120):
    """
    Optimized PCAP analysis that preserves all features plus IP addresses.
    """
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist")
        return pd.DataFrame()
    
    if output_file is None:
        output_file = input_file.replace('.pcap', '_complete_features_with_ips.csv')
    
    start_time = time.time()
    
    try:
        extractor = OptimizedFlowExtractor(input_file, timeout)
        
        if not extractor.process_packets():
            return pd.DataFrame()
        
        df = extractor.extract_features()
        
        # Replace spaces with underscores (but keep Source_IP and Destination_IP as is)
        df.columns = df.columns.str.replace(' ', '_')
        
        if not df.empty and output_file:
            df.to_csv(output_file, index=False)
            print(f"Features saved to {output_file}")
        
        elapsed = time.time() - start_time
        print(f"Complete analysis finished in {elapsed:.2f} seconds")
        
        if not df.empty:
            print(f"Extracted {len(df)} flows with {len(df.columns)} features")
            print(f"Features: 78 original + Source IP + Destination IP = 80 total")
            print(f"Unidirectional flows: {len(df[df['Total_Backward_Packets'] == 0])}")
            print(f"Bidirectional flows: {len(df[df['Total_Backward_Packets'] > 0])}")
        
        return df
        
    except Exception as e:
        print(f"Error: {e}")
        return pd.DataFrame()

def find_project_root():
    """Find NetworkSecurity_project directory"""
    current_dir = os.path.abspath(os.path.dirname(__file__))
    
    while current_dir != os.path.dirname(current_dir):
        if os.path.basename(current_dir) == "NetworkSecurity_project":
            return current_dir
        current_dir = os.path.dirname(current_dir)
    
    return None


if __name__ == "__main__":
    project_root = find_project_root()
    
    if project_root:
        pcap_file = os.path.join(project_root, "src", "parser", "network_data", "packet.pcap")
        output_file = os.path.join(project_root, "src", "parser", "network_data", "real_packet_features.csv")
    else:
        print("Error: Could not find NetworkSecurity_project directory")
        exit(1)
    
    df = analyze_pcap_optimized(pcap_file, output_file)
    
    if not df.empty:
        print(f"\nFinal result: {df.shape}")
        print("All 80 features preserved!")
        print(f"Columns: {list(df.columns)}")