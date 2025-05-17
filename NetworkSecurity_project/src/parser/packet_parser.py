from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
import time
import os
from collections import defaultdict

class FlowExtractor:
    """
    Extract network flow features from packet captures.
    
    This class processes packets from PCAP files, groups them into bidirectional
    flows, and calculates statistical features for network traffic analysis.
    """

    def __init__(self, pcap_file: str, timeout: int = 600, activity_timeout: int = 5):
        """
        Initialize the flow extractor.
        
        Args:
            pcap_file: Path to the PCAP file to analyze
            timeout: Flow timeout in seconds (default: 600)
            activity_timeout: Timeout for active/idle periods (default: 5)
        """
        self.pcap_file = pcap_file
        self.timeout = timeout
        self.activity_timeout = activity_timeout
        self.flows = defaultdict(lambda: self._create_empty_flow())
        self.completed_flows = []
        self.active_times = defaultdict(list)
        self.idle_times = defaultdict(list)
        self.bulk_flows = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.active_flows = {}  # Last activity time for each flow

    def _create_empty_flow(self):
        """
        Create an empty flow data structure with default values.
        
        Returns:
            Dictionary with initialized values for flow tracking
        """
        return {
            # Basic flow info
            'start_time': None,
            'last_time': None,
            'dest_port': None,
            
            # Packet lists
            'fwd_packets': [],
            'bwd_packets': [],
            
            # Packet timestamps
            'fwd_times': [],
            'bwd_times': [],
            
            # TCP flags
            'fwd_psh_flags': 0,
            'bwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'bwd_urg_flags': 0,
            'fin_flags': 0,
            'syn_flags': 0,
            'rst_flags': 0,
            'psh_flags': 0,
            'ack_flags': 0,
            'urg_flags': 0,
            'cwe_flags': 0,
            'ece_flags': 0,
            
            # Header lengths
            'fwd_header_bytes': 0,
            'bwd_header_bytes': 0,
            
            # TCP window size
            'fwd_win_bytes': None,
            'bwd_win_bytes': None,
            
            # Data packets
            'fwd_data_pkts': 0,
            'min_seg_size_fwd': None,
            
            # Bulk transfer tracking
            'fwd_bulk_state': 0,
            'bwd_bulk_state': 0,
            'fwd_bulk_start': 0,
            'bwd_bulk_start': 0,
            'fwd_bulk_bytes': 0,
            'bwd_bulk_bytes': 0,
            'fwd_bulk_packets': 0,
            'bwd_bulk_packets': 0,
            
            # Activity tracking
            'active_start': 0,
            'idle_start': 0,
            'active': False,
        }

    def process_packets(self):
        """
        Process all packets in the PCAP file and extract flow features.
        
        This method reads packets, organizes them into flows, and calculates
        statistics for each flow.
        """
        print(f"Reading packets from {self.pcap_file}...")
        try:
            packets = rdpcap(self.pcap_file)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            # Continue with an empty packet list instead of failing
            packets = []
        
        print(f"Processing {len(packets)} packets...")
        
        for packet in packets:
            try:
                if IP not in packet:
                    continue
                
                # Extract IP information
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                
                # Check for TCP or UDP
                if TCP in packet:
                    proto = 'TCP'
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    header_len = packet[TCP].dataofs * 4  # TCP header length in bytes
                    win_size = packet[TCP].window
                elif UDP in packet:
                    proto = 'UDP'
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    flags = 0
                    header_len = 8  # UDP header is 8 bytes
                    win_size = 0
                else:
                    continue  # Skip other protocols
                
                # Create flow tuple (5-tuple) and the reverse
                forward_flow = (ip_src, ip_dst, proto, sport, dport)
                backward_flow = (ip_dst, ip_src, proto, dport, sport)
                
                # Current packet timestamp
                timestamp = float(packet.time)
                
                # Check if it's a new flow or existing one
                if forward_flow in self.flows:
                    flow_id = forward_flow
                    direction = 'fwd'
                elif backward_flow in self.flows:
                    flow_id = backward_flow
                    direction = 'bwd'
                else:
                    # New flow, use forward direction
                    flow_id = forward_flow
                    direction = 'fwd'
                    self.flows[flow_id]['start_time'] = timestamp
                    self.flows[flow_id]['active_start'] = timestamp
                    self.flows[flow_id]['active'] = True
                    self.flows[flow_id]['dest_port'] = dport
                
                flow = self.flows[flow_id]
                
                # Update timestamps
                flow['last_time'] = timestamp
                
                # Store packet
                packet_len = len(packet)
                ip_header_len = packet[IP].ihl * 4
                total_header_len = ip_header_len + header_len
                payload_len = packet_len - total_header_len
                
                if direction == 'fwd':
                    flow['fwd_packets'].append(packet_len)
                    flow['fwd_times'].append(timestamp)
                    flow['fwd_header_bytes'] += total_header_len
                    
                    if flow['fwd_win_bytes'] is None and TCP in packet:
                        flow['fwd_win_bytes'] = win_size
                    
                    if payload_len > 0:
                        flow['fwd_data_pkts'] += 1
                    
                    if flow['min_seg_size_fwd'] is None or total_header_len < flow['min_seg_size_fwd']:
                        flow['min_seg_size_fwd'] = total_header_len
                else:
                    flow['bwd_packets'].append(packet_len)
                    flow['bwd_times'].append(timestamp)
                    flow['bwd_header_bytes'] += total_header_len
                    
                    if flow['bwd_win_bytes'] is None and TCP in packet:
                        flow['bwd_win_bytes'] = win_size
                
                # Process TCP flags
                if TCP in packet:
                    if direction == 'fwd':
                        if 'P' in flags:
                            flow['fwd_psh_flags'] += 1
                        if 'U' in flags:
                            flow['fwd_urg_flags'] += 1
                    else:
                        if 'P' in flags:
                            flow['bwd_psh_flags'] += 1
                        if 'U' in flags:
                            flow['bwd_urg_flags'] += 1
                    
                    if 'F' in flags:
                        flow['fin_flags'] += 1
                    if 'S' in flags:
                        flow['syn_flags'] += 1
                    if 'R' in flags:
                        flow['rst_flags'] += 1
                    if 'P' in flags:
                        flow['psh_flags'] += 1
                    if 'A' in flags:
                        flow['ack_flags'] += 1
                    if 'U' in flags:
                        flow['urg_flags'] += 1
                    if 'C' in flags:
                        flow['cwe_flags'] += 1
                    if 'E' in flags:
                        flow['ece_flags'] += 1
                
                # Track active and idle time
                if timestamp - flow['last_time'] > self.activity_timeout:
                    if flow['active']:
                        # Record the active time
                        active_time = flow['last_time'] - flow['active_start']
                        self.active_times[flow_id].append(active_time)
                        
                        # Start an idle period
                        flow['idle_start'] = flow['last_time']
                        flow['active'] = False
                    else:
                        # Record the idle time
                        idle_time = timestamp - flow['idle_start']
                        self.idle_times[flow_id].append(idle_time)
                        
                        # Start a new active period
                        flow['active_start'] = timestamp
                        flow['active'] = True
                
                # Update bulk behavior tracking
                self._update_bulk_behavior(flow_id, direction, payload_len, timestamp)
                
                # Check for flow timeout
                self._check_flow_timeouts(timestamp)
            except Exception as e:
                # Log error but continue processing other packets
                print(f"Error processing packet: {e}")
                continue
        
        # Finalize all remaining flows
        for flow_id in list(self.flows.keys()):
            try:
                self._finalize_flow(flow_id)
            except Exception as e:
                print(f"Error finalizing flow: {e}")
        
        return True

    def _update_bulk_behavior(self, flow_id, direction, payload_len, timestamp):
        """
        Update bulk transfer behavior tracking.
        
        Args:
            flow_id: Flow identifier tuple
            direction: Packet direction ('fwd' or 'bwd')
            payload_len: Size of packet payload
            timestamp: Packet timestamp
        """
        try:
            flow = self.flows[flow_id]
            bulk_state_field = f"{direction}_bulk_state"
            bulk_start_field = f"{direction}_bulk_start"
            bulk_bytes_field = f"{direction}_bulk_bytes"
            bulk_packets_field = f"{direction}_bulk_packets"
            bulk_array = self.bulk_flows[flow_id][direction[:3]]
            
            # If payload exists, check and update bulk state
            if payload_len > 0:
                if flow[bulk_state_field] == 0:
                    flow[bulk_state_field] = 1
                    flow[bulk_start_field] = timestamp
                    flow[bulk_bytes_field] = payload_len
                    flow[bulk_packets_field] = 1
                else:
                    flow[bulk_bytes_field] += payload_len
                    flow[bulk_packets_field] += 1
            elif flow[bulk_state_field] == 1:
                # End of bulk transfer
                if flow[bulk_packets_field] >= 4:  # Minimum packets for bulk
                    bulk_duration = timestamp - flow[bulk_start_field]
                    if bulk_duration > 0:
                        bulk_rate = flow[bulk_bytes_field] / bulk_duration
                    else:
                        bulk_rate = 0
                    
                    bulk_array.append({
                        'bytes': flow[bulk_bytes_field],
                        'packets': flow[bulk_packets_field],
                        'rate': bulk_rate
                    })
                
                # Reset bulk state
                flow[bulk_state_field] = 0
                flow[bulk_bytes_field] = 0
                flow[bulk_packets_field] = 0
        except Exception as e:
            # Just log and continue - don't let bulk tracking failures affect processing
            print(f"Error updating bulk behavior: {e}")

    def _check_flow_timeouts(self, current_time):
        """
        Check for flow timeouts and finalize timed-out flows.
        
        Args:
            current_time: Current timestamp to check against
        """
        for flow_id in list(self.flows.keys()):
            try:
                flow = self.flows[flow_id]
                if current_time - flow['last_time'] > self.timeout:
                    self._finalize_flow(flow_id)
            except Exception as e:
                print(f"Error checking flow timeout: {e}")

    def _finalize_flow(self, flow_id):
        """
        Finalize a flow by calculating final statistics and adding to completed flows.
        
        Args:
            flow_id: Flow identifier tuple
        """
        try:
            flow = self.flows[flow_id]
            
            # Final check for active/idle timing
            if flow['active']:
                active_time = flow['last_time'] - flow['active_start']
                self.active_times[flow_id].append(active_time)
            
            # Add to completed flows
            self.completed_flows.append(flow)
            
            # Clean up
            del self.flows[flow_id]
        except Exception as e:
            print(f"Error finalizing flow: {e}")

    def extract_features(self):
        """
        Extract features from the completed flows.
        
        Returns:
            DataFrame containing all the extracted features for each flow
        """
        # Define all required columns to ensure they exist in the output
        columns = [
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
        
        # If no flows were completed, return an empty DataFrame with all required columns
        if not self.completed_flows:
            return pd.DataFrame(columns=columns)
        
        features = []
        
        for flow in self.completed_flows:
            try:
                # Skip flows without enough packets for meaningful analysis
                if len(flow['fwd_packets']) == 0 or len(flow['bwd_packets']) == 0:
                    continue
                
                flow_id = id(flow)  # Unique ID for this flow object
                
                # Initialize feature dictionary with zeros for all columns
                feature_dict = {col: 0 for col in columns}
                
                # Calculate all required features
                
                # Basic flow info
                feature_dict['Destination Port'] = flow['dest_port']
                feature_dict['Flow Duration'] = (flow['last_time'] - flow['start_time']) * 1000  # ms
                
                # Packet counts
                feature_dict['Total Fwd Packets'] = len(flow['fwd_packets'])
                feature_dict['Total Backward Packets'] = len(flow['bwd_packets'])
                
                # Packet lengths
                fwd_bytes = sum(flow['fwd_packets'])
                bwd_bytes = sum(flow['bwd_packets'])
                feature_dict['Total Length of Fwd Packets'] = fwd_bytes
                feature_dict['Total Length of Bwd Packets'] = bwd_bytes
                
                # Forward packet length stats
                if flow['fwd_packets']:
                    feature_dict['Fwd Packet Length Max'] = max(flow['fwd_packets'])
                    feature_dict['Fwd Packet Length Min'] = min(flow['fwd_packets'])
                    feature_dict['Fwd Packet Length Mean'] = np.mean(flow['fwd_packets'])
                    feature_dict['Fwd Packet Length Std'] = np.std(flow['fwd_packets']) if len(flow['fwd_packets']) > 1 else 0
                
                # Backward packet length stats
                if flow['bwd_packets']:
                    feature_dict['Bwd Packet Length Max'] = max(flow['bwd_packets'])
                    feature_dict['Bwd Packet Length Min'] = min(flow['bwd_packets'])
                    feature_dict['Bwd Packet Length Mean'] = np.mean(flow['bwd_packets'])
                    feature_dict['Bwd Packet Length Std'] = np.std(flow['bwd_packets']) if len(flow['bwd_packets']) > 1 else 0
                
                # Flow rates
                duration_sec = (flow['last_time'] - flow['start_time'])
                if duration_sec > 0:
                    feature_dict['Flow Bytes/s'] = (fwd_bytes + bwd_bytes) / duration_sec
                    feature_dict['Flow Packets/s'] = (len(flow['fwd_packets']) + len(flow['bwd_packets'])) / duration_sec
                
                # Inter-arrival times (IAT)
                all_times = sorted(flow['fwd_times'] + flow['bwd_times'])
                
                # Flow IAT
                if len(all_times) > 1:
                    iats = [all_times[i] - all_times[i-1] for i in range(1, len(all_times))]
                    feature_dict['Flow IAT Mean'] = np.mean(iats) * 1000  # ms
                    feature_dict['Flow IAT Std'] = np.std(iats) * 1000 if len(iats) > 1 else 0
                    feature_dict['Flow IAT Max'] = max(iats) * 1000
                    feature_dict['Flow IAT Min'] = min(iats) * 1000
                
                # Forward IAT
                if len(flow['fwd_times']) > 1:
                    fwd_times = sorted(flow['fwd_times'])
                    fwd_iats = [fwd_times[i] - fwd_times[i-1] for i in range(1, len(fwd_times))]
                    feature_dict['Fwd IAT Total'] = sum(fwd_iats) * 1000
                    feature_dict['Fwd IAT Mean'] = np.mean(fwd_iats) * 1000
                    feature_dict['Fwd IAT Std'] = np.std(fwd_iats) * 1000 if len(fwd_iats) > 1 else 0
                    feature_dict['Fwd IAT Max'] = max(fwd_iats) * 1000
                    feature_dict['Fwd IAT Min'] = min(fwd_iats) * 1000
                
                # Backward IAT
                if len(flow['bwd_times']) > 1:
                    bwd_times = sorted(flow['bwd_times'])
                    bwd_iats = [bwd_times[i] - bwd_times[i-1] for i in range(1, len(bwd_times))]
                    feature_dict['Bwd IAT Total'] = sum(bwd_iats) * 1000
                    feature_dict['Bwd IAT Mean'] = np.mean(bwd_iats) * 1000
                    feature_dict['Bwd IAT Std'] = np.std(bwd_iats) * 1000 if len(bwd_iats) > 1 else 0
                    feature_dict['Bwd IAT Max'] = max(bwd_iats) * 1000
                    feature_dict['Bwd IAT Min'] = min(bwd_iats) * 1000
                
                # TCP Flags
                feature_dict['Fwd PSH Flags'] = flow['fwd_psh_flags']
                feature_dict['Bwd PSH Flags'] = flow['bwd_psh_flags']
                feature_dict['Fwd URG Flags'] = flow['fwd_urg_flags']
                feature_dict['Bwd URG Flags'] = flow['bwd_urg_flags']
                
                # Header lengths
                feature_dict['Fwd Header Length'] = flow['fwd_header_bytes']
                feature_dict['Bwd Header Length'] = flow['bwd_header_bytes']
                
                # Packet rates
                if duration_sec > 0:
                    feature_dict['Fwd Packets/s'] = len(flow['fwd_packets']) / duration_sec
                    feature_dict['Bwd Packets/s'] = len(flow['bwd_packets']) / duration_sec
                
                # Packet length stats for all packets
                all_packets = flow['fwd_packets'] + flow['bwd_packets']
                if all_packets:
                    feature_dict['Min Packet Length'] = min(all_packets)
                    feature_dict['Max Packet Length'] = max(all_packets)
                    feature_dict['Packet Length Mean'] = np.mean(all_packets)
                    feature_dict['Packet Length Std'] = np.std(all_packets) if len(all_packets) > 1 else 0
                    feature_dict['Packet Length Variance'] = np.var(all_packets) if len(all_packets) > 1 else 0
                
                # Flag counts
                feature_dict['FIN Flag Count'] = flow['fin_flags']
                feature_dict['SYN Flag Count'] = flow['syn_flags']
                feature_dict['RST Flag Count'] = flow['rst_flags']
                feature_dict['PSH Flag Count'] = flow['psh_flags']
                feature_dict['ACK Flag Count'] = flow['ack_flags']
                feature_dict['URG Flag Count'] = flow['urg_flags']
                feature_dict['CWE Flag Count'] = flow['cwe_flags']
                feature_dict['ECE Flag Count'] = flow['ece_flags']
                
                # Down/Up Ratio
                if len(flow['fwd_packets']) > 0:
                    feature_dict['Down/Up Ratio'] = len(flow['bwd_packets']) / len(flow['fwd_packets'])
                
                # Average packet sizes
                if all_packets:
                    feature_dict['Average Packet Size'] = (fwd_bytes + bwd_bytes) / len(all_packets)
                
                if flow['fwd_packets']:
                    feature_dict['Avg Fwd Segment Size'] = fwd_bytes / len(flow['fwd_packets'])
                
                if flow['bwd_packets']:
                    feature_dict['Avg Bwd Segment Size'] = bwd_bytes / len(flow['bwd_packets'])
                
                # Duplicate header length field (as in the required column list)
                feature_dict['Fwd Header Length.1'] = flow['fwd_header_bytes']
                
                # Bulk transfer metrics
                fwd_bulks = self.bulk_flows[flow_id]['fwd']
                bwd_bulks = self.bulk_flows[flow_id]['bwd']
                
                if fwd_bulks:
                    feature_dict['Fwd Avg Bytes/Bulk'] = np.mean([b['bytes'] for b in fwd_bulks])
                    feature_dict['Fwd Avg Packets/Bulk'] = np.mean([b['packets'] for b in fwd_bulks])
                    feature_dict['Fwd Avg Bulk Rate'] = np.mean([b['rate'] for b in fwd_bulks])
                
                if bwd_bulks:
                    feature_dict['Bwd Avg Bytes/Bulk'] = np.mean([b['bytes'] for b in bwd_bulks])
                    feature_dict['Bwd Avg Packets/Bulk'] = np.mean([b['packets'] for b in bwd_bulks])
                    feature_dict['Bwd Avg Bulk Rate'] = np.mean([b['rate'] for b in bwd_bulks])
                
                # Subflow metrics (simplified as the same as the main flow for now)
                feature_dict['Subflow Fwd Packets'] = len(flow['fwd_packets'])
                feature_dict['Subflow Fwd Bytes'] = fwd_bytes
                feature_dict['Subflow Bwd Packets'] = len(flow['bwd_packets'])
                feature_dict['Subflow Bwd Bytes'] = bwd_bytes
                
                # TCP window information
                feature_dict['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] if flow['fwd_win_bytes'] is not None else 0
                feature_dict['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] if flow['bwd_win_bytes'] is not None else 0
                
                # Data packets and segment size
                feature_dict['act_data_pkt_fwd'] = flow['fwd_data_pkts']
                feature_dict['min_seg_size_forward'] = flow['min_seg_size_fwd'] if flow['min_seg_size_fwd'] is not None else 0
                
                # Active and idle time statistics
                active_times = self.active_times[flow_id]
                idle_times = self.idle_times[flow_id]
                
                if active_times:
                    feature_dict['Active Mean'] = np.mean(active_times) * 1000  # ms
                    feature_dict['Active Std'] = np.std(active_times) * 1000 if len(active_times) > 1 else 0
                    feature_dict['Active Max'] = max(active_times) * 1000
                    feature_dict['Active Min'] = min(active_times) * 1000
                
                if idle_times:
                    feature_dict['Idle Mean'] = np.mean(idle_times) * 1000  # ms
                    feature_dict['Idle Std'] = np.std(idle_times) * 1000 if len(idle_times) > 1 else 0
                    feature_dict['Idle Max'] = max(idle_times) * 1000
                    feature_dict['Idle Min'] = min(idle_times) * 1000
                
                features.append(feature_dict)
            except Exception as e:
                print(f"Error extracting features for flow: {e}")
                continue
        
        # Create DataFrame with all required columns
        if not features:
            return pd.DataFrame(columns=columns)  # Return empty DF with column names
        
        df = pd.DataFrame(features)
        
        # Ensure all required columns exist, fill missing with zeros
        for col in columns:
            if col not in df.columns:
                df[col] = 0
        
        # Return DataFrame with columns in the specified order
        return df[columns]


def analyze_pcap(input_file, output_file="flow_features.csv", timeout=600):
    """
    Analyze a PCAP file and extract flow features.
    
    Args:
        input_file: Path to the input PCAP file
        output_file: Path to save the output CSV file (default: flow_features.csv)
        timeout: Flow timeout in seconds (default: 600)
        
    Returns:
        DataFrame containing the extracted features
    """
    try:
        if not os.path.exists(input_file):
            print(f"Error: Input file '{input_file}' does not exist")
            # Create an empty DataFrame with all required columns instead of failing
            columns = [
                'Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets',
                'Total_Length_of_Fwd_Packets', 'Total_Length_of_Bwd_Packets', 'Fwd_Packet_Length_Max',
                'Fwd_Packet_Length_Min', 'Fwd_Packet_Length_Mean', 'Fwd_Packet_Length_Std',
                'Bwd_Packet_Length_Max', 'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
                'Bwd_Packet_Length_Std', 'Flow_Bytes/s', 'Flow_Packets/s', 'Flow_IAT_Mean',
                'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean',
                'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Total', 'Bwd_IAT_Mean',
                'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min', 'Fwd_PSH_Flags', 'Bwd_PSH_Flags',
                'Fwd_URG_Flags', 'Bwd_URG_Flags', 'Fwd_Header_Length', 'Bwd_Header_Length',
                'Fwd_Packets/s', 'Bwd_Packets/s', 'Min_Packet_Length', 'Max_Packet_Length',
                'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance', 'FIN_Flag_Count',
                'SYN_Flag_Count', 'RST_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count', 'URG_Flag_Count',
                'CWE_Flag_Count', 'ECE_Flag_Count', 'Down/Up_Ratio', 'Average_Packet_Size',
                'Avg_Fwd_Segment_Size', 'Avg_Bwd_Segment_Size', 'Fwd_Header_Length.1',
                'Fwd_Avg_Bytes/Bulk', 'Fwd_Avg_Packets/Bulk', 'Fwd_Avg_Bulk_Rate',
                'Bwd_Avg_Bytes/Bulk', 'Bwd_Avg_Packets/Bulk', 'Bwd_Avg_Bulk_Rate',
                'Subflow_Fwd_Packets', 'Subflow_Fwd_Bytes', 'Subflow_Bwd_Packets', 'Subflow_Bwd_Bytes',
                'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
                'min_seg_size_forward', 'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min',
                'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min'
            ]
            empty_df = pd.DataFrame(columns=columns)
            if output_file:
                empty_df.to_csv(output_file, index=False)
                print(f"Empty features file saved to {output_file}")
            return empty_df

        start_time = time.time()

        # Create and run the flow extractor
        extractor = FlowExtractor(input_file, timeout)
        extractor.process_packets()  # Continue even if processing wasn't fully successful

        # Extract features from any flows that were processed
        df = extractor.extract_features()
        
        # Replace spaces with underscores in column names
        df.columns = df.columns.str.replace(' ', '_')

        # Save the features to CSV if output file is specified
        if output_file:
            try:
                df.to_csv(output_file, index=False)
                print(f"Features saved to {output_file}")
            except Exception as e:
                print(f"Error saving CSV file: {e}")

        elapsed_time = time.time() - start_time
        print(f"Extraction completed in {elapsed_time:.2f} seconds")
        print(f"Processed {len(extractor.completed_flows)} flows")

        # Print summary statistics if we have data
        if not df.empty:
            print("\nSummary statistics:")
            print(f"  Total flows: {len(df)}")
            print(f"  Total packets: {df['Total_Fwd_Packets'].sum() + df['Total_Backward_Packets'].sum()}")
            print(f"  Total bytes: {df['Total_Length_of_Fwd_Packets'].sum() + df['Total_Length_of_Bwd_Packets'].sum()}")
            if len(df) > 0:
                avg_duration = df['Flow_Duration'].mean()
                print(f"  Average flow duration: {avg_duration:.2f} ms")

        return df
    except Exception as e:
        print(f"Error during PCAP analysis: {e}")
        # Create and return an empty DataFrame with all required columns
        columns = [
            'Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets',
            'Total_Length_of_Fwd_Packets', 'Total_Length_of_Bwd_Packets', 'Fwd_Packet_Length_Max',
            'Fwd_Packet_Length_Min', 'Fwd_Packet_Length_Mean', 'Fwd_Packet_Length_Std',
            'Bwd_Packet_Length_Max', 'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
            'Bwd_Packet_Length_Std', 'Flow_Bytes/s', 'Flow_Packets/s', 'Flow_IAT_Mean',
            'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean',
            'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Total', 'Bwd_IAT_Mean',
            'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min', 'Fwd_PSH_Flags', 'Bwd_PSH_Flags',
            'Fwd_URG_Flags', 'Bwd_URG_Flags', 'Fwd_Header_Length', 'Bwd_Header_Length',
            'Fwd_Packets/s', 'Bwd_Packets/s', 'Min_Packet_Length', 'Max_Packet_Length',
            'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance', 'FIN_Flag_Count',
            'SYN_Flag_Count', 'RST_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count', 'URG_Flag_Count',
            'CWE_Flag_Count', 'ECE_Flag_Count', 'Down/Up_Ratio', 'Average_Packet_Size',
            'Avg_Fwd_Segment_Size', 'Avg_Bwd_Segment_Size', 'Fwd_Header_Length.1',
            'Fwd_Avg_Bytes/Bulk', 'Fwd_Avg_Packets/Bulk', 'Fwd_Avg_Bulk_Rate',
            'Bwd_Avg_Bytes/Bulk', 'Bwd_Avg_Packets/Bulk', 'Bwd_Avg_Bulk_Rate',
            'Subflow_Fwd_Packets', 'Subflow_Fwd_Bytes', 'Subflow_Bwd_Packets', 'Subflow_Bwd_Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
            'min_seg_size_forward', 'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min',
            'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min'
        ]
        empty_df = pd.DataFrame(columns=columns)
        if output_file:
            try:
                empty_df.to_csv(output_file, index=False)
                print(f"Empty features file saved to {output_file}")
            except Exception as save_err:
                print(f"Error saving empty CSV file: {save_err}")
        return empty_df


# Example of how to use this directly in Python
if __name__ == "__main__":
    # Replace with your actual PCAP file
    pcap_file = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/src/parser/network_data/packet.pcap"
    
    # Get the features directly as a DataFrame
    features_df = analyze_pcap(pcap_file, "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/src/parser/network_data/real_packet_features.csv")
    
    if features_df is not None:
        # You can now work with the features DataFrame directly
        print(f"DataFrame shape: {features_df.shape}")
        print("\nFirst few rows:")
        print(features_df.head())