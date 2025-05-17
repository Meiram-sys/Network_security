## Network_security AI-Based Intrusion Detection Systems
A real-time network security system that captures packets, processes them through ML models, and implements actions based on detection results.
## Overview
This project implements an AI-based intrusion detection system that:

Captures network packets in real-time
Parses captured data into ML-compatible format
Processes and cleans the data
Applies machine learning models for intrusion detection
Implements real-time actions based on detection results

# Workflow
1. Data Capture
Capture network traffic in PCAP format:
bashsudo python3 pcap.py
2. Data Parsing
Parse captured PCAP data into machine learning compatible format:
bashpython3 packet_parser.py
3. Streamlined Workflow
For a single flow operation (capture and parse):
bashpython3 get_real_packet.py
This script first runs pcap.py and then packet_parser.py automatically.
4. Feature Extraction
Combine separate CSV files into a single dataset for model training:
bashpython3 get_feature.py
The output is used in model_training.ipynb.

# Project Components
## Jupyter Notebooks
checking_parser.ipynb: Inspect and verify PCAP and parsed data
data_cleaning.ipynb: Data preprocessing and cleaning operations
model_training.ipynb: Train and evaluate ML models, store artifacts (label encoder and model)

## Python Scripts
pcap.py: Network packet capture utility
packet_parser.py: PCAP file parsing
get_real_packet.py: Automates the capture-parse workflow
get_feature.py: Feature engineering and dataset preparation
inference.py: Applies trained model to processed data

## Running Inference
To perform inference on new data:
bashpython3 inference.py
This script:
Takes the output from get_feature.py (CSV format)
Applies the trained ML model
Makes predictions
Stores results in model_result/result.csv

## Terminal Execution
Run the project from terminal:
bash/usr/bin/python3
## Output
Detection results are stored in CSV format at:
model_result/result.csv