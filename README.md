# NetworkSecurity_project  
**Real-time Network Packet Classification & DDoS Detection**

This repository contains a complete, end-to-end pipeline that **captures live traffic, simulates DDoS attacks, extracts 80 flow-level features, and classifies each flow as _BENIGN_ or _DDOS_ with a pre-trained LightGBM model**.

## ✨ Key Features
- Live packet capture using `tcpdump` (interface-agnostic)
- Aggressive SYN-flood generator for local testing on port `2703`
- High-performance flow parser that preserves all 78 CICIDS-2017 features plus Source/Destination IP (80 total)
- LightGBM inference with persisted `joblib` artefacts and human-readable CSV results
- Modular layout—easy to swap models or plug in new data sources

## 🗂️ Project Layout
NetworkSecurity_project/
├── artifacts/ # Saved model & label encoder (.joblib)
├── get_real_packet.py # Orchestrates capture → parse → (optional) attack
├── inference.py # Runs the trained classifier on fresh features
├── model_training.ipynb # Notebook used to (re)train the LightGBM model
├── Project_Presentation.pptx # High-level slides
└── src/
└── parser/
├── ddos_simulator.py # SYN-flood generator
├── packet_parser.py # 80-feature extractor
└── network_data/ # Captured .pcap and derived .csv files


## ⚙️ Installation

**Prerequisites:** Python 3.9+, `tcpdump` (needs sudo), and libpcap on the host.

```bash
git clone <repo>
cd NetworkSecurity_project
python -m venv .venv && source .venv/bin/activate
pip install scapy pandas numpy lightgbm joblib tqdm

| Step            | Command                                    | Description                                                        |
| --------------- | ------------------------------------------ | ------------------------------------------------------------------ |
| Capture & parse | `sudo python get_real_packet.py`           | Captures 60s of traffic, simulates DDoS, extracts features to CSV  |
| Run inference   | `python inference.py`                      | Loads model, classifies flows, saves result and filtered anomalies |
| Inspect results | `cat model_result/problematic_packets.csv` | View flagged packets with source/destination IPs                   |


📊 Training the Model
Use model_training.ipynb to retrain the classifier with CICIDS-2017 flows (BENIGN + DDOS only). The same feature structure is used for training and inference.

🔍 How It Works
ddos_simulator.py sends TCP SYN floods to port 2703
get_real_packet.py captures packets via tcpdump
packet_parser.py processes packets into 80-feature flows
inference.py loads LightGBM model and classifies flows

| Setting            | Location                     | Description                     |
| ------------------ | ---------------------------- | ------------------------------- |
| Capture duration   | get\_real\_packet.py (`-G`)  | How long to capture packets     |
| DDoS rate/duration | ddos\_simulator.py arguments | Adjust SYN flood behavior       |
| Model path         | inference.py (`artifacts/`)  | Load  `.joblib` model           |

Permission denied by tcpdump: Run with sudo or update capabilities.
Using own PCAP: Drop PCAP in src/parser/network_data/ and run:
python src/parser/packet_parser.py
python inference.py


