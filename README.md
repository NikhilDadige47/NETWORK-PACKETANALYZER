# Network Packet Analyzer

## Overview
The Network Packet Analyzer is a Python-based tool designed to analyze network traffic from PCAP files. It provides detailed insights into network protocols, bandwidth usage, IP communications, and potential security anomalies. The tool also includes a GUI for ease of use and supports exporting analysis results.

## Features
- **Protocol Analysis**: Identify and analyze network protocols (e.g., TCP, UDP, ICMP).
- **Bandwidth Usage**: Calculate total bandwidth and bandwidth per IP.
- **IP Communication Analysis**: Track communication between source and destination IPs.
- **Anomaly Detection**: Detect unusual protocol usage, high bandwidth consumption, and abnormal communication patterns.
- **Port Scanning Detection**: Identify potential port scanning activities.
- **Shortest Path Calculation**: Compute shortest paths between IPs in the network graph.
- **Export Results**: Save analysis results as CSV files or text files.
- **User-Friendly GUI**: Intuitive interface for selecting PCAP files, setting thresholds, and viewing results.

## Requirements
- Python 3.6 or higher
- Required Python libraries:
  - `scapy`
  - `pandas`
  - `tabulate`
  - `tqdm`
  - `networkx`
  - `tkinter`

Install dependencies using:
```bash
pip install -r requirements.txt
```

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-packet-analyzer.git
   ```
2. Navigate to the project directory:
   ```bash
   cd network-packet-analyzer
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
### Command-Line
Run the script with a PCAP file:
```bash
python mini.py
```

### GUI
1. Launch the GUI:
   ```bash
   python mini.py
   ```
2. Use the interface to:
   - Browse and select a PCAP file.
   - Set the port scan threshold.
   - Analyze packets and view results.
   - Export results to CSV or text files.

## Key Functions
- **`read_pcap(pcap_file)`**: Reads PCAP files and loads packets.
- **`extract_packet_data(packets)`**: Extracts protocol, size, and port information from packets.
- **`analyze_packet_data(df)`**: Analyzes bandwidth, protocol distribution, and IP communications.
- **`detect_anomalies(df, protocol_counts_df, ip_communication_table)`**: Detects anomalies in network traffic.
- **`detect_port_scanning(df, port_scan_threshold)`**: Identifies potential port scanning activities.
- **`print_results(...)`**: Formats and displays analysis results.

## Exported Results
The tool exports the following files:
- `protocol_counts.csv`: Protocol distribution.
- `ip_communications.csv`: Communication between IPs.
- `ip_communication_protocols.csv`: Protocols used between IPs.
- `potential_port_scanners.csv`: Detected port scanners.
- `anomalies.txt`: Anomaly detection results.

## Example
Analyze a sample PCAP file:
```bash
python mini.py --file example.pcap --threshold 100
```

## Disclaimer
This tool is intended for educational and ethical purposes only. Ensure you have proper authorization before analyzing network traffic.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
```