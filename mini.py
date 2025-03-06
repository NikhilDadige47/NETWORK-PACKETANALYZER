import sys
import logging
from scapy.all import *
import pandas as pd
from tabulate import tabulate
from tqdm import tqdm
import networkx as nx
import random
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Packet Analysis Functions
def read_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP or PCAPNG file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP/PCAPNG file: {e}")
        sys.exit(1)
    return packets

def extract_packet_data(packets):
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_num = packet[IP].proto
            protocol = protocol_name(protocol_num)
            size = len(packet)
            # Initialize ports to None
            src_port = None
            dst_port = None

            # Extract ports if available based on protocol
            if protocol in ['TCP', 'UDP']:
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
            elif protocol == 'ICMP':
                # ICMP does not have ports
                src_port = None
                dst_port = None
            else:
                # For other protocols, ports may not be applicable
                src_port = None
                dst_port = None

            packet_data.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "size": size,
                "src_port": src_port,
                "dst_port": dst_port
            })
    return pd.DataFrame(packet_data)

def protocol_name(number):
    """
    Maps protocol numbers to protocol names.
    Extends the mapping to include more protocols.
    """
    protocol_dict = {
        1: 'ICMP',
        2: 'IGMP',
        6: 'TCP',
        17: 'UDP',
        89: 'OSPF',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        132: 'SCTP',
        88: 'EIGRP',
        115: 'L2TP',
        144: 'MTP',
        58: 'ICMPv6',
        0: 'HOPOPT',
        109: 'PIM',
        # Add more protocols as needed
    }
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    total_bandwidth = df["size"].sum()
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100
    protocol_counts = protocol_counts.rename(index=lambda x: x if not x.startswith("Unknown") else x)
    
    protocol_counts_df = protocol_counts.reset_index()
    protocol_counts_df.columns = ["Protocol", "Percentage"]

    protocol_frequency = df["protocol"].value_counts().reset_index()
    protocol_frequency.columns = ["Protocol", "Count"]

    # Merge count and percentage
    protocol_counts_df = protocol_frequency.merge(protocol_counts_df, on="Protocol")
    
    # IP Communication
    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False)
    ip_communication_percentage = ip_communication / ip_communication.sum() * 100
    ip_communication_table = pd.concat([ip_communication, ip_communication_percentage], axis=1).reset_index()
    ip_communication_table.columns = ['src_ip', 'dst_ip', 'Count', 'Percentage']

    # Protocols between IPs
    ip_communication_protocols = df.groupby(["src_ip", "dst_ip", "protocol"]).size().reset_index()
    ip_communication_protocols.columns = ["Source IP", "Destination IP", "Protocol", "Count"]
    ip_communication_protocols["Percentage"] = ip_communication_protocols.groupby(["Source IP", "Destination IP"])["Count"].transform(lambda x: x / x.sum() * 100)

    return total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols

def extract_packet_data_security(packets):
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets for port scanning activity", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_num = packet[IP].proto
            protocol = protocol_name(protocol_num)
            size = len(packet)

            # Initialize ports to None
            src_port = None
            dst_port = None

            # Extract ports if available based on protocol
            if protocol in ['TCP', 'UDP']:
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
            elif protocol == 'ICMP':
                # ICMP does not have ports
                src_port = None
                dst_port = None
            else:
                # For other protocols, ports may not be applicable
                src_port = None
                dst_port = None

            packet_data.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "size": size,
                "src_port": src_port,
                "dst_port": dst_port
            })
    return pd.DataFrame(packet_data)

def detect_port_scanning(df, port_scan_threshold):
    # Only consider packets with valid destination ports
    df_valid_ports = df.dropna(subset=['dst_port'])
    
    port_scan_df = df_valid_ports.groupby(['src_ip', 'dst_port']).size().reset_index(name='count')
    unique_ports_per_ip = port_scan_df.groupby('src_ip').size().reset_index(name='unique_ports')
    potential_port_scanners = unique_ports_per_ip[unique_ports_per_ip['unique_ports'] >= port_scan_threshold]
    ip_addresses = potential_port_scanners['src_ip'].unique()
    return ip_addresses

def build_network_graph(df):
    G = nx.Graph()
    for _, row in df.iterrows():
        if not G.has_edge(row['src_ip'], row['dst_ip']):
            G.add_edge(row['src_ip'], row['dst_ip'], weight=row['size'])
        else:
            G[row['src_ip']][row['dst_ip']]['weight'] += row['size']
    return G

def compute_all_shortest_paths(graph):
    shortest_paths = {}
    for source_ip in graph.nodes:
        for target_ip in graph.nodes:
            if source_ip != target_ip:
                try:
                    path = nx.shortest_path(graph, source=source_ip, target=target_ip, weight='weight')
                    path_length = nx.shortest_path_length(graph, source=source_ip, target=target_ip, weight='weight')
                    shortest_paths[(source_ip, target_ip)] = (path, path_length)
                except nx.NetworkXNoPath:
                    shortest_paths[(source_ip, target_ip)] = (None, None)
    return shortest_paths

# Anomaly Detection Functions
def detect_anomalies(df, protocol_counts_df, ip_communication_table):
    anomalies = []

    # Anomaly Detection: High Bandwidth Usage per Source IP
    bandwidth_per_ip = df.groupby('src_ip')['size'].sum().reset_index()
    bandwidth_mean = bandwidth_per_ip['size'].mean()
    bandwidth_std = bandwidth_per_ip['size'].std()
    high_bandwidth_threshold = bandwidth_mean + 3 * bandwidth_std
    high_bandwidth_ips = bandwidth_per_ip[bandwidth_per_ip['size'] > high_bandwidth_threshold]
    if not high_bandwidth_ips.empty:
        anomalies.append("High Bandwidth Usage Detected:")
        for _, row in high_bandwidth_ips.iterrows():
            anomalies.append(f" - {row['src_ip']} is using {row['size']} bytes.")
    else:
        anomalies.append("No high bandwidth usage anomalies detected.")

    # Anomaly Detection: Unusual Protocol Usage
    protocol_usage_mean = protocol_counts_df['Percentage'].mean()
    protocol_usage_std = protocol_counts_df['Percentage'].std()
    unusual_protocol_threshold = protocol_usage_mean + 3 * protocol_usage_std
    unusual_protocols = protocol_counts_df[protocol_counts_df['Percentage'] > unusual_protocol_threshold]
    if not unusual_protocols.empty:
        anomalies.append("\nUnusual Protocol Usage Detected:")
        for _, row in unusual_protocols.iterrows():
            anomalies.append(f" - {row['Protocol']} usage is {row['Percentage']:.2f}%, which is unusually high.")
    else:
        anomalies.append("\nNo unusual protocol usage anomalies detected.")

    # Anomaly Detection: Abnormal Number of Communications
    communication_mean = ip_communication_table['Count'].mean()
    communication_std = ip_communication_table['Count'].std()
    abnormal_comm_threshold = communication_mean + 3 * communication_std
    abnormal_communications = ip_communication_table[ip_communication_table['Count'] > abnormal_comm_threshold]
    if not abnormal_communications.empty:
        anomalies.append("\nAbnormal Number of Communications Detected:")
        for _, row in abnormal_communications.iterrows():
            anomalies.append(f" - {row['src_ip']} -> {row['dst_ip']} has {row['Count']} packets.")
    else:
        anomalies.append("\nNo abnormal number of communications detected.")

    return "\n".join(anomalies)

def print_results(total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols, shortest_paths, potential_port_scanners, anomalies):
    if total_bandwidth < 10**9:
        bandwidth_unit = "Mbps"
        total_bandwidth /= 10**6
    else:
        bandwidth_unit = "Gbps"
        total_bandwidth /= 10**9

    results = []
    results.append(f"Total bandwidth used: {total_bandwidth:.2f} {bandwidth_unit}")
    results.append("\nProtocol Distribution:\n")
    results.append(tabulate(protocol_counts_df, headers=["Protocol", "Count", "Percentage"], tablefmt="grid", showindex=False))
    results.append("\nTop IP Address Communications:\n")
    results.append(tabulate(ip_communication_table, headers=["Source IP", "Destination IP", "Count", "Percentage"], tablefmt="grid", floatfmt=".2f", showindex=False))
    results.append("\nShare of each protocol between IPs:\n")
    results.append(tabulate(ip_communication_protocols, headers=["Source IP", "Destination IP", "Protocol", "Count", "Percentage"], tablefmt="grid", floatfmt=".2f", showindex=False))

    sorted_shortest_paths = sorted(
        ((source_ip, target_ip, path, path_length) 
         for (source_ip, target_ip), (path, path_length) in shortest_paths.items()),
        key=lambda x: x[3] if x[3] is not None else float('inf')
    )

    results.append("\nShortest Paths Between All IPs (Sorted by Length):")
    for source_ip, target_ip, path, path_length in sorted_shortest_paths:
        if path is None:
            results.append(f"No path found between {source_ip} and {target_ip}.")
        else:
            if isinstance(path, list):
                results.append(f"From {source_ip} to {target_ip}: {' -> '.join(path)} (Length: {path_length})")

    results.append("\nPotential Port Scanning Detected from IP Addresses:")
    if len(potential_port_scanners) > 0:
        results.append(", ".join(potential_port_scanners))
    else:
        results.append("None detected.")

    results.append("\nAnomaly Detection Results:")
    results.append(anomalies)
        
    return "\n".join(results)

def main(pcap_file, port_scan_threshold):
    packets = read_pcap(pcap_file)
    df = extract_packet_data(packets)
    total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols = analyze_packet_data(df)
    network_graph = build_network_graph(df)
    shortest_paths = compute_all_shortest_paths(network_graph)

    # Extract security-related data
    df_security = extract_packet_data_security(packets)
    potential_port_scanners = detect_port_scanning(df_security, port_scan_threshold)

    # Perform Anomaly Detection
    anomalies = detect_anomalies(df, protocol_counts, ip_communication_table)

    # Prepare results for display
    results = print_results(total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols, shortest_paths, potential_port_scanners, anomalies)
    
    # Collect dataframes for export
    export_data = {
        "Protocol Counts": protocol_counts,
        "IP Communications": ip_communication_table,
        "IP Communication Protocols": ip_communication_protocols,
        "Potential Port Scanners": pd.DataFrame(potential_port_scanners, columns=['Potential Port Scanners']),
        "Anomalies": anomalies
    }

    return results, export_data

# Tkinter GUI Application
class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")

        self.pcap_file = ""
        self.port_scan_threshold = 100
        self.export_data = None  # To store data for export

        # PCAP file selection
        self.label_file = tk.Label(root, text="PCAP File:")
        self.label_file.pack(pady=5)

        self.entry_file = tk.Entry(root, width=50)
        self.entry_file.pack(pady=5)

        self.button_browse = tk.Button(root, text="Browse", command=self.browse_file)
        self.button_browse.pack(pady=5)

        # Port scan threshold input
        self.label_threshold = tk.Label(root, text="Port Scan Threshold:")
        self.label_threshold.pack(pady=5)

        self.entry_threshold = tk.Entry(root)
        self.entry_threshold.insert(0, str(self.port_scan_threshold))
        self.entry_threshold.pack(pady=5)

        # Analyze button
        self.button_analyze = tk.Button(root, text="Analyze", command=self.analyze_packets)
        self.button_analyze.pack(pady=5)

        # Export button (initially disabled)
        self.button_export = tk.Button(root, text="Export Results", command=self.export_results, state=tk.DISABLED)
        self.button_export.pack(pady=5)

        # Result area
        self.result_area = scrolledtext.ScrolledText(root, width=120, height=50)  # Increased size
        self.result_area.pack(pady=5)

    def browse_file(self):
        self.pcap_file = filedialog.askopenfilename(filetypes=[("PCAP files", ".pcap;.pcapng")])
        self.entry_file.delete(0, tk.END)
        self.entry_file.insert(0, self.pcap_file)

    def analyze_packets(self):
        if not self.pcap_file:
            self.result_area.delete(1.0, tk.END)
            self.result_area.insert(tk.END, "Please select a PCAP file to analyze.")
            return
        try:
            self.port_scan_threshold = int(self.entry_threshold.get())
        except ValueError:
            self.result_area.delete(1.0, tk.END)
            self.result_area.insert(tk.END, "Port Scan Threshold must be an integer.")
            return

        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, "Analyzing packets...\n")
        self.root.update_idletasks()

        try:
            results, export_data = main(self.pcap_file, self.port_scan_threshold)
            self.result_area.insert(tk.END, results)
            self.export_data = export_data
            self.button_export.config(state=tk.NORMAL)  # Enable export button
        except Exception as e:
            self.result_area.insert(tk.END, f"An error occurred during analysis: {e}")

    def export_results(self):
        if not self.export_data:
            messagebox.showwarning("Export Warning", "No analysis data available to export.")
            return

        # Prompt user to select a directory to save CSV files
        export_dir = filedialog.askdirectory(title="Select Directory to Save CSV Files")
        if not export_dir:
            return  # User cancelled

        try:
            # Export Protocol Counts
            protocol_counts = self.export_data.get("Protocol Counts")
            protocol_counts.to_csv(os.path.join(export_dir, "protocol_counts.csv"), index=True)
            
            # Export IP Communications
            ip_comms = self.export_data.get("IP Communications")
            ip_comms.to_csv(os.path.join(export_dir, "ip_communications.csv"), index=False)
            
            # Export IP Communication Protocols
            ip_comm_protocols = self.export_data.get("IP Communication Protocols")
            ip_comm_protocols.to_csv(os.path.join(export_dir, "ip_communication_protocols.csv"), index=False)
            
            # Export Potential Port Scanners
            port_scanners = self.export_data.get("Potential Port Scanners")
            port_scanners.to_csv(os.path.join(export_dir, "potential_port_scanners.csv"), index=False)
            
            # Export Anomalies
            anomalies = self.export_data.get("Anomalies")
            with open(os.path.join(export_dir, "anomalies.txt"), "w") as f:
                f.write(anomalies)
            
            messagebox.showinfo("Export Success", f"Analysis results exported successfully to {export_dir}")
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred during export: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
