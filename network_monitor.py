import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import joblib
import random
import statistics

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Anomaly Detector")
        self.root.geometry("800x500")  # Increased window size for better visibility
        self.root.configure(bg="#1e1e1e")
        
        self.monitoring = False
        self.packet_data = []
        self.threshold = self.load_threshold()
        
        self.create_widgets()
        self.threat_levels = {"low": "#FFD700", "medium": "#FFA500", "high": "#FF0000"}
    
    def create_widgets(self):
        frame = tk.Frame(self.root, padx=10, pady=10, bg="#1e1e1e")
        frame.pack(expand=True, fill=tk.BOTH)
        
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12), padding=5)
        style.configure("TLabel", font=("Arial", 12), background="#1e1e1e", foreground="white")
        
        self.start_button = ttk.Button(frame, text="▶ Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)
        
        self.stop_button = ttk.Button(frame, text="⏹ Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)
        
        self.status_label = ttk.Label(frame, text="Status: ⛔ Stopped", font=("Arial", 14, "bold"))
        self.status_label.grid(row=1, column=0, columnspan=2, pady=10)
        
        self.log_box = tk.Text(frame, height=15, width=90, state=tk.DISABLED, bg="#252526", fg="#00FF00", font=("Courier", 10))
        log_scrollbar = ttk.Scrollbar(frame, command=self.log_box.yview)
        self.log_box.config(yscrollcommand=log_scrollbar.set)
        log_scrollbar.grid(row=2, column=2, sticky='ns')
        self.log_box.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.threat_label = ttk.Label(frame, text="", font=("Arial", 12, "bold"), foreground="red", wraplength=600, justify="center")
        self.threat_label.grid(row=3, column=0, columnspan=2, pady=5)
    
    def load_threshold(self):
        try:
            return joblib.load("anomaly_threshold.pkl")
        except:
            normal_data = [random.randint(50, 500) for _ in range(100)]
            threshold = statistics.mean(normal_data) + (2 * statistics.stdev(normal_data))
            joblib.dump(threshold, "anomaly_threshold.pkl")
            return threshold
    
    def start_capture(self):
        self.monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: ✅ Monitoring", foreground="#00FF00")
        
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        self.monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: ⛔ Stopped", foreground="red")
        self.threat_label.config(text="")
    
    def capture_packets(self):
        def process_packet(packet):
            if self.monitoring:
                features = self.extract_features(packet)
                if features:
                    self.packet_data.append(features)
                    self.log_message(f"Packet: {features}")
                    if features[2] > self.threshold:
                        self.highlight_threat(features)
        
        scapy.sniff(filter="ip or tcp or udp", prn=process_packet, store=False)
    
    def extract_features(self, packet):
        try:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            packet_size = len(packet)
            return [src_ip, dst_ip, packet_size]
        except AttributeError:
            return None
    
    def log_message(self, message):
        self.log_box.config(state=tk.NORMAL)
        self.log_box.insert(tk.END, message + "\n")
        self.log_box.config(state=tk.DISABLED)
        self.log_box.yview(tk.END)
    
    def highlight_threat(self, features):
        severity = "high" if features[2] > self.threshold * 1.5 else "medium" if features[2] > self.threshold else "low"
        alert_message = (
            f"⚠️ [{severity.upper()}] Anomaly Detected! Large packet from {features[0]} to {features[1]} (Size: {features[2]})\n"
            "This could indicate an attack or abnormal network behavior. Please investigate further."
        )
        self.threat_label.config(text=alert_message, foreground=self.threat_levels[severity])
        self.log_message(alert_message)
        self.save_anomaly_log(features)
    
    def save_anomaly_log(self, features):
        with open("anomaly_log.txt", "a") as log_file:
            log_file.write(f"Anomalous Packet - Source: {features[0]}, Destination: {features[1]}, Size: {features[2]}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitor(root)
    root.mainloop()
