# 🚀 Network Traffic Anomaly Detector  

A real-time **network monitoring tool** that detects **unusual traffic patterns** and potential threats.  

## 📌 Overview  
This tool captures network packets, extracts key features, and identifies anomalies based on statistical thresholds. It includes a **user-friendly GUI** that displays real-time alerts and logs detected threats.  

## 🛠️ Technologies Used  
- **Python** – Tkinter (GUI), Scapy (packet sniffing), Joblib (data processing)  
- **Networking** – Real-time packet capture & analysis  
- **Data Processing** – Anomaly detection using statistical methods  

## 🚀 Features  
✅ **Real-time Packet Capture** – Monitors incoming & outgoing traffic  
✅ **Anomaly Detection** – Flags unusually large packets as potential threats  
✅ **User-Friendly GUI** – Displays alerts with severity levels (Low, Medium, High)  
✅ **Threat Logging** – Saves anomalous activity to a log file  

## 🖥️ Screenshots  
*(Add screenshots of the GUI in action)*  

## Example Logs Outputs
⚠️ [HIGH] Anomaly Detected! Large packet from 192.168.1.10 to 8.8.8.8 (Size: 1200)
This could indicate an attack or abnormal network behavior. Please investigate further.

## 📂 Installation & Usage  

### 1️⃣ Install Dependencies  
Ensure you have Python installed, then run:  
```bash
pip install scapy joblib

