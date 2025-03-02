# 🚀 Network Traffic Anomaly Detector

A real-time **network monitoring tool** that detects unusual traffic patterns and potential threats. It captures packets, analyzes their sizes, and alerts the user when anomalies are detected.

---

## 📌 Features
✅ **Live Network Packet Capture** – Uses Scapy for real-time monitoring.  
✅ **Threat Alerts** – Provides alerts with severity levels (Low, Medium, High).  
✅ **User-Friendly GUI** – Built with Tkinter for easy interaction.  
✅ **Logging System** – Saves detected anomalies for analysis.  

---

## 🛠️ Installation & Setup

### 🔹 Prerequisites
Ensure you have the following installed:
- **Python 3.x** ([Download Here](https://www.python.org/downloads/))
- **Git** ([Download Here](https://git-scm.com/downloads))
- **Required Python Libraries**

### 🔹 Installation Steps

1️⃣ **Clone the Repository**  
```sh
git clone https://github.com/adamharith73/network-anomaly-detector.git
cd network-anomaly-detector
```

2️⃣ **Install Dependencies**  
```sh
pip install -r requirements.txt
```

3️⃣ **Run the Application**  
```sh
python main.py
```

---

## 🚀 How to Use

1️⃣ **Start the Capture**  
   - Click **"▶ Start Capture"** to begin monitoring network traffic.  
   
2️⃣ **Detect Anomalies**  
   - The app will log packets and highlight potential threats.  
   - Alerts will indicate severity levels:
     - 🟡 **Low** – Slightly unusual activity.  
     - 🟠 **Medium** – Suspicious behavior detected.  
     - 🔴 **High** – Possible attack, requires immediate attention.  

3️⃣ **Stop Capture & Analyze Logs**  
   - Click **"⏹ Stop Capture"** to end monitoring.  
   - View the saved logs in `anomaly_log.txt` for analysis.  

---

## ⚡ Future Enhancements
🔹 Machine Learning integration for smarter threat detection.  
🔹 Graphical visualization of network traffic.  
🔹 IP reputation check to validate suspicious connections.  

---

### 🔗 Contributing & Support
Want to improve this project? Feel free to contribute!  
For issues or suggestions, create a GitHub **Issue** or **Pull Request**.  

---

### 📜 License
This project is licensed under the **MIT License**.


