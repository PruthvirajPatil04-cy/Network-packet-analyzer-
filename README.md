# Network Packet Analyzer

Setup:
```bash
pip install -r requirements.txt
```

## Quick health check
```bash
python scratch/smoke.py
```
How to use it:
Create a file named README.md in the root folder of your local project directory (D:\MINDCRAFT\packet-analyzer\).

Paste the content below into that file and save it.

Commit and push it to your GitHub:

Bash
git add README.md
git commit -m "Add README.md"
git push origin main
Markdown
# 🛡️ Network Packet Analyzer

A network packet analysis tool designed to capture, inspect, and analyze network traffic for monitoring, security assessment, and troubleshooting purposes.

## 🚀 Features
- **Packet Capture:** Sniff and capture live network data packets passing through your network interface.
- **Protocol Analysis:** Inspect various network protocols (e.g., TCP, UDP, IP, ICMP, etc.).
- **Detailed Insights:** View packet source/destination IP addresses, ports, payloads, and header details.
- **Lightweight & Efficient:** Built for fast processing and easy terminal-based or graphical evaluation.

---

## 🛠️ Tech Stack
- **Language/Framework:
  **Primary Language
Python 3.11 — the only programming language in the project. Every file (.py) is Python.

Frameworks & Libraries
Category	Name	What it does
Web UI Framework	Streamlit	Powers the entire dashboard — panes, sidebar, tour, refresh loop
Packet Capture Framework	Scapy	Reads real network packets (used in capture.py)
Charting Framework	Plotly (plotly.graph_objects, plotly.express)	Every chart: bar, line, gauge, timeline, heatmap, throughput, flow
Data Framework	Pandas	Packet tables, threat scorecard, CSV export
Testing Framework	Pytest	All 20+ unit tests
AI SDK	Google Antigravity SDK	Gemini-powered alert explanations and the autonomous SOC agent
Concurrency	Python stdlib threading, asyncio	Simulator thread, agent thread, packet buffer lock, async SDK calls
Serialization	Python stdlib json	Alert export, agent decision log
Date/Time	Python stdlib datetime	Timestamps for packets and decisions

- **Environment:** Developed using Antigravity

---

## 📥 Getting Started

### Prerequisites
Make sure you have the following installed on your system:
- Python / Node.js / C++ Compiler (depending on your project stack)
- Npcap / WinPcap (if running packet capturing on Windows) or libpcap (on Linux/macOS)

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/PruthvirajPatil04-cy/Network-packet-analyzer-.git](https://github.com/PruthvirajPatil04-cy/Network-packet-analyzer-.git)
   cd Network-packet-analyzer-
Install dependencies:

Bash
# Example for Python:
pip install -r requirements.txt
Run the application:

Bash
# Example:
python main.py
(Note: Depending on your OS and network permissions, you may need to run the tool with Administrator / sudo privileges to capture live packets).

📌 Usage
Start the tool and select your network interface.

Monitor incoming and outgoing packets in real-time.

Review extracted metrics or generated log reports.

🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

📝 License
This project is open-source and available under the MIT License.
