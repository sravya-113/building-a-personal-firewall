# 🔐 Personal Firewall (Python + Scapy)

A lightweight Python-based personal firewall that monitors network traffic in real-time and blocks packets based on custom rules for IPs, ports, and protocols.

---

## 📁 Project Structure

personal-firewall/

├── firewall.py # Main firewall script

├── config.json # Block/allow rules

├── logs/

│ └── blocked_traffic.log # Blocked traffic log

├──  Screenshots

  ├── firewall_running.png
  
 ├── blocked_traffic_log.jpg

└── README.md



---

## ⚙️ Setup

1. **Clone the repo**  
   ```bash
   git clone https://github.com/yourusername/personal-firewall.git
   cd personal-firewall
Install requirements


pip install scapy

Update your rules in config.json

Example:


{

  "blocked_ips": ["192.168.1.100"],
  
  "blocked_ports": [22, 445],
  
  "allowed_protocols": ["TCP", "UDP"]
  
}

Run the firewall (as admin/root)


python firewall.py

🧪 Test It

Ping a blocked IP or port using:


curl http://example.com
nslookup google.com 8.8.8.8

Blocked traffic is logged in:

logs/blocked_traffic.log


📸 Screenshots

[firewall running](screenshots/firewall_running.jpg)
