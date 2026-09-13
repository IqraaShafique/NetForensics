# NetForensics — PCAP Security Analyzer

NetForensics is a Python-based network security tool for analyzing PCAP and PCAPNG files using Scapy. It examines network packets, IP addresses, ports, protocols, DNS activity, TCP connections, and traffic patterns to identify potentially suspicious behavior.
The analyzer includes detection for TCP port scanning, excessive SYN activity, suspicious services, unusual traffic volumes, and TLS heartbeat anomalies. Each finding is presented with relevant source and destination information, evidence, severity, confidence level, and an overall risk assessment.
The project is designed as a lightweight network forensics and security analysis tool that can be used to investigate captured network traffic without requiring live packet capture.

## How to Analyze Your Own PCAP File  ##
1. Clone or download this repository.
2. Install the required Python package:

-> pip install -r requirements.txt

3. Place your `.pcap` or `.pcapng` file in the project folder.
4. Run the analyzer:

-> python pcap_analyzer.py your_file.pcap
