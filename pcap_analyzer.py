from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS
from collections import Counter, defaultdict
import sys
import os

#port numbers and their service names
port_names = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

def get_ip_addresses(packet):
    #IPv4
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    #IPv6
    elif IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return None, None

def is_tcp_syn(packet):
    #checking for initial TCP SYN packet
    if TCP not in packet:
        return False

    flags = packet[TCP].flags
    return bool(flags & 0x02) and not bool(flags & 0x10)

def is_tcp_syn_ack(packet):
    #checking for TCP SYN-ACK packet
    if TCP not in packet:
        return False

    flags = packet[TCP].flags
    return bool(flags & 0x02) and bool(flags & 0x10)

def is_tcp_rst(packet):
    #checking for TCP reset packet
    if TCP not in packet:
        return False

    flags = packet[TCP].flags
    return bool(flags & 0x04)

def get_tcp_payload(packet):
    #getting raw TCP payload
    if TCP in packet:
        return bytes(packet[TCP].payload)

    return b""

def detect_tls_heartbeat(packet):
    #generic TLS heartbeat detection
    if TCP not in packet:
        return None

    payload = get_tcp_payload(packet)

    #minimum TLS record size
    if len(payload) < 6:
        return None

    #TLS heartbeat record type is 24
    if payload[0] != 0x18:
        return None

    #supported TLS versions
    tls_versions = {
        b"\x03\x00",
        b"\x03\x01",
        b"\x03\x02",
        b"\x03\x03"
    }

    if payload[1:3] not in tls_versions:
        return None

    heartbeat = payload[5:]

    if len(heartbeat) < 3:
        return None

    heartbeat_type = heartbeat[0]
    claimed_length = int.from_bytes(heartbeat[1:3], "big")
    actual_length = max(0, len(heartbeat) - 3)

    #heartbeat request
    if heartbeat_type == 1:
        if claimed_length > actual_length:
            return {
                "type": "Malformed TLS Heartbeat",
                "claimed": claimed_length,
                "actual": actual_length
            }

        return {
            "type": "TLS Heartbeat Request",
            "claimed": claimed_length,
            "actual": actual_length
        }

    #heartbeat response
    if heartbeat_type == 2:
        return {
            "type": "TLS Heartbeat Response",
            "claimed": claimed_length,
            "actual": actual_length
        }

    return None

def analyze_pcap(filename):
    print("============================================================")
    print("PCAP SECURITY ANALYZER")
    print("============================================================")

    if not os.path.exists(filename):
        print(f"\n[ERROR] File not found: {filename}")
        return

    print(f"\nReading PCAP file: {filename}")

    try:
        packets = rdpcap(filename)
    except Exception as e:
        print(f"[ERROR] Could not read PCAP file: {e}")
        return

    print(f"Total packets: {len(packets)}")

    #counters for traffic analysis
    protocols = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    source_ports = Counter()
    destination_ports = Counter()
    conversations = Counter()
    dns_queries = Counter()

    #counters for TCP analysis
    syn_attempts = defaultdict(int)
    syn_ack_responses = defaultdict(int)
    rst_packets = defaultdict(int)
    scan_ports = defaultdict(set)

    #counters for traffic volume
    bytes_sent = Counter()
    bytes_received = Counter()

    #counters for TLS analysis
    tls_heartbeat_requests = defaultdict(int)
    tls_heartbeat_responses = defaultdict(int)
    malformed_heartbeats = defaultdict(int)

    packet_bytes = 0

    #packet type counters
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    dns_count = 0

    #analyze every packet
    for packet in packets:
        packet_bytes += len(packet)

        src_ip, dst_ip = get_ip_addresses(packet)

        #ignore packets without IP addresses
        if src_ip is None:
            continue

        source_ips[src_ip] += 1
        destination_ips[dst_ip] += 1

        #TCP
        if TCP in packet:
            protocols["TCP"] += 1
            tcp_count += 1

            sport = packet[TCP].sport
            dport = packet[TCP].dport

            source_ports[sport] += 1
            destination_ports[dport] += 1

            conversations[(src_ip, dst_ip, sport, dport, "TCP")] += 1
            bytes_sent[src_ip] += len(packet)

            #TCP SYN
            if is_tcp_syn(packet):
                key = (src_ip, dst_ip)
                syn_attempts[key] += 1
                scan_ports[key].add(dport)

            #TCP SYN-ACK
            if is_tcp_syn_ack(packet):
                key = (dst_ip, src_ip)
                syn_ack_responses[key] += 1

            #TCP RST
            if is_tcp_rst(packet):
                key = (dst_ip, src_ip)
                rst_packets[key] += 1

            #TLS heartbeat analysis
            heartbeat = detect_tls_heartbeat(packet)

            if heartbeat:
                key = (src_ip, dst_ip, dport)

                if heartbeat["type"] == "Malformed TLS Heartbeat":
                    malformed_heartbeats[key] += 1

                elif heartbeat["type"] == "TLS Heartbeat Request":
                    tls_heartbeat_requests[key] += 1

                elif heartbeat["type"] == "TLS Heartbeat Response":
                    tls_heartbeat_responses[key] += 1

        #UDP
        elif UDP in packet:
            protocols["UDP"] += 1
            udp_count += 1

            sport = packet[UDP].sport
            dport = packet[UDP].dport

            source_ports[sport] += 1
            destination_ports[dport] += 1

            conversations[(src_ip, dst_ip, sport, dport, "UDP")] += 1
            bytes_sent[src_ip] += len(packet)

        #ICMP
        elif ICMP in packet:
            protocols["ICMP"] += 1
            icmp_count += 1
            bytes_sent[src_ip] += len(packet)

        #other IP traffic
        else:
            protocols["Other"] += 1
            bytes_sent[src_ip] += len(packet)

        #DNS
        if DNS in packet:
            dns_count += 1
            protocols["DNS"] += 1

            if packet[DNS].qd is not None:
                try:
                    query = packet[DNS].qd.qname.decode("utf-8", errors="ignore")
                    dns_queries[query] += 1
                except Exception:
                    pass

    #display traffic summary
    print("\n------------------------------------------------------------")
    print("TRAFFIC SUMMARY")
    print("------------------------------------------------------------")
    print(f"Total Packets : {len(packets)}")
    print(f"Total Bytes   : {packet_bytes}")
    print(f"TCP Packets   : {tcp_count}")
    print(f"UDP Packets   : {udp_count}")
    print(f"ICMP Packets  : {icmp_count}")
    print(f"DNS Packets   : {dns_count}")

    #protocol statistics
    print("\n------------------------------------------------------------")
    print("PROTOCOL DISTRIBUTION")
    print("------------------------------------------------------------")

    for protocol, count in protocols.most_common():
        percentage = (count / len(packets)) * 100
        print(f"{protocol:<10} {count:<10} {percentage:.2f}%")

    #top source IPs
    print("\n------------------------------------------------------------")
    print("TOP SOURCE IP ADDRESSES")
    print("------------------------------------------------------------")

    for ip, count in source_ips.most_common(10):
        print(f"{ip:<40} {count} packets")

    #top destination IPs
    print("\n------------------------------------------------------------")
    print("TOP DESTINATION IP ADDRESSES")
    print("------------------------------------------------------------")

    for ip, count in destination_ips.most_common(10):
        print(f"{ip:<40} {count} packets")

    #top destination ports
    print("\n------------------------------------------------------------")
    print("TOP DESTINATION PORTS")
    print("------------------------------------------------------------")

    for port, count in destination_ports.most_common(15):
        name = port_names.get(port, "Unknown")
        print(f"Port {port:<5} {name:<10} {count} packets")

    #DNS queries
    print("\n------------------------------------------------------------")
    print("DNS QUERIES")
    print("------------------------------------------------------------")

    if dns_queries:
        for domain, count in dns_queries.most_common(20):
            print(f"{domain:<50} {count}")
    else:
        print("No DNS queries found.")

    #top conversations
    print("\n------------------------------------------------------------")
    print("TOP NETWORK CONVERSATIONS")
    print("------------------------------------------------------------")

    for conversation, count in conversations.most_common(10):
        src, dst, sport, dport, protocol = conversation
        print(f"{src}:{sport} -> {dst}:{dport} [{protocol}] {count} packets")

    #security findings
    print("\n------------------------------------------------------------")
    print("SECURITY FINDINGS")
    print("------------------------------------------------------------")

    findings = []

    #TCP port scanning
    for key, ports in scan_ports.items():
        scanner, target = key
        syn_count = syn_attempts[key]
        unique_ports = len(ports)
        syn_ack_count = syn_ack_responses.get(key, 0)
        rst_count = rst_packets.get(key, 0)

        if unique_ports >= 20 and syn_count >= 20:

            if unique_ports >= 50:
                confidence = "HIGH"
                severity = "HIGH"
            elif unique_ports >= 30:
                confidence = "MEDIUM"
                severity = "MEDIUM"
            else:
                confidence = "LOW"
                severity = "MEDIUM"

            print("\n[1] POSSIBLE TCP PORT SCAN")
            print("------------------------------------------------------------")
            print("Classification : LIKELY SUSPICIOUS")
            print(f"Severity       : {severity}")
            print(f"Confidence     : {confidence}")
            print(f"Source IP      : {scanner}")
            print(f"Target IP      : {target}")
            print(f"Unique Ports   : {unique_ports}")
            print(f"SYN Attempts   : {syn_count}")
            print(f"SYN-ACK Replies: {syn_ack_count}")
            print(f"RST Packets    : {rst_count}")
            print("Evidence       : Multiple TCP SYN attempts were sent to different destination ports.")
            print("Assessment     : Traffic pattern is consistent with TCP port scanning.")

            findings.append({
                "type": "Port Scan",
                "severity": severity
            })

    #TCP SYN Flood
    for key, count in syn_attempts.items():
        source, target = key

        if count >= 100:
            print("\n[TCP SYN ANOMALY]")
            print("------------------------------------------------------------")
            print("Classification : SUSPICIOUS")
            print("Severity       : HIGH")
            print("Confidence     : MEDIUM")
            print(f"Source IP      : {source}")
            print(f"Target IP      : {target}")
            print(f"SYN Attempts   : {count}")
            print("Evidence       : Large number of TCP SYN packets observed.")
            print("Assessment     : Activity may indicate connection flooding or abnormal scanning.")

            findings.append({
                "type": "SYN Anomaly",
                "severity": "HIGH"
            })

    #TLS HEARTBEAT
    for key, count in malformed_heartbeats.items():
        attacker, victim, port = key

        print("\n[TLS HEARTBEAT ANOMALY]")
        print("------------------------------------------------------------")
        print("Classification : SUSPICIOUS")
        print("Severity       : HIGH")
        print("Confidence     : HIGH")
        print(f"Source IP      : {attacker}")
        print(f"Destination IP : {victim}")
        print(f"Destination Port: {port}")
        print(f"Malformed Requests: {count}")
        print("Evidence       : TLS heartbeat request contains a claimed payload length larger than the available payload.")
        print("Assessment     : Traffic may indicate a Heartbleed-style memory disclosure attempt.")
        print("Reference      : CVE-2014-0160")

        findings.append({
            "type": "TLS Heartbeat Anomaly",
            "severity": "HIGH"
        })

    #suspiciois services
    suspicious_ports = {
        21: "FTP",
        23: "Telnet",
        445: "SMB",
        3389: "RDP"
    }

    for port, service in suspicious_ports.items():
        count = destination_ports[port]

        if count > 0:
            print(f"\n[SUSPICIOUS SERVICE] {service}")
            print("------------------------------------------------------------")
            print("Classification : INFORMATIONAL")
            print("Severity       : LOW")
            print("Confidence     : MEDIUM")
            print(f"Destination Port: {port}")
            print(f"Packets        : {count}")
            print(f"Evidence       : {service} traffic was observed in the capture.")
            print("Assessment     : The service may require review, but its presence alone does not prove malicious activity.")

            findings.append({
                "type": "Suspicious Service",
                "severity": "LOW"
            })

    if dns_count > 0:

        print("\n[DNS ACTIVITY]")
        print("------------------------------------------------------------")
        print("Classification : INFORMATIONAL")
        print("Severity       : LOW")
        print("Confidence     : HIGH")
        print(f"DNS Packets    : {dns_count}")
        print(f"Unique Queries : {len(dns_queries)}")
        print("Evidence       : DNS queries were detected in the network traffic.")
        print("Assessment     : DNS activity is not considered malicious without additional suspicious indicators.")

    if bytes_sent:
        total_outbound = sum(bytes_sent.values())

        for ip, amount in bytes_sent.most_common(5):
            percentage = (amount / total_outbound) * 100

            if percentage >= 60 and total_outbound > 1000000:

                print("\n[HIGH TRAFFIC SOURCE]")
                print("------------------------------------------------------------")
                print("Classification : SUSPICIOUS")
                print("Severity       : MEDIUM")
                print("Confidence     : LOW")
                print(f"Source IP      : {ip}")
                print(f"Traffic        : {amount} bytes")
                print(f"Traffic Share  : {percentage:.2f}%")
                print("Evidence       : A single host generated a large portion of the observed traffic.")
                print("Assessment     : High traffic volume may require investigation for scanning, transfers, or other abnormal activity.")

                findings.append({
                    "type": "High Traffic",
                    "severity": "MEDIUM"
                })

    print("\n-----------------------------------------------------")
    print("OVERALL ASSESSMENT")
    print("-----------------------------------------------------")

    critical = sum(1 for finding in findings if finding["severity"] == "CRITICAL")
    high = sum(1 for finding in findings if finding["severity"] == "HIGH")
    medium = sum(1 for finding in findings if finding["severity"] == "MEDIUM")
    low = sum(1 for finding in findings if finding["severity"] == "LOW")

    print(f"Total Findings : {len(findings)}")
    print(f"Critical       : {critical}")
    print(f"High           : {high}")
    print(f"Medium         : {medium}")
    print(f"Low            : {low}")

    if critical > 0:
        overall_risk = "CRITICAL"
    elif high > 0:
        overall_risk = "HIGH"
    elif medium > 0:
        overall_risk = "MEDIUM"
    elif low > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "LOW"

    print(f"Overall Risk   : {overall_risk}")

    if len(findings) == 0:
        print("Assessment : No significant suspicious network behavior was detected.")
    else:
        print("Assessment : One or more network behaviors require security review.")

    #analysis complete
    print("\n------------------------------------------------------------")
    print("ANALYSIS COMPLETE")
    print("------------------------------------------------------------")

def main():
    filename = sys.argv[1]
    analyze_pcap(filename)

if __name__ == "__main__":
    main()
