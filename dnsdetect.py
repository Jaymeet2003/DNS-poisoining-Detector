import sys
import scapy.all as scapy
import time
from collections import defaultdict

# Dictionary to track DNS responses per transaction ID
dns_responses = defaultdict(list)
# Lists to maintain identified legitimate and malicious IPs
legitimate_ips_list = []
malicious_ips_list = []

# Function to log detected attacks for multiple queries to a file
def log_dns_attacks(detected_attacks):
    # Timestamp each log entry with the current date and time
    log_entry = f"{time.strftime('%B %d %Y %H:%M:%S')} \n"
    
    # Process each detected attack to format the output
    for tx_id, query, malicious_ips, legitimate_ips in detected_attacks:
        # Convert "0" IPs to "NONE" for both legitimate and malicious IP lists
        legitimate_ips = ["NONE" if ip == '0' else ip for ip in legitimate_ips]
        malicious_ips = ["NONE" if ip == '0' else ip for ip in malicious_ips]
        
        # Format the log entry with the transaction ID, query, and detected IPs
        log_entry += (
            f"TXID: {tx_id:x}, Query: {query}\n"
            f"Legitimate IPs: [{', '.join(legitimate_ips)}]\n"
            f"Malicious IPs: [{', '.join(malicious_ips)}]\n\n"
        )
    
    # Append each log entry to the attack_log.txt file
    with open("attack_log.txt", "a") as f:
        f.write(log_entry)

# Function to inspect each DNS packet for spoofing attacks
def inspect_dns(packet):
    detected_attacks = []  # List to store detected attacks for batch logging

    # Check if the packet is a DNS response
    if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 1:
        # Extract transaction ID, query name, and response IP
        dns_id = packet[scapy.DNS].id
        query_name = packet[scapy.DNS].qd.qname.decode() if packet[scapy.DNS].qd else None
        response_ip = packet[scapy.DNSRR].rdata if scapy.DNSRR in packet else '0'

        # Drop packet if the response IP is already identified as malicious
        if response_ip in malicious_ips_list:
            print(f"Malicious IP {response_ip} detected. Dropping packet.")
            return  # Exit function to drop packet

        # Track responses for each transaction ID
        if response_ip:
            dns_responses[dns_id].append(response_ip)

        # Process responses based on the count of responses for this transaction ID
        response_count = len(dns_responses[dns_id])

        if response_count == 1:
            # If only one response, mark it as legitimate
            legitimate_ips = []
            for ip in dns_responses[dns_id]:
                legitimate_ips.append("NONE" if ip == '0' else ip)
            print(f"Single response detected. Trusted IPs: {legitimate_ips}")

        elif response_count == 2:
            # For two responses, trust the first as legitimate and flag the second as malicious
            legitimate_ips = ["NONE" if dns_responses[dns_id][0] == '0' else dns_responses[dns_id][0]]
            malicious_ips = [ip for ip in dns_responses[dns_id] if ip != legitimate_ips[0]]

            # Log if any malicious IPs are detected
            if malicious_ips:
                detected_attacks.append((dns_id, query_name, malicious_ips, legitimate_ips))

        elif response_count > 2:
            # If more than two responses, identify the most and least common IPs
            ip_count = {ip: dns_responses[dns_id].count(ip) for ip in dns_responses[dns_id]}
            max_count = max(ip_count.values())
            legitimate_ips = [ip for ip, count in ip_count.items() if count == 1 and ip not in legitimate_ips_list]
            malicious_ips = [ip for ip, count in ip_count.items() if count == max_count and ip not in malicious_ips_list]

            # Ensure legitimate and malicious IP lists are exclusive
            malicious_ips = [ip for ip in malicious_ips if ip not in legitimate_ips]

            # Log detected attacks if malicious IPs are present
            if malicious_ips:
                legitimate_ips_list.extend([ip for ip in legitimate_ips if ip not in legitimate_ips_list])
                malicious_ips_list.extend([ip for ip in malicious_ips if ip not in malicious_ips_list])
                detected_attacks.append((dns_id, query_name, malicious_ips_list, legitimate_ips_list))

            # Clear responses after processing for the current transaction ID
            del dns_responses[dns_id]

    # Log all detected attacks in one batch
    if detected_attacks:
        log_dns_attacks(detected_attacks)

# Main program to handle command-line inputs and initialize sniffing
if __name__ == "__main__":
    # Default interface and tracefile
    interface = "en0"
    tracefile = None

    # Parse command-line arguments
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == "-i" and i + 1 < len(sys.argv):
            interface = sys.argv[i + 1]
        elif sys.argv[i] == "-r" and i + 1 < len(sys.argv):
            tracefile = sys.argv[i + 1]

    # Use the first available network interface if none specified
    if interface is None:
        available_interfaces = scapy.get_if_list()
        if available_interfaces:
            interface = available_interfaces[0]
        else:
            print("No network interface found.")
            sys.exit(1)

    print(f"Running DNS spoof detection on interface: {interface}")

    # If a tracefile is specified, analyze packets from the file
    if tracefile:
        print(f"Analyzing packets from trace file: {tracefile}")
        scapy.sniff(offline=tracefile, prn=inspect_dns, store=False)
        print("Finished processing trace file. Starting live sniffing...")

    # Begin live sniffing if no tracefile or after tracefile analysis
    else: 
        local_ip = scapy.get_if_addr(interface)
        scapy.sniff(
            iface=interface,
            filter=f"udp port 53 and ip",
            prn=inspect_dns,
            store=False
        )
