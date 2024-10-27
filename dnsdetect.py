import sys
import scapy.all as scapy
from datetime import datetime, timedelta
from collections import defaultdict


# Get list of network interfaces available on the system
ip = scapy.get_if_list()
print(ip)

# Default settings
interface = "wlan0" 

# Initialize a dictionary to track DNS responses for each domain and TxID
dns_cache = defaultdict(list)
cache_timeout = timedelta(minutes=5)  # Define a cache timeout for entries

def handle_dns_packet(packet):
    if scapy.DNS in packet:
        dns_layer = packet[scapy.DNS]

        packet.show()
        if dns_layer.qr == 1:
            txid = dns_layer.id
            domain = dns_layer.qd.qname.decode().rstrip('.')


            response_ips = []
            ttl_value = None
            src_ip = packet[scapy.IP].src

            for i in range(dns_layer.ancount):
                dns_response = dns_layer.an[i]
                if isinstance(dns_response, scapy.DNSRR) and dns_response.type == 1:  # type of response and  A record (IPv4)
                    response_ips.append(dns_response.rdata)
                    ttl_value = dns_response.ttl
            # Detect potential spoofing
            # detect_spoofing(txid, domain, response_ips, ttl_value, src_ip, dns_layer)


def detect_spoofing(txid, domain, response_ips, ttl_value, source_ip, dns_layer):
    """Detects spoofing based on IP, TTL, and DNS flag mismatches for the same TxID and domain."""
    # Cache cleanup: Remove entries older than cache_timeout
    current_time = datetime.now()
    dns_cache[(txid, domain)] = [(entry[0], entry[1], entry[2]) for entry in dns_cache[(txid, domain)]
                                 if current_time - entry[2] < cache_timeout]

    existing_responses = dns_cache[(txid, domain)]
    
    # Extract DNS flags and counts
    answer_count = dns_layer.ancount
    ns_count = dns_layer.nscount
    is_authoritative = dns_layer.aa  # Authoritative Answer flag

    print(answer_count,ns_count,is_authoritative)

    # Check for suspicious flag combinations
    if (answer_count == 0 and is_authoritative == 1 and ns_count == 1) or \
       (answer_count > 0 and is_authoritative == 1 and ns_count > 0):
        
        print("here")
        # Flag as spoofed if these flag combinations are present
        log_attack(txid, domain, [], response_ips, ttl_value, [source_ip])
        print(f"[ALERT] Suspicious DNS flag combination detected for {domain} with TXID {txid}. Check 'answer.txt' for details.")
        return  # Exit early since we've detected a spoofed response

    # Check for TTL consistency across responses for the same domain and TxID
    if existing_responses:
        legit_ips, legit_ttl, legit_source_ip = existing_responses[0]

        # Check for IP or TTL mismatches
        if set(response_ips) != set(legit_ips) or ttl_value != legit_ttl:
            spoofed_ips = response_ips
            source_ips = [source_ip, legit_source_ip]  # List of detected source IPs
            # Log potential DNS poisoning
            log_attack(txid, domain, legit_ips, spoofed_ips, ttl_value, source_ips)
            print(f"[ALERT] DNS Spoofing detected for {domain} with TXID {txid}. Check 'attack.txt' for details.")
    else:
        # No previous response, treat this as the first legitimate response
        dns_cache[(txid, domain)].append((response_ips, ttl_value, source_ip))
        print(dns_cache)





def log_attack(txid, domain, legit_ips, spoofed_ips, spoofed_ttl, src_ips):
    """Logs a DNS poisoning attack to a file."""

    print("logging")
    with open('attack_log.txt', 'a') as f:
        f.write(f"\n{datetime.now().strftime('%B %d %Y %H:%M:%S')}\n")
        f.write(f"TXID 0x{txid:04x} Request {domain}\n")
        f.write(f"Answer1 [Legitimate IPs: {', '.join(legit_ips)}]\n")
        f.write(f"Answer2 [Spoofed IPs: {', '.join(spoofed_ips)}]\n")
        f.write(f"Spoofed TTL: {spoofed_ttl}\n")
        f.write("-" * 50 + "\n")

# Function to load the hostname file if provided
def load_tracefile(tracefile):
    """
    Loads a hostname file containing IP-hostname pairs.
    """
    print(f"Reading packets from tracefile {tracefile} for DNS poisoning detection...")
    packets = scapy.rdpcap(tracefile)
    for packet in packets:
        handle_dns_packet(packet)
        # pass

# Function to start sniffing packets from an interface
def sniff_interface(interface):
    print(f"Sniffing on interface {interface} for DNS poisoning detection...")
    scapy.sniff(iface=interface, filter="ip and udp port 53", prn=handle_dns_packet)


def parse_args():
    """
    Parses command-line arguments to get the network interface to sniff on and the hostname file.
    """
    global interface

    if len(sys.argv) > 3 or len(sys.argv) > 5:
        print("Usage: dnsinjector.py [-i interface] [-h hostnames]")
        sys.exit(1)
    if "-r" not in sys.argv:
        sniff_interface(interface)
    else:
        for i in range(1, len(sys.argv)):
            if sys.argv[i] == "-i":  # Interface argument
                interface = sys.argv[i + 1]
            elif sys.argv[i] == "-r":  # Hostname file argument
                trace_file = sys.argv[i + 1]
                load_tracefile(trace_file)


# Main program entry point
if __name__ == "__main__":
    dns_cache.clear()
    parse_args()