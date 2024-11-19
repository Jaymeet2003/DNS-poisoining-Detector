
# DNS Spoof Detection Tool

## Overview
This tool is designed to sniff DNS traffic on a specified network interface and detect DNS spoofing attacks by analyzing DNS responses. The tool tracks legitimate and malicious IPs per DNS transaction and logs suspicious activity.

**Disclaimer**: This code is for educational and security research purposes only. Unauthorized use is illegal and unethical.

## Prerequisites
- Python 3.5 or above
- Scapy library (install with `pip install scapy`)

## Usage
### Command-line Arguments
- `-i <interface>`: Specifies the network interface to use for sniffing. Default is `en0`.
- `-r <tracefile>`: Specifies a pcap file to analyze instead of live traffic.

### Running the Program
To run the script on a live interface:
```bash
python dns_spoof_detector.py [-i interface]
```

To analyze a pcap file:
```bash
python dns_spoof_detector.py -r <tracefile>
```

### Example
To run the script using interface `en0`:
```bash
python dns_spoof_detector.py -i en0
```

To analyze packets from `capture.pcap`:
```bash
python dns_spoof_detector.py -r capture.pcap
```

## How It Works
1. The tool monitors DNS traffic for responses and tracks each DNS transaction by ID.
2. Legitimate IPs are identified from initial DNS responses, while subsequent differing IPs are flagged as potentially malicious.
3. Detected spoofing attempts are logged to `attack_log.txt` with timestamps and details of legitimate and malicious IPs.

### Detection Logic:
- **Single Response**: Marked as legitimate.
- **Two Responses**: The first is considered legitimate; any differing IPs are flagged as malicious.
- **Multiple Responses**: The most common IP is flagged as legitimate, others as malicious.

## Log File
The `attack_log.txt` file records:
- Timestamp of detection
- Transaction ID
- Queried domain
- List of legitimate and malicious IPs

## Important Notes
- Ensure you have the necessary permissions to run this script (root/admin).
- Use responsibly and in compliance with all applicable laws and ethical guidelines.

## License
This tool is provided as-is with no warranty. It is intended for educational purposes only.
