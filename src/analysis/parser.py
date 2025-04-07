import pyshark
import json
import re

def parse_network_artefacts(pcap_file):
    ip_addresses = set()  # To store unique IPs
    domain_names = set()  # To store unique domain names
    hosts = set()  # To store unique hosts

    # Open the pcap file using pyshark
    cap = pyshark.FileCapture(pcap_file, display_filter='dns or ip')

    # Iterate through the packets in the pcap file
    for packet in cap:
        # Check if the packet has an IP layer
        if 'IP' in packet:
            # Extract source and destination IP addresses
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Add to the set of IPs
            ip_addresses.add(src_ip)
            ip_addresses.add(dst_ip)

        # Check if the packet has a DNS layer
        if 'DNS' in packet:
            # Extract domain names from DNS queries or responses
            if hasattr(packet.dns, 'qry_name'):  # DNS query name
                domain_names.add(packet.dns.qry_name)

            # Check for CNAME records in DNS responses
            if hasattr(packet.dns, 'cname') and packet.dns.cname:
                domain_names.add(packet.dns.cname)

            # Check for A and AAAA records (IPv4/IPv6) in DNS responses
            if hasattr(packet.dns, 'a') and packet.dns.a:  # A record (IPv4)
                ip_addresses.add(packet.dns.a)

            if hasattr(packet.dns, 'aaaa') and packet.dns.aaaa:  # AAAA record (IPv6)
                ip_addresses.add(packet.dns.aaaa)

        # Extract hosts (base domains) from domain names
        for domain in domain_names:
            # Split the domain name by '.' and get the last two parts (main domain and suffix)
            domain_parts = domain.split('.')
            if len(domain_parts) > 1:
                host = '.'.join(domain_parts[-2:])  # Get last two parts
                hosts.add(host)
    cap.close()

    return ip_addresses, domain_names, hosts


def parse_syscalls_artefacts(json_file):
    """
    Extracts unique file operations from a JSONL file containing Sysdig output.

    Args:
        file_path (str): Path to the JSONL file.

    Returns:
        list: A list of dictionaries, each representing a unique file operation with keys 'operation', 'filename', and 'flag'.
    """
    # Define a set to store unique file operations
    unique_operations = set()

    # Define a regular expression pattern to extract file operations
    # This pattern looks for key-value pairs in the format key=value
    pattern = re.compile(r'(\w+)=([^\s]+)')

    # Open the JSONL file and process it line by line
    with open(json_file, 'r') as file:
        print("PyDetective debug: Parsing syscalls artefacts")
        for line in file:
            # Parse the JSON object from the current line
            try:
                log_entry = json.loads(line)
            except json.JSONDecodeError:
                # Skip lines that are not valid JSON
                continue

            # Extract the 'evt.info' field
            evt_info = log_entry.get('evt.info', '')
            print(evt_info)
            # Parse key-value pairs from 'evt.info'
            parsed_info = dict(pattern.findall(evt_info))

            # Check if the parsed info contains file operation details
            if 'res' in parsed_info and 'data' in parsed_info:
                # Extract operation, filename, and flag
                operation = parsed_info.get('operation', '').lower()
                filename = parsed_info.get('filename', '')
                flag = parsed_info.get('flag', '')

                # Only consider entries with a valid filename
                if filename:
                    # Create a tuple representing the file operation
                    file_operation = (operation, filename, flag)
                    # Add the tuple to the set to ensure uniqueness
                    unique_operations.add(file_operation)

    # Convert the set of tuples back to a list of dictionaries
    file_operations_list = [
        {'operation': op, 'filename': fn, 'flag': fl}
        for op, fn, fl in unique_operations
    ]

    return file_operations_list