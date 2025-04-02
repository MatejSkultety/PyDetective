import pyshark

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

    return ip_addresses, domain_names, hosts


# Example usage
pcap_file = 'valid_tcpdump.pcap'  # Replace with your .pcap file
ips, domains, hosts = parse_network_artefacts(pcap_file)

print(f"Unique IP addresses in {pcap_file}:")
for ip in ips:
    print(ip)

print(f"\nUnique domain names in {pcap_file}:")
for domain in domains:
    print(domain)

print(f"\nUnique hosts in {pcap_file}:")
for host in hosts:
    print(host)
