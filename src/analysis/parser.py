import pyshark
import json


def parse_network_artefacts(pcap_file: str, ignored_hosts: list[str] = None, ignored_ips: list[str] = None) -> tuple[set, set, set]:
    """
    Extracts unique IP addresses, domain names, and hosts from a pcap file.
    It uses the pyshark library to read the pcap file and extract relevant information.

    Args:
        pcap_file (str): Path to the pcap file.
        ignored_hosts (list[str], optional): List of hosts to ignore. Defaults to None.
        ignored_ips (list[str], optional): List of IP addresses to ignore. Defaults to None.

    Returns:
        tuple: A tuple containing three sets:
            - IP addresses (set): Unique IP addresses found in the pcap file.
            - Domain names (set): Unique domain names found in the pcap file.
            - Hosts (set): Unique hosts derived from the domain names.
    """
    ip_addresses = set()
    domain_names = set()
    hosts = set()

    cap = pyshark.FileCapture(pcap_file, display_filter='dns or ip')
    for packet in cap:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if ignored_ips and not (src_ip in ignored_ips):
                ip_addresses.add(src_ip)
            if ignored_ips and not (dst_ip in ignored_ips):
                ip_addresses.add(dst_ip)
        if 'DNS' in packet:
            if hasattr(packet.dns, 'qry_name'):
                domain_names.add(packet.dns.qry_name)
            if hasattr(packet.dns, 'cname') and packet.dns.cname:
                domain_names.add(packet.dns.cname)
            # Check for A and AAAA records (IPv4/IPv6) in DNS responses
            if hasattr(packet.dns, 'a') and packet.dns.a:  # A record (IPv4)
                ip_addresses.add(packet.dns.a)
            if hasattr(packet.dns, 'aaaa') and packet.dns.aaaa:  # AAAA record (IPv6)
                ip_addresses.add(packet.dns.aaaa)
        for domain in domain_names:
            domain_parts = domain.split('.')
            if len(domain_parts) > 1:
                host = '.'.join(domain_parts[-2:])  # Get last two parts
                if ignored_hosts and not (host in ignored_hosts):
                    hosts.add(host)
    cap.close()
    return ip_addresses, domain_names, hosts


def parse_syscalls_artefacts(json_path: str) -> list:
    """
    Extracts unique file operations from a JSONL file containing Sysdig event data.

    Args:
        json_path (str): Path to the JSONL file.

    Returns:
        list: A list of dictionaries, each representing a unique file operation with keys:
              'operation', 'filename', and 'flag'.
    """
    unique_operations = set()
    operations = set()
    files = set()
    flags = set()
    # JSONL file needs to be processed line by line
    with open(json_path, 'r') as file:
        for line in file:
            try:
                syscall = json.loads(line.strip())
                event_type = syscall.get("evt.type")
                filename = syscall.get("fd.name")
                flag = syscall.get("evt.arg.flags")
                operation_tuple = (event_type, filename, flag)
                unique_operations.add(operation_tuple)
                operations.add(event_type)
                files.add(filename)
                flags.add(flag)
            except json.JSONDecodeError:
                # Handle JSON parsing errors (e.g., malformed lines)
                continue

    file_operations_list = [
        {'operation': op, 'filename': fn, 'flag': fl}
        for op, fn, fl in unique_operations
    ]

    return file_operations_list
