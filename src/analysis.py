import pyshark
import json
import subprocess


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
    
    cap.close()
    return ip_addresses, domain_names


def analyse_syscalls_artefacts(scap_path: str) -> dict:

    command = [f"sudo falco"]
    process = subprocess.Popen(command, shell=True)
    process.wait()


# engine:
#   kind: replay
#   replay:
#     capture_file: out/sysdig_output.scap
# json_output: true