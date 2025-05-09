import pyshark
import json
import subprocess
import yara
import os
from datetime import datetime

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

    command = [f"sudo falco -c config/falco.yaml"]
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    process.wait()
    for line in process.stdout:
        print(line.decode().strip())


class StaticAnalyzer:
    def __init__(self, rules_path, max_size_mb=10):
        self.rules = self.compile_rules(rules_path)
        self.max_size = max_size_mb * 1024 * 1024  # Convert MB to bytes
        self.results = []
    
    def compile_rules(self, rules_path):
        """Compile all YARA rules from a directory"""
        if os.path.isfile(rules_path):
            return yara.compile(filepath=rules_path)
        
        all_rules = {}
        for root, _, files in os.walk(rules_path):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    rule_path = os.path.join(root, file)
                    try:
                        rule_name = os.path.splitext(file)[0]
                        all_rules[rule_name] = yara.compile(filepath=rule_path)
                    except yara.SyntaxError as e:
                        print(f"Syntax error in {rule_path}: {e}")
        return all_rules
    

    def scan_file(self, file_path):
        """Scan a single file with all loaded rules"""
        result = {
            'file': file_path,
            'timestamp': datetime.now().isoformat(),
            'matches': []
        }
            
        try:
            for rule_name, rule in self.rules.items():
                matches = rule.match(filepath=file_path)
                if matches:
                    for match in matches:
                        match_info = {
                            'rule': match.rule,
                            'namespace': match.namespace,
                            'tags': list(match.tags),
                            'meta': match.meta,
                            'strings': []
                        }
                        
                        for string_match in match.strings:
                            for instance in string_match.instances:
                                string_info = {
                                    'identifier': string_match.identifier,
                                    'offset': instance.offset,
                                    'matched_data': instance.matched_data.hex()[:50] + '...' if len(instance.matched_data) > 25 else instance.matched_data.hex()
                                }
                                match_info['strings'].append(string_info)
                        
                        result['matches'].append(match_info)
        except Exception as e:
            result['error'] = str(e)
            
        self.results.append(result)
        return result
    

    def scan_directory(self, directory_path):
        """Recursively scan all files in a directory"""
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.scan_file(file_path)
    
    
    def export_results(self, output_file):
        """Export scan results to a JSON file"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
