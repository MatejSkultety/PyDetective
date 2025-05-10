import pyshark
import json
import subprocess
import yara
import os
from datetime import datetime


def parse_network_artefacts(pcap_file: str, ignored_hosts: list[str] = None, ignored_ips: list[str] = None) -> tuple[set, set]:
    """
    Extracts unique IP addresses, domain and names from a pcap file.
    It uses the pyshark library to read the pcap file and extract relevant information.

    Args:
        pcap_file (str): Path to the pcap file.
        ignored_hosts (list[str], optional): List of hosts to ignore. Defaults to None.
        ignored_ips (list[str], optional): List of IP addresses to ignore. Defaults to None.

    Returns:
        tuple: A tuple containing two sets:
            - IP addresses (set): Unique IP addresses found in the pcap file.
            - Domain names (set): Unique domain names found in the pcap file.
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


def analyse_syscalls_artefacts(config_path: str, export_path: str) -> None:
    """
    Run Falco to analyze syscalls captured using Sysdig for potentialy malicious behaviour
    and export the results to a file.
    
    Args:
        config_path (str): Path to the Falco configuration file.
        export_path (str): Path to the file where the Falco output will be saved.
        
    Returns:
        None
    """
    command = [f"sudo falco -c {config_path} > {export_path}"]
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()

# TODO consider max time limit for the process
class StaticAnalyzer:
    """
    A class to perform static analysis on files using YARA rules.
    YARA rules can be compiled from a directory or a single file and scan files for matches.
    """
    def __init__(self: object, rules_path: str) -> None:
        """
        Initialize the StaticAnalyzer with the path to YARA rules.

        Args:
            rules_path (str): The path to the directory or file containing YARA rules.

        Returns:
            None
        """
        self.rules = self.compile_rules(rules_path)
        self.results = []
    

    def compile_rules(self: object, rules_path: str) -> dict:
        """
        Compile YARA rules from a directory or a single file.
        If the path is a directory, it will compile all .yar and .yara files in that directory.
        
        Args:
            rules_path (str): The path to the directory or file containing YARA rules.

        Returns:
            dict: A dictionary of compiled YARA rules.
        """
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
    

    def scan_file(self: object, file_path: str) -> dict:
        """
        Perform static analysis on a single file using compiled YARA rules.

        Args:
            file_path (str): The path to the file to scan.

        Returns:
            dict: A dictionary containing the results of the scan, including matches found.
        """
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
    

    def scan_directory(self: object, directory_path: str, export_path: str = None) -> None:
        """
        Recursively scan all files in a directory using compiled YARA rules.

        Args:
            directory_path (str): The path to the directory to scan.
            export_path (str, optional): The path to the file where the results will be saved. Defaults to None.

        Returns:
            None
        
        """
        self.results = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.scan_file(file_path)
        if export_path:
            self.export_results(export_path)
    
    
    def export_results(self: object, export_path: str) -> None:
        """
        Export the results of static analysis to a JSON file.

        Args:
            export_path (str): The path to the file where the results will be saved.

        Returns:
            None
        """
        with open(export_path, 'w') as f:
            json.dump(self.results, f, indent=2)
