import pyshark
import json
import subprocess
import yara
import os
import requests
from datetime import datetime
import ipwhois
import socket
import whois

from . import profile


def parse_network_artefacts(profile: profile.Profile) -> tuple[set, set]:
    """
    Extracts unique IP addresses, domain and names from a pcap file.
    It uses the pyshark library to read the pcap file and extract relevant information.

    Args:
        profile (profile.Profile): The profile instance containing configuration.

    Returns:
        tuple: A tuple containing two sets:
            - IP addresses (set): Unique IP addresses found in the pcap file.
            - Domain names (set): Unique domain names found in the pcap file.
    """
    ip_addresses = set()
    domain_names = set()

    cap = pyshark.FileCapture(profile.network_output_path, display_filter='dns or ip')
    for packet in cap:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if src_ip not in profile.ignored_ips:
                ip_addresses.add(src_ip)
            if dst_ip not in profile.ignored_ips:
                ip_addresses.add(dst_ip)
        if 'DNS' in packet:
            if hasattr(packet.dns, 'qry_name'):
                domain = packet.dns.qry_name
                if domain not in profile.ignored_domains:
                    domain_names.add(domain)
            if hasattr(packet.dns, 'cname') and packet.dns.cname:
                cname = packet.dns.cname
                if cname not in profile.ignored_domains:
                    domain_names.add(cname)
            # Check for A and AAAA records (IPv4/IPv6) in DNS responses
            if hasattr(packet.dns, 'a') and packet.dns.a:
                if packet.dns.a not in profile.ignored_ips:
                    ip_addresses.add(packet.dns.a)
            if hasattr(packet.dns, 'aaaa') and packet.dns.aaaa:
                if packet.dns.aaaa not in profile.ignored_ips:
                    ip_addresses.add(packet.dns.aaaa)
    cap.close()
    return ip_addresses, domain_names


def check_ip_otx(ip: str, profile: profile.Profile) -> dict:
    otx_api_key = profile.otx_api_key
    if not otx_api_key:
        return {}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": otx_api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.ok:
            data = r.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            malicious = pulses > 0
            return {
                "otx_malicious": malicious,
                "otx_pulse_count": pulses,
                "otx_pulse_names": [p["name"] for p in data.get("pulse_info", {}).get("pulses", [])]
            }
    except Exception:
        pass
    return {}


def check_domain_otx(domain: str, profile: profile.Profile) -> dict:
    otx_api_key = profile.otx_api_key
    if not otx_api_key:
        return {}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": otx_api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.ok:
            data = r.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            malicious = pulses > 0
            return {
                "otx_malicious": malicious,
                "otx_pulse_count": pulses,
                "otx_pulse_names": [p["name"] for p in data.get("pulse_info", {}).get("pulses", [])]
            }
    except Exception:
        pass
    return {}


def enrich_ip(ip: str, profile) -> dict:
    result = {"ip": ip}
    try:
        obj = ipwhois.IPWhois(ip)
        res = obj.lookup_rdap()
        result.update({
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
            "country": res.get("network", {}).get("country"),
            "network_name": res.get("network", {}).get("name"),
        })
    except Exception:
        pass
    result.update(check_ip_otx(ip, profile))
    return result


def enrich_domain(domain: str, profile) -> dict:
    result = {"domain": domain}
    try:
        w = whois.whois(domain)
        result.update({
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
        })
    except Exception:
        pass
    result.update(check_domain_otx(domain, profile))
    return result


def analyse_network_artefacts(profile: profile.Profile) -> None:
    """
    Analyze network artefacts from a pcap file, enrich them and export the results to a JSON file.

    Args:
        profile (profile.Profile): The profile instance containing configuration.

    Returns:
        None
    """
    ip_addresses, domain_names = parse_network_artefacts(profile)
    enriched_ips = [enrich_ip(ip, profile) for ip in ip_addresses]
    enriched_domains = [enrich_domain(domain, profile) for domain in domain_names]
    result = {
        'ip_addresses': enriched_ips,
        'domain_names': enriched_domains
    }
    with open(profile.network_result_path, 'w') as f:
        json.dump(result, f, indent=4)


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
            json.dump(self.results, f, indent=4)
