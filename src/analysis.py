import json
import logging
import os
import subprocess

import ipaddress
import ipwhois
import pyshark
import requests
import whois
import yara

from . import profile


def add_ip(ip: str, ip_addresses: set, profile: profile.Profile) -> None:
    """
    Adds an IP address to the set if it is not ignored and is not a private IP.

    Args:
        ip (str): The IP address to add.
        ip_addresses (set): The set of IP addresses to which the IP will be added.
        profile (profile.Profile): The profile instance containing ignored IPs.
    """
    if (ip not in profile.ignored_ips and not ipaddress.ip_address(ip).is_private):
        ip_addresses.add(ip)


def add_domain(domain: str, domain_names: set, profile: profile.Profile) -> None:
    """        
    Adds a domain name to the set if it is not ignored.

    Args:
        domain (str): The domain name to add.
        domain_names (set): The set of domain names to which the domain will be added.
        profile (profile.Profile): The profile instance containing ignored domains.
    """
    if domain not in profile.ignored_domains:
        domain_names.add(domain)


def parse_network_artefacts(profile: profile.Profile) -> tuple[set, set]:
    """
    Extracts unique IP addresses and domain names from a pcap file.
    It uses the pyshark library to read the pcap file and extract relevant information.

    Args:
        profile (profile.Profile): The profile instance containing configuration.

    Returns:
        tuple: A tuple containing two sets:
            - IP addresses (set): Unique IP addresses found in the pcap file.
            - Domain names (set): Unique domain names found in the pcap file.
    """
    logging.debug(f"Parsing network artefacts from {profile.network_output_path}")
    ip_addresses = set()
    domain_names = set()
    with pyshark.FileCapture(profile.network_output_path, display_filter='dns or ip') as cap:
        for packet in cap:
            if 'IP' in packet:
                add_ip(packet.ip.src, ip_addresses, profile)
                add_ip(packet.ip.dst, ip_addresses, profile)
            if 'DNS' in packet:
                if hasattr(packet.dns, 'qry_name'):
                    add_domain(packet.dns.qry_name, domain_names, profile)
                if hasattr(packet.dns, 'cname') and packet.dns.cname:
                    add_domain(packet.dns.cname, domain_names, profile)
                # Check for A and AAAA records (IPv4/IPv6) in DNS responses
                if hasattr(packet.dns, 'a') and packet.dns.a:
                    add_ip(packet.dns.a, ip_addresses, profile)
                if hasattr(packet.dns, 'aaaa') and packet.dns.aaaa:
                    add_ip(packet.dns.aaaa, ip_addresses, profile)
    return ip_addresses, domain_names


def check_ip_otx(ip: str, profile: profile.Profile) -> dict:
    """
    Check if an IP address is associated with any known threats using the OTX API.
    This function queries the OTX API to retrieve threat intelligence data for the given IP address.
    OTX API key is required for authentication, which should be set in the profile.

    Args:
        ip (str): The IP address to check.
        profile (profile.Profile): The profile instance containing configuration.
    Returns:
        dict: A dictionary containing threat intelligence data for the IP address.
    """
    otx_api_key = profile.otx_api_key
    if not otx_api_key:
        return {}
    url = f"{profile.otx_ipv4_indicators_url}/{ip}"
    headers = {"X-OTX-API-KEY": otx_api_key}
    try:
        request = requests.get(url, headers=headers, timeout=10)
        if request.ok:
            data = request.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            malicious = pulses > 0
            return {
                "otx_malicious": malicious,
                "otx_pulse_count": pulses,
                "otx_pulse_names": [p["name"] for p in data.get("pulse_info", {}).get("pulses", [])]
            }
    except Exception as e:
        logging.error(f"OTX IP check failed for {ip}: {e}")
        return {}


def check_domain_otx(domain: str, profile: profile.Profile) -> dict:
    """
    Check if a domain is associated with any known threats using the OTX API.
    This function queries the OTX API to retrieve threat intelligence data for the given domain.
    OTX API key is required for authentication, which should be set in the profile.

    Args:
        domain (str): The domain name to check.
        profile (profile.Profile): The profile instance containing configuration.
    Returns:
        dict: A dictionary containing the results of the OTX check, including whether the domain is malicious,
                the pulse count, and the names of the pulses associated with the domain.
    """
    otx_api_key = profile.otx_api_key
    if not otx_api_key:
        return {}
    url = f"{profile.otx_domain_indicators_url}/{domain}"
    headers = {"X-OTX-API-KEY": otx_api_key}
    try:
        request = requests.get(url, headers=headers, timeout=10)
        if request.ok:
            data = request.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            malicious = pulses > 0
            return {
                "otx_malicious": malicious,
                "otx_pulse_count": pulses,
                "otx_pulse_names": [p["name"] for p in data.get("pulse_info", {}).get("pulses", [])]
            }
    except Exception as e:
        logging.error(f"OTX domain check failed for {domain}: {e}")
        return {}


def enrich_ip(ip: str, profile: profile.Profile) -> dict:
    """
    Enrich IP address information using RDAP lookup and OTX API for threat intelligence.
    This function retrieves details such as ASN, country, and network name from RDAP.
    It also checks the IP against the OTX API to determine if it is associated with any known threats.

    Args:
        ip (str): The IP address to enrich.
        profile (profile.Profile): The profile instance containing configuration.
    Returns:
        dict: A dictionary containing enriched IP address information.
    """
    logging.debug(f"Enriching IP address {ip}")
    result = {"ip": ip}
    try:
        obj = ipwhois.IPWhois(ip)
        details = obj.lookup_rdap()
        result.update({
            "asn": details.get("asn"),
            "asn_description": details.get("asn_description"),
            "country": details.get("network", {}).get("country"),
            "network_name": details.get("network", {}).get("name"),
        })
    except Exception:
        pass
    result.update(check_ip_otx(ip, profile))
    return result


def enrich_domain(domain: str, profile: profile.Profile) -> dict:
    """
    Enrich domain information using WHOIS lookup and OTX API for threat intelligence.
    This function retrieves WHOIS details such as registrar, creation date, expiration date,
    and name servers. It also checks the domain against the OTX API to determine if it is
    associated with any known threats.

    Args:
        domain (str): The domain name to enrich.
        profile (profile.Profile): The profile instance containing configuration.
    Returns:
        dict: A dictionary containing enriched domain information.
    """
    logging.debug(f"Enriching domain {domain}")
    result = {"domain": domain}
    try:
        details = whois.whois(domain)
        result.update({
            "registrar": details.registrar,
            "creation_date": str(details.creation_date),
            "expiration_date": str(details.expiration_date),
            "name_servers": details.name_servers,
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
    command = f"sudo falco -c {config_path} > {export_path}"
    logging.debug(f"Running Falco with command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()


def compile_yara_rules(rules_path: str) -> dict:
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
                    logging.error(f"Syntax error in {rule_path}: {e}")
    return all_rules


def scan_file(file_path: str, rules: dict, results: list) -> dict:
    """
    Perform static analysis on a single file using compiled YARA rules.

    Args:
        file_path (str): The path to the file to scan.
        rules (dict): Dictionary of compiled YARA rules.
        results (list): List to append the scan result.

    Returns:
        dict: A dictionary containing the results of the scan, including matches found.
    """
    result = {
        'file': file_path,
        'matches': []
    }
    try:
        for rule_name, rule in rules.items():
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
    results.append(result)
    return result


def scan_directory(directory_path: str, rules: dict, export_path: str) -> None:
    """
    Recursively scan all files in a directory using compiled YARA rules.

    Args:
        directory_path (str): The path to the directory to scan.
        rules (dict): Dictionary of compiled YARA rules.
        export_path (str): The path to the file where the results will be saved.

    Returns:
        None
    """
    results = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path, rules, results)
    with open(export_path, 'w') as f:
        json.dump(results, f, indent=4)
