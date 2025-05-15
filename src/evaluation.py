import json
from datetime import datetime
import toml
from enum import Enum

from . import profile


class Verdict(Enum):
    SAFE = "SAFE"
    DANGEROUS = "DANGEROUS"
    MALICIOUS = "MALICIOUS"


def evaluate_network_results(source_path: str) -> dict:
    result = {
        "warnings": 0,
        "errors": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }

    with open(source_path, "r") as file:
        data = json.load(file)

        # Evaluate IP addresses
        for ip_info in data.get("ip_addresses", []):
            try:
                if "otx_malicious" in ip_info:
                    if ip_info.get("otx_malicious"):
                        issue = {
                            "priority": "ERROR",
                            "rule": f"Dangerous IP accessed: {ip_info.get('ip', '')} - {ip_info.get('asn_description', '')}",
                            "output": ip_info
                        }
                        result["issues"].append(issue)
                        result["errors"] += 1
                    else:
                        issue = {
                            "priority": "INFO",
                            "rule": f"IP accessed: {ip_info.get('ip', '')} - {ip_info.get('asn_description', '')}",
                            "output": ip_info
                        }
                        result["issues"].append(issue)
                else:
                    issue = {
                        "priority": "WARNING",
                        "rule": f"IP without OTX details accessed {ip_info.get('ip', '')}",
                        "output": ip_info
                    }
                    result["issues"].append(issue)
                    result["warnings"] += 1
            except Exception:
                issue = {
                    "priority": "WARNING",
                    "rule": f"IP {ip_info.get('ip', 'unknown')} - Could not evaluate",
                    "output": ip_info
                }
                result["issues"].append(issue)
                result["warnings"] += 1

        # Evaluate domain names
        for domain_info in data.get("domain_names", []):
            try:
                if "otx_malicious" in domain_info and domain_info.get("otx_malicious"):
                    issue = {
                        "priority": "ERROR",
                        "rule": f"Dangerous domain accessed: {domain_info.get('domain', '')}",
                        "output": domain_info
                    }
                    result["issues"].append(issue)
                    result["errors"] += 1  
                else:   
                    issue = {
                        "priority": "WARNING",
                        "rule": f"Unexpected domain accessed: {domain_info.get('domain', '')}",
                        "output": domain_info
                    }
                    result["issues"].append(issue)
                    result["warnings"] += 1
            except Exception:
                issue = {
                    "priority": "WARNING",
                    "rule": f"Domain {domain_info.get('domain', 'unknown')} - Could not evaluate",
                    "output": domain_info
                }
                result["issues"].append(issue)
                result["warnings"] += 1

    if result["errors"] > 0:
        result["verdict"] = Verdict.MALICIOUS.value
    elif result["warnings"] > 0:
        result["verdict"] = Verdict.DANGEROUS.value
    else:
        result["verdict"] = Verdict.SAFE.value
    return result


def evaluate_syscalls_results(source_path: str) -> dict:
    result = {
        "warnings": 0,
        "errors": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }

    with open(source_path, "r") as file:
        for line in file:
            try:
                event = json.loads(line.strip())
                formatted_event = {
                    "priority": event.get("priority", ""),
                    "rule": event.get("rule", ""),
                    "output": event.get("output_fields", {})
                }
                result["issues"].append(formatted_event)
                priority = formatted_event["priority"].upper()
                if priority in ["NOTICE", "INFO", "DEBUG"]:
                    result["warnings"] += 1
                else:
                    result["errors"] += 1
            except json.JSONDecodeError:
                continue
    if result["errors"] > 0:
        result["verdict"] = Verdict.MALICIOUS.value
    elif result["warnings"] > 0:
        result["verdict"] = Verdict.DANGEROUS.value
    else:
        result["verdict"] = Verdict.SAFE.value
    return result


def evaluate_static_results(source_path: str) -> dict:
    result = {
        "warnings": 0,
        "errors": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }

    with open(source_path, "r") as file:
        try:
            data = json.load(file)  # Load the JSON array from the file
            for entry in data:
                file_path = entry.get("file", "")
                matches = entry.get("matches", [])

                for match in matches:
                    if match.get("rule"):
                        formatted_event = {
                            "priority": "ERROR",
                            "rule": str(match.get("rule", "") + " " + file_path),
                            "output": {
                                "meta": match.get("meta", {}), 
                                "strings": match.get("strings", [])
                            }
                        }
                        result["issues"].append(formatted_event)
                        result["errors"] += 1

        except json.JSONDecodeError:
            print("Invalid JSON file encountered, skipping.")
    if result["errors"] > 0:
        result["verdict"] = Verdict.MALICIOUS.value
    elif result["warnings"] > 0:
        result["verdict"] = Verdict.DANGEROUS.value
    else:
        result["verdict"] = Verdict.SAFE.value
    return result


def evaluate_post_install_results(*args, **kwargs):
    # Placeholder implementation
    return {
        "warnings": 0,
        "errors": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }


def evaluate_package(profile: profile.Profile, static_result: dict = None) -> dict:
    # Call individual evaluation functions
    network_result = evaluate_network_results(profile.network_result_path)
    syscalls_result = evaluate_syscalls_results(profile.syscalls_result_path)
    if static_result is None:
        static_result = evaluate_static_results(profile.static_result_path)
    post_install_result = evaluate_post_install_results(profile.post_install_result_path)

    # Aggregate results
    verdicts = set()
    verdicts.add(network_result["verdict"])
    verdicts.add(syscalls_result["verdict"])
    verdicts.add(static_result["verdict"])
    verdicts.add(post_install_result["verdict"])
    if Verdict.MALICIOUS.value in verdicts:
        final_verdict = Verdict.MALICIOUS.value
    elif Verdict.DANGEROUS.value in verdicts:
        final_verdict = Verdict.DANGEROUS.value
    else:
        final_verdict = Verdict.SAFE.value

    # Create the final result dictionary
    package_evaluation = {
        "metadata": get_package_metadata_from_pyproject(profile.archives_path),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "final_verdict": final_verdict,
        "evaluations": {
            "network": network_result,
            "syscalls": syscalls_result,
            "static": static_result,
            "post_install": post_install_result
        }
    }

    export_results(package_evaluation, "out/evaluation_result.json")

    return package_evaluation


def get_package_metadata_from_pyproject(package_path: str) -> dict:
    pass


def export_results(evaluation_result: dict, export_path: str) -> None:
    with open(export_path, "w") as file:
        json.dump(evaluation_result, file, indent=4)
