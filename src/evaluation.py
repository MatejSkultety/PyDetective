import json
from datetime import datetime
import toml
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import weasyprint

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
                falco_priority = event.get("priority", "").upper()
                if falco_priority in ["NOTICE", "INFO", "DEBUG"]:
                    result["warnings"] += 1
                    priority = "WARNING"
                else:
                    result["errors"] += 1
                    priority = "ERROR"
                formatted_event = {
                    "priority": priority,
                    "rule": event.get("rule", ""),
                    "output": event.get("output_fields", {})
                }
                result["issues"].append(formatted_event)
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
                            "rule": str(match.get("rule", "")),
                            "output": {
                                "file": entry.get("file", ""),
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

    export_results(profile, package_evaluation)

    return package_evaluation


def get_package_metadata_from_pyproject(package_path: str) -> dict:
    pass


def export_results(profile: profile.Profile, evaluation_result: dict) -> None:
    with open(profile.evaluation_output_path, "w") as file:
        json.dump(evaluation_result, file, indent=4)
    print_evaluation_result(profile, evaluation_result)


def print_evaluation_result(profile: profile.Profile, evaluation_result: dict) -> None:
    print('.' * profile.terminal_size.columns)
    console = Console(record=True)
    metadata = evaluation_result.get("metadata", {})
    timestamp = evaluation_result.get("timestamp", "")
    final_verdict = evaluation_result.get("final_verdict", "")
    evaluations = evaluation_result.get("evaluations", {})

    # Header panel and metadata table (skip if quiet)
    header = f"[bold]PyDetective Analysis Result[/bold]\n[dim]Timestamp:[/dim] {timestamp}\n[dim]Final Verdict:[/dim] [bold]{final_verdict}[/bold]"
    console.print(Panel(header, expand=False))

    if metadata:
        meta_table = Table(title="Package Metadata", box=box.SIMPLE)
        meta_table.add_column("Key", style="bold")
        meta_table.add_column("Value")
        for k, v in metadata.items():
            meta_table.add_row(str(k), str(v))
        console.print(meta_table)

    # Evaluations summary table (always shown)
    summary_table = Table(title="Evaluation Summary", box=box.SIMPLE)
    summary_table.add_column("Check", style="bold")
    summary_table.add_column("Verdict")
    summary_table.add_column("Warnings", justify="right")
    summary_table.add_column("Errors", justify="right")
    for check, result in evaluations.items():
        summary_table.add_row(
            check.capitalize(),
            result.get("verdict", ""),
            str(result.get("warnings", 0)),
            str(result.get("errors", 0)),
        )
    console.print(summary_table)

    if not profile.args.quiet:
        for check, result in evaluations.items():
            issues = result.get("issues", [])
            if issues:
                table = Table(title=f"{check.capitalize()} Triggered Rules", box=box.MINIMAL)
                table.add_column("Priority", style="bold")
                table.add_column("Rule")
                if profile.args.verbose:
                    table.add_column("Output", overflow="fold")
                for issue in issues:
                    if profile.args.verbose:
                        table.add_row(
                            str(issue.get("priority", "")),
                            str(issue.get("rule", "")),
                            str(issue.get("output", "")),
                        )
                    else:
                        table.add_row(
                            str(issue.get("priority", "")),
                            str(issue.get("rule", "")),
                        )
                console.print(table)
    html_content = console.export_html()
    html_path = "out/evaluation_result.html"
    with open(html_path, "w") as f:
        f.write(html_content)
    pdf_path = "out/evaluation_result.pdf"
    weasyprint.HTML(string=html_content).write_pdf(pdf_path)

def export_results_html(profile: profile.Profile, evaluation_result: dict) -> None:
    pass