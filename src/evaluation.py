import json
from datetime import datetime
import time
import toml
import logging
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import subprocess
import pkginfo
import os
import weasyprint

from . import profile


class Verdict(Enum):
    SAFE = "SAFE"
    DANGEROUS = "SUSPICIOUS"
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


def evaluate_post_install_results(source_path: str) -> dict:
    result = {
        "warnings": 0,
        "errors": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }
    try:
        with open(source_path, "r") as file:
            for line in file:
                if "SCAN SUMMARY" in line:
                    break
                if line.strip():
                    result["issues"].append({
                        "priority": "ERROR",
                        "rule": "Detected issue",
                        "output": line.strip()
                    })
                    result["errors"] += 1
    except FileNotFoundError:
        logging.error(f"Post-install result file not found: {source_path}")
    if result["errors"] > 0:
        result["verdict"] = Verdict.MALICIOUS.value
    else:
        result["verdict"] = Verdict.SAFE.value

    return result


def evaluate_package(profile: profile.Profile, static_result: dict = None) -> dict:
    # Call individual evaluation functions
    network_result = evaluate_network_results(profile.network_result_path)
    syscalls_result = evaluate_syscalls_results(profile.syscalls_result_path)
    if static_result is None:
        static_result = evaluate_static_results(profile.static_result_path)
    post_install_result = evaluate_post_install_results(profile.post_install_result_path)

    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Evaluating package '{profile.package_name}'")
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
    evaluation_result = {
        "metadata": get_package_metadata(profile),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "final_verdict": final_verdict,
        "evaluations": {
            "network": network_result,
            "syscalls": syscalls_result,
            "static": static_result,
            "post_install": post_install_result
        }
    }
    logging.debug("Storing evaluation result in MySQL database")
    store_evaluation_result(profile, evaluation_result)
    print_evaluation_result(profile, evaluation_result)

    return evaluation_result


def get_package_metadata(profile: profile.Profile) -> dict:
    if not profile.local_package:
        metadata_retrieval_command = f"curl https://pypi.org/pypi/{profile.package_name}/json"
        try:
            result = subprocess.run(metadata_retrieval_command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                metadata = json.loads(result.stdout).get("info", {})
                return {
                    "package_name": profile.package_name,
                    "version": metadata.get("version", ""),
                    "author": metadata.get("author", ""),
                    "author_email": metadata.get("author_email", ""),
                    "home_page": metadata.get("home_page", ""),
                    "package_url": metadata.get("package_url", "")
                }
            else:
                logging.error(f"Failed to retrieve package metadata: {result.stderr}")
                return {}
        except Exception as e:
            logging.error(f"Error retrieving package metadata: {e}")
            return {}
    else:
        try:
            if profile.package_name.endswith(".whl"):
                metadata = pkginfo.Wheel(profile.package_name)
            elif profile.package_name.endswith(".tar.gz"):
                metadata = pkginfo.SDist(profile.package_name)
            else:
                info_path = str(profile.package_name + "/pyproject.toml")
                if not os.path.exists(info_path):
                    return {}
                with open(info_path, 'r') as file:
                    pyproject = toml.load(file)
                    metadata = pyproject.get("project", {})
            meta_dict = {
                "package_name": getattr(metadata, "name", "") or profile.package_name,
                "version": getattr(metadata, "version", ""),
                "author": getattr(metadata, "author", ""),
                "author_email": getattr(metadata, "author_email", ""),
                "home_page": getattr(metadata, "home_page", ""),
                "package_url": getattr(metadata, "package_url", "")
            }
            return meta_dict
        except Exception as e:
            logging.error(f"Error reading local package metadata: {e}")
            return {}


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

    if metadata and not profile.args.quiet:
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
    if profile.args.write and not profile.args.database:
        export_results_to_file(profile, evaluation_result, console)


def export_results_to_file(profile: profile.Profile, evaluation_result: dict, console: Console) -> None:
    
    export_path = profile.args.write
    export_format = export_path.split('.')[-1].lower()
    if export_format == 'json':
        with open(export_path, 'w') as file:
            json.dump(evaluation_result, file, indent=4)
        logging.info(f"Results exported to {export_path}")
    elif export_format == 'html':
        with open(export_path, 'w') as file:
            file.write(console.export_html())
        logging.info(f"Results exported to {export_path}")
    elif export_format == 'pdf':
        html_content = console.export_html()
        pdf_content = weasyprint.HTML(string=html_content).write_pdf()
        with open(export_path, 'wb') as file:
            file.write(pdf_content)
        logging.info(f"Results exported to {export_path}")
    else:
        with open(export_path, 'w') as file:
            json.dump(evaluation_result, file, indent=4)
        logging.info(f"Unsuported format. Results exported to {export_path} as JSON")
        print(f"[{time.strftime('%H:%M:%S')}] [WARNING] Unsuported output format. Results exported to {export_path} as JSON.")


def store_evaluation_result(profile: profile.Profile, evaluation_result: dict) -> None:
    verdict = evaluation_result.get("final_verdict", "")
    try:
        cursor = profile.database_connection.cursor()
        cursor.execute(
            f"INSERT INTO {profile.db_table} (package_name, timestamp, verdict, evaluation_result) VALUES (%s, %s, %s, %s)",
            (profile.package_name, profile.analysis_timestamp, verdict, json.dumps(evaluation_result))
        )
        profile.database_connection.commit()
        logging.info(f"Evaluation result stored in MySQL for package {profile.package_name}")
    except Exception as e:
        logging.error(f"Failed to store evaluation result in MySQL: {e}")


def read_db_results(profile: profile.Profile) -> None:
    try:
        cursor = profile.database_connection.cursor()
        if profile.args.database.lower() == "all":
            cursor.execute(f"SELECT package_name, timestamp, verdict FROM {profile.db_table}")
            rows = cursor.fetchall()
            console = Console()
            table = Table(title="PyDetective Results History")
            table.add_column("Package Name", style="bold")
            table.add_column("Timestamp")
            table.add_column("Verdict")
            for package_name, timestamp, verdict in rows:
                table.add_row(str(package_name), str(timestamp), str(verdict))
            console.print(table)
        else:
            cursor.execute(
                f"SELECT evaluation_result FROM {profile.db_table} WHERE package_name = %s",
                (profile.args.database,)
            )
            rows = cursor.fetchall()
            if not rows:
                print(f"[{time.strftime('%H:%M:%S')}] [WARNING] No results found for package "
                      f"'{profile.args.database}' in the database. Try running the analysis first or use -db ALL to see all results.")
                return
            for row in rows:
                evaluation_result = json.loads(row[0])
                print_evaluation_result(profile, evaluation_result)
    except Exception as e:
        logging.error(f"Failed to read results from MySQL: {e}")
