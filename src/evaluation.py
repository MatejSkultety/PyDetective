import datetime
import enum
import hashlib
import json
import logging
import os
import subprocess
import time

import pkginfo
import rich
import rich.console
import rich.panel
import rich.table
import toml
import weasyprint

from . import profile


class Verdict(enum.Enum):
    """
    Enum to represent the verdict of the evaluation.
    - SAFE: No issues found, package is safe.
    - DANGEROUS: Some low priority issues found, package may be suspicious.
    - MALICIOUS: High priority issues found, package is considered malicious.
    """
    SAFE = "SAFE"
    DANGEROUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


def evaluate_network_results(profile: profile.Profile) -> dict:
    """
    Evaluate network results from the profile's network result path in profile.
    Verdict is determined based on the number of high and low priority issues found.

    Args:
        profile (profile.Profile): The profile containing paths to the network results and evaluation settings.
    Returns:
        dict: A dictionary containing the evaluation results, including the number of issues and verdict.
    """
    result = {
        "num_low_priority": 0,
        "num_high_priority": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }
    with open(profile.network_result_path, "r") as file:
        data = json.load(file)
        # Evaluate IP addresses
        for ip_info in data.get("ip_addresses", []):
            try:
                if "otx_malicious" in ip_info:
                    if ip_info.get("otx_malicious"):
                        issue = {
                            "priority": "HIGH",
                            "rule": f"Dangerous IP accessed: {ip_info.get('ip', '')} - {ip_info.get('asn_description', '')}",
                            "output": ip_info
                        }
                        result["issues"].append(issue)
                        result["num_high_priority"] += 1
                else:
                    issue = {
                        "priority": "LOW",
                        "rule": f"IP without OTX details accessed {ip_info.get('ip', '')}",
                        "output": ip_info
                    }
                    result["issues"].append(issue)
                    result["num_low_priority"] += 1
            except Exception:
                issue = {
                    "priority": "LOW",
                    "rule": f"IP {ip_info.get('ip', 'unknown')} - Could not evaluate",
                    "output": ip_info
                }
                result["issues"].append(issue)
                result["num_low_priority"] += 1
        # Evaluate domain names
        for domain_info in data.get("domain_names", []):
            try:
                if "otx_malicious" in domain_info and domain_info.get("otx_malicious"):
                    issue = {
                        "priority": "HIGH",
                        "rule": f"Dangerous domain accessed: {domain_info.get('domain', '')}",
                        "output": domain_info
                    }
                    result["issues"].append(issue)
                    result["num_high_priority"] += 1  
                else:   
                    issue = {
                        "priority": "LOW",
                        "rule": f"Unexpected domain accessed: {domain_info.get('domain', '')}",
                        "output": domain_info
                    }
                    result["issues"].append(issue)
                    result["num_low_priority"] += 1
            except Exception:
                issue = {
                    "priority": "LOW",
                    "rule": f"Domain {domain_info.get('domain', 'unknown')} - Could not evaluate",
                    "output": domain_info
                }
                result["issues"].append(issue)
                result["num_low_priority"] += 1
    if result["num_high_priority"] > profile.MAX_TOLERATED_HIGH_PRIORITY_NETWORK:
        result["verdict"] = Verdict.MALICIOUS.value
    elif result["num_low_priority"] > profile.MAX_TOLERATED_LOW_PRIORITY_NETWORK:
        result["verdict"] = Verdict.DANGEROUS.value
    else:
        result["verdict"] = Verdict.SAFE.value
    return result


def evaluate_syscalls_results(profile: profile.Profile) -> dict:
    """
    Evaluate syscall results from the profile's syscalls result path in profile.
    Verdict is determined based on the number of high and low priority syscalls found.

    Args:
        profile (profile.Profile): The profile containing paths to the syscalls results and evaluation settings.
    Returns:
        dict: A dictionary containing the evaluation results, including the number of issues and verdict.
    """
    result = {
        "num_low_priority": 0,
        "num_high_priority": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }
    with open(profile.syscalls_result_path, "r") as file:
        for line in file:
            try:
                event = json.loads(line.strip())
                falco_priority = event.get("priority", "").upper()
                if falco_priority in ["NOTICE", "INFO", "DEBUG"]:
                    result["num_low_priority"] += 1
                    priority = "LOW"
                else:
                    result["num_high_priority"] += 1
                    priority = "HIGH"
                formatted_event = {
                    "priority": priority,
                    "rule": event.get("rule", ""),
                    "output": event.get("output_fields", {})
                }
                result["issues"].append(formatted_event)
            except json.JSONDecodeError:
                continue
    if result["num_high_priority"] > profile.MAX_TOLERATED_HIGH_PRIORITY_SYSCALLS:
        result["verdict"] = Verdict.MALICIOUS.value
    elif result["num_low_priority"] > profile.MAX_TOLERATED_LOW_PRIORITY_SYSCALLS:
        result["verdict"] = Verdict.DANGEROUS.value
    else:
        result["verdict"] = Verdict.SAFE.value
    return result


def evaluate_static_results(profile: profile.Profile) -> dict:
    """
    Evaluate static analysis results from the profile's static result path in profile.
    Verdict is determined based on the number of high and low priority issues found.

    Args:
        profile (profile.Profile): The profile containing paths to the static results and evaluation settings.
    Returns:
        dict: A dictionary containing the evaluation results, including the number of issues and verdict.
    """
    result = {
        "num_low_priority": 0,
        "num_high_priority": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }
    with open(profile.static_result_path, "r") as file:
        try:
            data = json.load(file)
            for entry in data:
                matches = entry.get("matches", [])
                for match in matches:
                    if match.get("rule"):
                        meta, = match.get("meta", {}),
                        formatted_event = {
                            "priority": meta.get("priority", "HIGH").upper(),
                            "rule": str(match.get("rule", "")),
                            "output": {
                                "file": entry.get("file", ""),
                                "meta": meta, 
                                "strings": match.get("strings", [])
                            }
                        }
                        result["issues"].append(formatted_event)
                        result["num_high_priority"] += 1
        except json.JSONDecodeError:
            print("Invalid JSON file encountered, skipping.")
    if result["num_high_priority"] > profile.MAX_TOLERATED_HIGH_PRIORITY_STATIC:
        result["verdict"] = Verdict.MALICIOUS.value
    elif result["num_low_priority"] > profile.MAX_TOLERATED_LOW_PRIORITY_STATIC:
        result["verdict"] = Verdict.DANGEROUS.value
    else:
        result["verdict"] = Verdict.SAFE.value
    return result


def evaluate_post_install_results(profile: profile.Profile) -> dict:
    """
    Evaluate post-install results from the profile's post-install result path in profile.
    Verdict is determined based only on the number of high priority issues found.

    Args:
        profile (profile.Profile): The profile containing paths to the post-install results and evaluation settings.
    Returns:
        dict: A dictionary containing the evaluation results, including the number of issues and verdict.
    """
    result = {
        "num_low_priority": 0,
        "num_high_priority": 0,
        "verdict": Verdict.SAFE.value,
        "issues": []
    }
    try:
        with open(profile.post_install_result_path, "r") as file:
            for line in file:
                # clamscan output lines consist of infected files and then a summary section
                if "SCAN SUMMARY" in line:
                    break
                if line.strip():
                    result["issues"].append({
                        "priority": "HIGH",
                        "rule": "Detected issue",
                        "output": line.strip()
                    })
                    result["num_high_priority"] += 1
    except FileNotFoundError:
        logging.error(f"Post-install result file not found: {profile.post_install_result_path}")
    if result["num_high_priority"] > profile.MAX_TOLERATED_HIGH_PRIORITY_POST_INSTALL:
        result["verdict"] = Verdict.MALICIOUS.value
    else:
        result["verdict"] = Verdict.SAFE.value
    return result


def evaluate_package(profile: profile.Profile, static_result: dict = None) -> dict:
    """
    Evaluate a package based on its profile, including network, syscalls, static analysis, and post-install results.
    This function aggregates results from various checks and determines the final verdict based on the issues found.
    It also retrieves package metadata, displays and stores the evaluation result in a MySQL database if configured.

    Args:
        profile (profile.Profile): The profile containing paths to the results and evaluation settings.
        static_result (dict, optional): Pre-created static analysis results. If None, it will be created.
    Returns:
        dict: A dictionary containing the evaluation results, including metadata, timestamp, final verdict, and detailed evaluations.
    """
    # Main evaluation logic
    network_result = evaluate_network_results(profile)
    syscalls_result = evaluate_syscalls_results(profile)
    # static_result is created before installation of the package, so it can be passed as an argument
    if static_result is None:
        static_result = evaluate_static_results(profile)
    post_install_result = evaluate_post_install_results(profile)

    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Evaluating package '{profile.package_name}'")
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
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
    """
    Retrieve metadata for the package specified in the profile.
    If the package is a local file, it reads metadata from the file.
    If the package is not local, it retrieves metadata from PyPI using a curl command.

    Args:
        profile (profile.Profile): The profile containing the package name and local package flag.
    Returns:
        dict: A dictionary containing package metadata such as name, version, author, author email, home page, and package URL.
    """
    # Downloaded package
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
    # Local package
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
                "package_name": metadata.get("name", "") or profile.package_name,
                "version": metadata.get("version", ""),
                "author": metadata.get("authors", [{}])[0].get("name", "") if "authors" in metadata else "",
                "author_email": metadata.get("authors", [{}])[0].get("email", "") if "authors" in metadata else "",
                "home_page": metadata.get("home_page", ""),
                "package_url": metadata.get("package_url", "")
            }
            return meta_dict
        except Exception as e:
            logging.error(f"Error reading local package metadata: {e}")
            return {}


def print_evaluation_result(profile: profile.Profile, evaluation_result: dict) -> None:
    """
    Print the evaluation result in a formatted way using rich library.
    It displays the package metadata, timestamp, final verdict, and detailed evaluations.
    If the profile is set to write results, it exports the results to a file in the specified format (JSON, HTML, or PDF).

    Args:
        profile (profile.Profile): The profile containing the evaluation settings and paths.
        evaluation_result (dict): The evaluation result dictionary containing metadata and evaluations.
    Returns:
        None
    """
    print('.' * profile.terminal_size.columns)
    console = rich.console.Console(record=True)
    metadata = evaluation_result.get("metadata", {})
    timestamp = evaluation_result.get("timestamp", "")
    final_verdict = evaluation_result.get("final_verdict", "")
    evaluations = evaluation_result.get("evaluations", {})

    header = f"[bold]PyDetective Analysis Result[/bold]\n[dim]Timestamp:[/dim] {timestamp}\n[dim]Final Verdict:[/dim] [bold]{final_verdict}[/bold]"
    console.print(rich.panel.Panel(header, expand=False))
    if metadata and not profile.args.quiet:
        console.print(create_metadata_table(metadata))
    console.print(create_summary_table(evaluations))
    if not profile.args.quiet:
        for check, result in evaluations.items():
            issues = result.get("issues", [])
            if issues:
                console.print(create_issues_table(check, issues, profile.args.verbose))
    if profile.args.write and not profile.args.database:
        export_results_to_file(profile, evaluation_result, console)


def create_metadata_table(metadata: dict) -> rich.table.Table:
    """
    Create a table for displaying package metadata.

    Args:
        metadata (dict): A dictionary containing package metadata such as name, version, author, etc.
    Returns:
        rich.table.Table: A table containing the package metadata with keys and values.
    """
    table = rich.table.Table(title="Package Metadata", box=rich.box.SIMPLE)
    table.add_column("Key", style="bold")
    table.add_column("Value")
    for k, v in metadata.items():
        table.add_row(str(k), str(v))
    return table


def create_summary_table(evaluations: dict) -> rich.table.Table:
    """
    Create a summary table for the evaluation results.

    Args:
        evaluations (dict): A dictionary containing the evaluation results for each check.
    Returns:
        rich.table.Table: A table summarizing the evaluation results, including the number of low and high priority issues.
    """
    table = rich.table.Table(title="Evaluation Summary", box=rich.box.SIMPLE)
    table.add_column("Check", style="bold")
    table.add_column("Check Verdict")
    table.add_column("Low Priority Issues", justify="center")
    table.add_column("High Priority Issues", justify="center")
    for check, result in evaluations.items():
        table.add_row(
            check.capitalize(),
            result.get("verdict", ""),
            str(result.get("num_low_priority", 0)),
            str(result.get("num_high_priority", 0)),
        )
    return table


def create_issues_table(check: str, issues: list, verbose: bool) -> rich.table.Table:
    """
    Create a table for displaying issues found during the evaluation of a specific check.
    Args:
        check (str): The type of check (e.g., "network", "syscalls", "static", "post_install").
        issues (list): A list of issues found during the evaluation.
        verbose (bool): If True, includes detailed output in the table.
    Returns:
        rich.table.Table: A table containing the issues with their priority, rule, and output.
    """
    check_titles = {
        "network": "Network: Issues Found",
        "syscalls": "Syscalls: Triggered Falco Rules",
        "static": "Static Analysis: Triggered YARA Rules",
        "post_install": "Post-Install: Issues Found"
    }
    table = rich.table.Table(title=check_titles.get(check.lower(), "Other Issues Found"), box=rich.box.MINIMAL)
    table.add_column("Priority", style="bold")
    table.add_column("Rule")
    if verbose:
        table.add_column("Output", overflow="fold")
    for issue in issues:
        if verbose:
            table.add_row(str(issue.get("priority", "")), str(issue.get("rule", "")), str(issue.get("output", "")))
            table.add_section()
        else:
            table.add_row(str(issue.get("priority", "")), str(issue.get("rule", "")))
    return table


def export_results_to_file(profile: profile.Profile, evaluation_result: dict, console: rich.console.Console) -> None:
    """
    Export the evaluation results to a file in the specified format (JSON, HTML, or PDF).
    If the format is not supported, it defaults to JSON.

    Args:
        profile (profile.Profile): The profile containing the export path and format.
        evaluation_result (dict): The evaluation result dictionary containing metadata and evaluations.
        console (rich.console.Console): The rich console object for exporting HTML content.
    Returns:
        None
    """
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
    """
    Store the evaluation result in a MySQL database. Saves only unique results based on a hash of the evaluation.

    Args:
        profile (profile.Profile): The profile containing database connection and settings.
        evaluation_result (dict): The evaluation result dictionary containing metadata and evaluations to be stored.
    Returns:
        None
    """
    verdict = evaluation_result.get("final_verdict", "")
    version = evaluation_result.get("metadata", {}).get("version", "")
    hash = get_result_hash(evaluation_result)
    try:
        cursor = profile.database_connection.cursor()
        cursor.execute(
            f"INSERT IGNORE INTO {profile.db_table} (package_name, version, verdict, timestamp, hash, evaluation_result) VALUES (%s, %s, %s, %s, %s, %s)",
            (profile.package_name, version, verdict, profile.analysis_timestamp, hash, json.dumps(evaluation_result))
        )
        profile.database_connection.commit()
        logging.info(f"Evaluation result stored in MySQL for package {profile.package_name}")
    except Exception as e:
        logging.error(f"Failed to store evaluation result in MySQL: {e}")


def get_result_hash(evaluation_result: dict) -> str:
    """
    Generate a hash for the evaluation result to ensure uniqueness.
    Uses MD5 hashing on specific package metadata and evaluation details.

    Args:
        evaluation_result (dict): The evaluation result dictionary containing metadata and evaluations.
    Returns:
        str: A unique hash string representing the evaluation result.
    """
    metadata = evaluation_result.get("metadata", {})
    package_name = metadata.get("package_name", "")
    version = metadata.get("version", "")
    final_verdict = evaluation_result.get("final_verdict", "")

    evaluations = evaluation_result.get("evaluations", {})
    eval_summary = []
    for section, section_data in sorted(evaluations.items()):
        verdict = section_data.get("verdict", "")
        num_high_priority = section_data.get("num_high_priority", 0)
        num_low_priority = section_data.get("num_low_priority", 0)
        eval_summary.append(f"{section}:{verdict}:{num_high_priority}:{num_low_priority}")

    hash_input = f"{package_name},{version},{final_verdict}," + ",".join(eval_summary)
    logging.debug(f"Generating hash for evaluation result: {hash_input}")
    return hashlib.md5(hash_input.encode()).hexdigest()


def read_db_results(profile: profile.Profile) -> None:
    """
    Read and display results from the MySQL database based on the profile's database settings.
    If the database argument is set to "ALL", it retrieves all results from the specified table.
    If a specific package name is provided, it retrieves results for that package only.
    
    Args:
        profile (profile.Profile): The profile containing database connection and arguments.
    Returns:
        None
    """
    try:
        cursor = profile.database_connection.cursor()
        if profile.args.database.lower() == "all":
            cursor.execute(f"SELECT package_name, version, verdict, timestamp FROM {profile.db_table}")
            rows = cursor.fetchall()
            console = rich.console.Console()
            table = rich.table.Table(title="PyDetective Results History")
            table.add_column("Package Name", style="bold")
            table.add_column("Version")
            table.add_column("Verdict")
            table.add_column("Timestamp")
            for package_name, version, verdict, timestamp in rows:
                table.add_row(str(package_name), str(version), str(verdict), str(timestamp))
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
