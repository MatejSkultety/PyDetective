import json
from datetime import datetime
import toml

def evaluate_network_results():
    pass


def evaluate_syscalls_results(source_path: str) -> dict:
    result = {
        "warnings": 0,
        "errors": 0,
        "verdict": "SAFE",
        "issues": []
    }

    with open(source_path, "r") as file:
        for line in file:
            try:
                event = json.loads(line.strip())
                # Extract specific fields for the event
                formatted_event = {
                    "priority": event.get("priority", ""),
                    "rule": event.get("rule", ""),
                    "output": event.get("output_fields", {})
                }
                result["issues"].append(formatted_event)

                # Update counts based on priority
                priority = formatted_event["priority"].upper()
                if priority in ["NOTICE", "INFO", "DEBUG"]:
                    result["warnings"] += 1
                else:
                    result["errors"] += 1
            except json.JSONDecodeError:
                print("Invalid JSON line encountered, skipping.")

    # Determine the verdict based on the counts
    if result["errors"] > 0:
        result["verdict"] = "MALICIOUS"
    elif result["warnings"] > 0:
        result["verdict"] = "DANGEROUS"

    return result


def evaluate_static_results(source_path: str) -> dict:
    result = {
        "warnings": 0,
        "errors": 0,
        "verdict": "SAFE",
        "issues": []
    }

    with open(source_path, "r") as file:
        try:
            data = json.load(file)  # Load the JSON array from the file
            for entry in data:
                file_path = entry.get("file", "")
                matches = entry.get("matches", [])

                for match in matches:
                    # Extract specific fields for the event
                    formatted_event = {
                        "priority": "WARNING" if match.get("rule") else "INFO",
                        "rule": str(match.get("rule", "") + " " + file_path),
                        "output": {
                            "meta": match.get("meta", {}), 
                            "strings": match.get("strings", [])
                        }
                    }
                    result["issues"].append(formatted_event)

                    # Update counts based on the presence of matches
                    if match.get("rule"):
                        result["warnings"] += 1

        except json.JSONDecodeError:
            print("Invalid JSON file encountered, skipping.")

    # Determine the verdict based on the counts
    if result["warnings"] > 0:
        result["verdict"] = "DANGEROUS"

    return result


def evaluate_post_install_results():
    pass


def evaluate_package(package_path: str, syscalls_path: str, static_path: str) -> dict:
    # Call individual evaluation functions
    syscalls_result = evaluate_syscalls_results(syscalls_path)
    static_result = evaluate_static_results(static_path)

    # Aggregate results
    final_verdict = "SAFE"
    if syscalls_result["verdict"] == "MALICIOUS" or static_result["verdict"] == "MALICIOUS":
        final_verdict = "MALICIOUS"
    elif syscalls_result["verdict"] == "DANGEROUS" or static_result["verdict"] == "DANGEROUS":
        final_verdict = "DANGEROUS"

    # Create the final result dictionary
    package_evaluation = {
        "metadata": get_package_metadata_from_pyproject(package_path),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "final_verdict": final_verdict,
        "evaluations": {
            "syscalls": syscalls_result,
            "static": static_result,
        }
    }

    export_results(package_evaluation, "out/evaluation_result.json")

    return package_evaluation


def get_package_metadata_from_pyproject(package_path: str) -> dict:
    pyproject_path = f"{package_path}/pyproject.toml"
    try:
        with open(pyproject_path, "r") as file:
            pyproject_data = toml.load(file)
            # Extract metadata from the pyproject.toml file
            project = pyproject_data.get("project", {})
            return {
                "name": project.get("name", ""),
                "version": project.get("version", ""),
                "author": ", ".join([author.get("name", "") for author in project.get("authors", [])]),
                "description": project.get("description", "No description provided")
            }
    except FileNotFoundError:
        print(f"pyproject.toml not found in {package_path}")
        return {
            "name": "Unknown",
            "version": "Unknown",
            "author": "Unknown",
            "description": "No description provided"
        }
    except toml.TomlDecodeError:
        print(f"Invalid TOML format in {pyproject_path}")
        return {
            "name": "Unknown",
            "version": "Unknown",
            "author": "Unknown",
            "description": "No description provided"
        }


def export_results(evaluation_result: str, export_path: str) -> None:

    with open(export_path, "w") as file:
        json.dump(evaluation_result, file, indent=4)
    