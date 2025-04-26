import subprocess


def create_command(export_file: str) -> list[str]:
    """
    Create the command to run Falco.

    Args:
        export_file (str): The file to export the results to.

    Returns:
        list[str]: The command to run Falco.
    """
    command = [f"sudo falco > {export_file}"]
    print(f"PyDetective debug: Falco command: {command}")
    return command


def run_process(export_file: str) -> subprocess.Popen:
    """
    Run the Falco command in a subprocess.

    Args:
        export_file (str): The file to export the results to.

    Returns:
        subprocess.Popen: The process object for the running command.
    """
    command = create_command(export_file)
    process = subprocess.Popen(command, shell=True)
    return process


def perform_analysis(export_file: str) -> None:
    """
    Run Falco and export the results to a file.

    Args:
        export_file (str): The file to export the results to.
    
    Returns:
        None
    """
    process = run_process(export_file)
    process.wait()
    print(f"PyDetective debug: Falco analysis complete. Results saved to {export_file}")
