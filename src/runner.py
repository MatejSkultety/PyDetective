import subprocess
import sys
import time
import logging
import os

from . import containers, scanning, analysis, profile, evaluation
from .evaluation import Verdict


def analyze_package(profile: profile.Profile) -> str:
    """
    Analyze a package by performing network and syscall scans, followed by analysis.

    Args:
        profile (profile.Profile): The profile instance containing configuration.
        secure (bool): Flag to indicate if secure mode is enabled. Defaults to False.

    Returns:
        verdict (str): The verdict of the analysis.
    """
    # static__analyzer = analysis.StaticAnalyzer(profile.static_rules_folder_path)
    # static__analyzer.scan_directory(profile.extracted_path, profile.static_result_path)

    # TODO evaluate and if dangerous, stop the process
    profile.static_analyzer.scan_directory(profile.extracted_path, profile.static_result_path)
    static_result = evaluation.evaluate_static_results(profile.static_result_path)

    if static_result["verdict"] == Verdict.MALICIOUS.value and profile.args.secure:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Package is detected as MALICIOUS by static analysis. Stopping the process ...")
        logging.error(f"Package is detected as MALICIOUS by static analysis. Stopping the process ...")
        return static_result["verdict"]

    containers.build_sandbox_image(profile.docker_client, profile.sandbox_folder_path, profile.image_tag)
    sandbox_container = containers.create_sandbox_container(profile)    
    # Start network and syscall scans
    sysdig_process = scanning.scan_syscalls(sandbox_container, profile.syscalls_output_path, profile.ignored_syscalls)
    containers.copy_package_to_container(sandbox_container, profile.archives_path, profile.container_dir_path)
    sandbox_container.start()
    tcpdump_container = scanning.scan_network(profile.docker_client, sandbox_container, profile.network_output_path)

    sandbox_container.wait()
    containers.get_logs_from_container(sandbox_container, profile.logging_path, True) # TODO true z profile.verbose
    scanning.stop_network_scan(tcpdump_container, profile.network_output_path)
    sysdig_process.kill()
    if profile.args.deep:
        pass
    sandbox_container.stop()
    sandbox_container.remove(force=True)

    analysis.analyse_syscalls_artefacts(profile.falco_config_path, profile.syscalls_result_path)
    analysis.analyse_network_artefacts(profile)
    
    return evaluation.evaluate_package(profile, static_result)


def install_package_on_host(archives_path: str, local_package: bool) -> None:
    """
    Install a package on the host system. It installs all package archives in the specified folder using pip.
    This function assumes that the archives are in a format compatible with pip.

    Args:
        archives_path (str): Path to folder containing all package archives.
        local_package (bool): Flag to indicate if the package is a local package. If True, it will install the package

    Returns:
        None
    """
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Installing package on host environment ...")
    logging.info(f"Installing package on host environment")
    try:
        if local_package:
            command = f"pip install {archives_path}"
            installer = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            installer.wait()
        else:
            archives = [f for f in os.listdir(archives_path)]
            if not archives:
                raise Exception("There are no archives to install.")
            for archive in archives:
                archive_path = os.path.join(archives_path, archive)
                try:
                    command = f"pip install {archive_path}"
                    installer = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
                    installer.wait()
                except subprocess.CalledProcessError as e:
                    print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Failed to install archive '{archive_path}': {e}")
                    logging.error(f"Failed to install package '{archive_path}': {e}")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Failed to install package: {e}")
        logging.error(f"Failed to install package: {e}")
        print("\nExiting program ...\n")
        sys.exit(1)
