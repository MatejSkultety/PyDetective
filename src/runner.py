import subprocess
import sys
import time
import logging
import os

from . import containers, scanning, analysis, profile


def analyze_package(profile: profile.Profile, secure_mode: bool = False) -> None:
    """
    Analyze a package by performing network and syscall scans, followed by analysis.

    Args:
        profile (profile.Profile): The profile instance containing configuration.
        secure_mode (bool): Flag to indicate if secure mode is enabled. Defaults to False.

    Returns:
        dict: A dictionary containing the results of the network and syscall analyses.
    """
    # static__analyzer = analysis.StaticAnalyzer(profile.static_rules_folder_path)
    # static__analyzer.scan_directory(profile.extracted_path, profile.static_result_path)

    # TODO evaluate and if dangerous, stop the process

    containers.build_sandbox_image(profile.docker_client, profile.sandbox_folder_path, profile.image_tag)
    sandbox_container = containers.create_sandbox_container(profile.docker_client, profile.image_name, secure_mode)    
    # Start network and syscall scans
    sysdig_process = scanning.scan_syscalls(sandbox_container, profile.syscalls_output_path)
    containers.copy_package_to_container(sandbox_container, profile.archives_path, profile.container_dir_path)
    sandbox_container.start()
    tcpdump_container = scanning.scan_network(profile.docker_client, sandbox_container, profile.network_output_path)
    
    sandbox_container.wait()
    containers.get_logs_from_container(sandbox_container, profile.logging_path, True) # TODO true z profile.verbose
    scanning.stop_network_scan(tcpdump_container, profile.network_output_path)
    sysdig_process.kill()

    # Analyze network artefacts
    network_artefacts = analysis.parse_network_artefacts(profile.network_output_path)

    # Analyze syscall artefacts
    syscalls_artefacts = analysis.analyse_syscalls_artefacts(profile.falco_config_path, profile.syscalls_result_path)
    # Clean up
    sandbox_container.stop()
    sandbox_container.remove(force=True)


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
