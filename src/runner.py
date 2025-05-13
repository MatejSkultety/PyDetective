import subprocess
import sys
import time
import logging

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
    containers.copy_package_to_container(sandbox_container, profile.archives_path, profile.container_dir_path)
    
    
    
    sandbox_container.start()
    sandbox_container.wait()
    containers.get_logs_from_container(sandbox_container)




    """
    # Start network and syscall scans
    sysdig_process = scanning.scan_syscalls(sandbox_container, profile.syscalls_output_path)
    sandbox_container.start()
    sandbox_container.pause()
    tcpdump_container = scanning.scan_network(profile.docker_client, sandbox_container, profile.network_output_path)

    sandbox_container.unpause()
    sandbox_container.wait()

    scanning.stop_network_scan(tcpdump_container, profile.network_output_path)
    sysdig_process.kill()

    # Analyze network artefacts
    network_artefacts = analysis.parse_network_artefacts(profile.network_output_path)

    # Analyze syscall artefacts
    syscalls_artefacts = analysis.analyse_syscalls_artefacts(profile.falco_config_path, profile.syscalls_result_path)
    """
    # Clean up
    sandbox_container.stop()
    sandbox_container.remove(force=True)


def install_package_on_host(profile: profile.Profile, package_path: str) -> None:
    """
    Install a package on the host system..

    Args:
        profile (profile.Profile): The profile instance containing configuration.
        package_path (str): Path to the package to install.

    Returns:
        None
    """
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Installing package '{profile.package_name}' on host environment ...")
    logging.info(f"Installing package '{profile.package_name}' on host environment")
    try:
        command = f""
        subprocess.Popen()
    except subprocess.CalledProcessError as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Failed to install package '{profile.package_name}': {e}")
        logging.error(f"Failed to install package '{profile.package_name}': {e}")
        print("\nExiting program ...\n")
        sys.exit(1)