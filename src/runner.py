import logging
import os
import subprocess
import sys
import time

from . import analysis, containers, evaluation, profile, scanning


def analyze_package(profile: profile.Profile) -> str:
    """
    Analyze a package by performing network and syscall scans, followed by analysis.
    This function performs static analysis, builds a sandbox image, creates a sandbox container,
    starts syscall and network scans, and evaluates the results. It also handles deep analysis if specified.

    Args:
        profile (profile.Profile): The profile instance containing configuration.

    Returns:
        verdict (str): The verdict of the analysis.
    """
    logging.info(f"ANALYZING PACKAGE: {profile.package_name}")
    logging.info("Starting static analysis of package")
    if not profile.args.quiet:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Starting static analysis of package...")
    analysis.scan_directory(profile.extracted_path, profile.yara_rules ,profile.static_result_path)
    
    static_result = evaluation.evaluate_static_results(profile)
    logging.info("Static results evaluated")
    if not profile.args.quiet:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Static results evaluated.")

    if static_result["verdict"] == evaluation.Verdict.MALICIOUS.value and profile.args.secure:
        print(f"[{time.strftime('%H:%M:%S')}] [WARNING] Package is detected as MALICIOUS by static analysis. Stopping the process ...")
        logging.error(f"Package is detected as MALICIOUS by static analysis. Stopping the process ...")
        return static_result["verdict"]

    logging.info("Building Docker images")
    if not profile.args.quiet:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Building Docker images...")
    containers.build_image(profile.docker_client, profile.sandbox_folder_path, profile.image_tag)
    containers.build_image(profile.docker_client, profile.tcpdump_path, profile.tcpdump_image_tag)

    logging.info("Creating sandbox container")
    if profile.args.verbose:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating sandbox container...")
    sandbox_container = containers.create_sandbox_container(profile)    

    logging.info("Starting syscall scan")
    if profile.args.verbose:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Starting syscall scan...")
    sysdig_process = scanning.scan_syscalls(sandbox_container, profile.syscalls_output_path, profile.ignored_syscalls)

    logging.info("Copying package to container")
    if profile.args.verbose:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Copying package to container...")
    containers.copy_package_to_container(sandbox_container, profile.archives_path, profile.container_dir_path)

    logging.info("Starting sandbox container")
    if not profile.args.quiet:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Starting sandbox container...")
    sandbox_container.start()

    logging.info("Starting network scan")
    if profile.args.verbose:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Starting network scan...")
    tcpdump_container = scanning.scan_network(profile.docker_client, sandbox_container, profile.network_output_path)

    if profile.args.deep:
        logging.info("Performing deep analysis of sandbox container")
        if not profile.args.quiet:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Performing deep analysis of sandbox container. This could take several minutes...")

    sandbox_container.wait()
    containers.get_logs_from_container(sandbox_container, profile.logging_path, profile.args.verbose)
    if profile.args.deep:
        containers.extract_file_from_container(sandbox_container, profile.deepscan_output_path, profile.output_folder_path)
    scanning.stop_network_scan(tcpdump_container, profile.network_output_path)
    sysdig_process.kill()

    logging.info("Instalation complete. Removing sandbox container")
    if not profile.args.quiet:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Instalation complete. Removing sandbox container...")
    sandbox_container.stop()
    sandbox_container.remove(force=True)

    logging.info("Analyzing syscall artefacts")
    if profile.args.verbose:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Analyzing syscall artefacts...")
    analysis.analyse_syscalls_artefacts(profile.falco_config_path, profile.syscalls_result_path)

    logging.info("Analyzing network artefacts")
    if profile.args.verbose:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Analyzing network artefacts...")
    analysis.analyse_network_artefacts(profile)
    
    logging.info("Evaluating final package verdict")
    if profile.args.verbose:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Evaluating final package verdict...")
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
        print("Exiting program ...")
        sys.exit(1)
