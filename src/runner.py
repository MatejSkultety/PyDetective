import docker
import subprocess

from . import containers, scanning, analysis, profile


def analyze_package(client: docker.client, profile: profile.Profile, package_path: str, secure_mode: bool = False) -> None:
    """
    Analyze a package by performing network and syscall scans, followed by analysis.

    Args:
        client (docker.client): The Docker client instance.
        profile (profile.Profile): The profile instance containing configuration.
        package_path (str): Path to the package to analyze.
        secure_mode (bool): Flag to indicate if secure mode is enabled. Defaults to False.

    Returns:
        dict: A dictionary containing the results of the network and syscall analyses.
    """
    static__analyzer = analysis.StaticAnalyzer(profile.static_rules_folder_path)
    static__analyzer.scan_directory(package_path, profile.static_result_path)

    # TODO evaluate and if dangerous, stop the process

    containers.build_sandbox_image(client, profile.sandbox_folder_path, profile.image_tag)
    sandbox_container = containers.create_sandbox_container(client, profile.image_name, package_path, secure_mode)
    containers.copy_package_to_container(sandbox_container, package_path, profile.container_dir_path)

    # Paths for output files
    network_output_path = profile.network_output_path
    syscalls_output_path = profile.syscalls_output_path

    # Start network and syscall scans
    sysdig_process = scanning.scan_syscalls(sandbox_container, syscalls_output_path)
    sandbox_container.start()
    sandbox_container.pause()
    tcpdump_container = scanning.scan_network(client, sandbox_container, network_output_path)

    sandbox_container.unpause()
    sandbox_container.wait()

    scanning.stop_network_scan(tcpdump_container, network_output_path)
    sysdig_process.kill()

    # Analyze network artefacts
    network_artefacts = analysis.parse_network_artefacts(network_output_path)

    # Analyze syscall artefacts
    syscalls_artefacts = analysis.analyse_syscalls_artefacts(profile.falco_config_path, profile.syscalls_result_path)

    # Clean up
    sandbox_container.stop()
    sandbox_container.remove(force=True)
