import docker
import subprocess

from . import containers, scanning, analysis


def analyze_package(client: docker.client, package_path: str, secure_mode: bool = False) -> None:
    """
    Analyze a package by performing network and syscall scans, followed by analysis.

    Args:
        client (docker.client): The Docker client instance.
        package_path (str): Path to the package to analyze.
        secure_mode (bool): Flag to indicate if secure mode is enabled. Defaults to False.

    Returns:
        dict: A dictionary containing the results of the network and syscall analyses.
    """
    # TODO create global variable
    static__analyzer = analysis.StaticAnalyzer("rules/static_rules")
    static__analyzer.scan_directory(package_path, "out/static_result.json")

    # TODO evaluate and if dangerous, stop the process

    containers.build_sandbox_image(client)
    sandbox_container = containers.create_sandbox_container(client, "pydetective_sandbox_container", package_path, secure_mode)
    containers.copy_package_to_container(sandbox_container, package_path, "./app")

    # Paths for output files
    network_output_path = "out/tcpdump_output.pcap"
    syscalls_output_path = "out/sysdig_output.scap"
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
    syscalls_artefacts = analysis.analyse_syscalls_artefacts("config/falco.yaml", "out/syscalls_result.json")

    # Clean up
    sandbox_container.stop()
    sandbox_container.remove(force=True)
