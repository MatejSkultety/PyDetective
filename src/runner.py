import docker
import subprocess

import containers
import scanning
import analysis


# def install_in_sandbox(requirements: str, network_scan: bool = True, syscalls_scan: bool = True, network_filters: list[str] = None, syscalls_filters: list[str] = None, complete_scan = False) -> None:

#     if complete_scan:
#         syscalls_filters = None
#         network_filters = None
#     else:
#         network_filters = filters.NETWORK_DEFAULT_FILTERS
#         syscalls_filters = None

#     client = docker.from_env()

#     sandbox.build_image(client)
#     sandbox_container = sandbox.create_container(client, requirements)
#     # TODO don't run and pause, stry to run it paused
#     sandbox_container.start()
#     sandbox_container.pause()

#     # TODO store all to scap -> parse to JSON based on filter
#     if syscalls_scan:
#         sysdig_process = start_syscall_scan(sandbox_container, "out/sysdig_output.scap", syscalls_filters)
#     if network_scan:
#         tcpdump_container = start_network_scan(client, sandbox_container, "out/tcpdump_output.pcap")

#     sandbox_container.unpause()
#     # instalacia
#     sandbox_container.wait()

#     if syscalls_scan:
#         syscalls_artefacts = stop_syscall_scan(sysdig_process, "out/sysdig_output.json")
#         #print("Syscalls artefacts: ", syscalls_artefacts)
#     if network_scan:
#         network_artefacts = stop_network_scan(tcpdump_container, "out/tcpdump_output.pcap", network_filters)
#         #print("Network artefacts: ", network_artefacts)
        
#     sandbox_container.stop()
#     sandbox_container.remove(force=True)



# def start_network_scan(client: docker.client, sandbox: docker.models.containers.Container, out_path: str) -> None:
#     directory, file_name = out_path.rsplit("/", 1)

#     tcpdump_container = tcpdump.run_container(client, sandbox, file_name)
#     return tcpdump_container


# def stop_network_scan(tcpdump_container: docker.models.containers.Container, out_path: str,  ignored_hosts: list[str] = None, ignored_ips: list[str] = None) -> None:
    


#     directory, file_name = out_path.rsplit("/", 1)
#     helpers.extract_file_from_container(tcpdump_container, file_name, directory)
#     tcpdump_container.stop()
#     tcpdump_container.remove(force=True)
#     network_artefacts, y, z = parser.parse_network_artefacts(out_path, ignored_hosts, ignored_ips)
#     return network_artefacts

# def start_syscall_scan(sandbox: docker.models.containers.Container, out_path: str, filters: list[str] = None) -> None:

#     sysdig_process = sysdig.run_process(sandbox, out_path, filters)
#     return sysdig_process


# def stop_syscall_scan(sysdig_process: subprocess.Popen, out_path: str) -> None:
#     sysdig_process.kill()
#     syscalls_artefacts = parser.parse_syscalls_artefacts(out_path)
#     return syscalls_artefacts


def analyze_package(client: docker.client, package_path: str) -> dict:
    """
    Analyze a package by performing network and syscall scans, followed by analysis.

    Args:
        client (docker.client): The Docker client instance.
        package_path (str): Path to the package to analyze.

    Returns:
        dict: A dictionary containing the results of the network and syscall analyses.
    """
    results = {}
    containers.build_sandbox_image(client)
    sandbox_container = containers.create_sandbox_container(client)


    # Paths for output files
    network_output_path = "out/tcpdump_output.pcap"
    syscalls_output_path = "out/sysdig_output.scap"

    # Start network and syscall scans
    tcpdump_container = scanning.scan_network(client, sandbox_container, network_output_path)
    sysdig_process = scanning.scan_syscalls(sandbox_container, syscalls_output_path)

    sandbox_container.start()
    sandbox_container.wait()

    tcpdump_container.stop()
    tcpdump_container.remove(force=True)

    sysdig_process.kill()

    # Analyze network artefacts
    network_artefacts = analysis.parse_network_artefacts(network_output_path)
    results["network_analysis"] = network_artefacts

    # Analyze syscall artefacts
    syscalls_artefacts = analysis.analyse_syscalls_artefacts(syscalls_output_path)
    results["syscall_analysis"] = syscalls_artefacts

    return results