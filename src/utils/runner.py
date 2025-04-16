import docker
import subprocess

from src.network import tcpdump
from src.sandbox import sandbox
from src.syscalls import sysdig
from src.analysis import parser
from src.utils import helpers
from src.library import filters


def install_in_sandbox(requirements: str, network_scan: bool = True, syscalls_scan: bool = True, network_filters: list[str] = None, syscalls_filters: list[str] = None, complete_scan = False) -> None:

    if complete_scan:
        syscalls_filters = None
        network_filters = None
    else:
        network_filters = filters.NETWORK_DEFAULT_FILTERS
        syscalls_filters = filters.SYSCALLS_DEFAULT_FILTERS

    client = docker.from_env()

    sandbox.createImage(client)
    sandbox_container = sandbox.createContainer(client, requirements)
    # TODO don't run and pause, stry to run it paused
    sandbox.runContainer(sandbox_container)
    sandbox_container.pause()

    # TODO store all to scap -> parse to JSON based on filter
    if syscalls_scan:
        sysdig_process = start_syscall_scan(sandbox_container, "out/sysdig_output.json", syscalls_filters)
    if network_scan:
        tcpdump_container = start_network_scan(client, sandbox_container, "out/tcpdump_output.pcap")

    sandbox_container.unpause()
    sandbox_container.wait()

    if syscalls_scan:
        syscalls_artefacts = stop_syscall_scan(sysdig_process, "out/sysdig_output.json")
        print("Syscalls artefacts: ", syscalls_artefacts)
    if network_scan:
        network_artefacts = stop_network_scan(tcpdump_container, "out/tcpdump_output.pcap", network_filters)
        print("Network artefacts: ", network_artefacts)
        
    sandbox_container.stop()
    sandbox_container.remove(force=True)



def start_network_scan(client: docker.client, sandbox: docker.models.containers.Container, out_path: str) -> None:

    tcpdump_container = tcpdump.create_container(client, sandbox, out_path)
    return tcpdump_container


def stop_network_scan(tcpdump_container: docker.models.containers.Container, out_path: str,  ignored_hosts: list[str] = None, ignored_ips: list[str] = None) -> None:
    

    tcpdump_container.stop()
    tcpdump_container.remove(force=True)
    directory, file_name = out_path.rsplit("/", 1)
    helpers.extract_file_from_container(tcpdump_container, file_name, directory)
    network_artefacts, y, z = parser.parse_network_artefacts(out_path, ignored_hosts, ignored_ips)
    return network_artefacts

def start_syscall_scan(sandbox: docker.models.containers.Container, out_path: str) -> None:

    sysdig_process = sysdig.run_process(sandbox, out_path)
    return sysdig_process


def stop_syscall_scan(sysdig_process: subprocess.Popen, out_path: str) -> None:
    sysdig_process.kill()
    syscalls_artefacts = parser.parse_syscalls_artefacts(out_path)
    return syscalls_artefacts
