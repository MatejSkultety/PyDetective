import docker
import subprocess
import logging

from . import containers


def create_network_command(export_path: str) -> list:
    """
    Create a command to run tcpdump with the specified parameters.
    
    Args:
        export_path (str): The path to the file where the tcpdump output will be saved.

    Returns:
        str: The command to run tcpdump.
    """
    directory, file_name = export_path.rsplit("/", 1)
    command = ["tcpdump", "-N", "-t", "-w", file_name]
    logging.debug(f"Tcpdump command: {command}")
    return command


def scan_network(client: docker.client, sandbox: docker.models.containers.Container, export_path: str):
    """
    Run a Docker container for tcpdump with the specified parameters.

    Args:
        client (docker.client): The Docker client instance.
        sandbox (docker.models.containers.Container): The sandbox container instance.
        export_path (str): The path to the file where the tcpdump output will be saved.
        ignored_hosts (str, optional): A comma-separated list of IP addresses to ignore. Defaults to None.

    Returns:
        docker.models.containers.Container: The created tcpdump container.
    """
    command = create_network_command(export_path)
    tcpdump_container = client.containers.run(
        image="tcpdump",
        command=command,
        network_mode=f"container:{sandbox.id}",
        tty=True,
        detach=True,
    )
    return tcpdump_container


def stop_network_scan(tcpdump_container: docker.models.containers.Container, export_path: str) -> None:
    """
    Stop the network scan, extract the output file from the container and remove the container.
    
    Args:
        tcpdump_container (docker.models.containers.Container): The tcpdump container instance.
        export_path (str): The path to the file where the tcpdump output will be saved.

    Returns:
        None
    """
    directory, file_name = export_path.rsplit("/", 1)
    containers.extract_file_from_container(tcpdump_container, file_name, directory)
    tcpdump_container.stop()
    tcpdump_container.remove(force=True)


def create_syscalls_command(sandbox: docker.models.containers.Container, export_path: str, filters: list[str]) -> list[str]:
    """
    Create the sysdig command inspecting syscalls of sandbox container.
    
    Args:
        sandbox (docker.models.containers.Container): The sandbox container instance.
        export_path (str): The file path to export the sysdig output.
        filters (list[str]): The filter to apply to the sysdig command.

    Returns:
        list[str]: The command to run sysdig.
    """
    if not filters or len(filters) == 0:
        filter_string = f"container.name={sandbox.name}"
    else:
        filter_string = f"container.name={sandbox.name}" + " and " + " and ".join(filters)

    output_format = "%proc.name %proc.cmdline %proc.args %evt.num %evt.dir %evt.type %evt.info %evt.arg.flags %fd.name"
    command = f"sudo sysdig -j -w {export_path} -pc \"{filter_string}\" -p'{output_format}'"
    logging.debug(f"Sysdig command: {command}")
    return command
# sudo sysdig -pc "container.name=zealous_meninsky and not (fd.name contains '/lib/x86_64')" -p'%proc.name %proc.cmdline %proc.args %evt.type %evt.info %evt.arg.flags %fd.name'


def scan_syscalls(sandbox: docker.models.containers.Container, export_path: str, filters: list[str] = None) -> subprocess.Popen:
    """
    Create sysdig command and run it in a subprocess.

    Args:
        sandbox (docker.models.containers.Container): Sandbox container instance to inspect.
        export_path (str): The file path to export the sysdig output.
        filters (list[str], optional): List of custom filters to apply to the sysdig command. Defaults to None.

    Returns:
        subprocess.Popen: The process object for the running sysdig command.
    """
    command = create_syscalls_command(sandbox, export_path, filters)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    return process
