import docker
import subprocess


def create_network_command(export_file: str) -> list:
    """
    Create a command to run tcpdump with the specified parameters.
    
    Args:
        export_file (str): The path to the file where the tcpdump output will be saved.

    Returns:
        str: The command to run tcpdump.
    """
    command = ["tcpdump", "-N", "-t", "-w", export_file]
    print(f"PyDetective debug: Tcpdump command: {command}")
    return command


def scan_network(client: docker.client, sandbox: docker.models.containers.Container, export_file: str):
    """
    Run a Docker container for tcpdump with the specified parameters.

    Args:
        client (docker.client): The Docker client instance.
        sandbox (docker.models.containers.Container): The sandbox container instance.
        export_file (str): The path to the file where the tcpdump output will be saved.
        ignored_hosts (str, optional): A comma-separated list of IP addresses to ignore. Defaults to None.

    Returns:
        docker.models.containers.Container: The created tcpdump container.
    """
    command = create_network_command(export_file)
    tcpdump_container = client.containers.run(
        image="tcpdump",
        command=command,
        network_mode=f"container:{sandbox.id}",
        tty=True,
        detach=True,
    )
    print("PyDetective debug: Tcpdump container started: ID: ", tcpdump_container.id)
    return tcpdump_container


def create_syscalls_command(sandbox: docker.models.containers.Container, export_file: str, filters: list[str]) -> list[str]:
    """
    Create the sysdig command inspecting syscalls of sandbox container.
    
    Args:
        sandbox (docker.models.containers.Container): The sandbox container instance.
        export_file (str): The file path to export the sysdig output.
        filters (list[str]): The filter to apply to the sysdig command.

    Returns:
        list[str]: The command to run sysdig.
    """
    if not filters or len(filters) == 0:
        filter_string = ""
    else:
        filter_string = "and " + " and ".join(filters) + " "
        print (f"PyDetective debug: Sysdig filters: {filter_string}")

    output_format = "%proc.name %proc.cmdline %proc.args %evt.type %evt.info %evt.arg.flags %fd.name"
    command = [f"sudo sysdig -j -w {export_file} -pc container.name={sandbox.name} {filter_string} -p'{output_format}'"]
    print(f"PyDetective debug: Sysdig command: {command}")

    return command


def scan_syscalls(sandbox: docker.models.containers.Container, export_file: str, filters: list[str] = None) -> subprocess.Popen:
    """
    Create sysdig command and run it in a subprocess.

    Args:
        sandbox (docker.models.containers.Container): Sandbox container instance to inspect.
        export_file (str): The file path to export the sysdig output.
        filters (list[str], optional): List of custom filters to apply to the sysdig command. Defaults to None.

    Returns:
        subprocess.Popen: The process object for the running sysdig command.
    """
    command = create_syscalls_command(sandbox, export_file, filters)
    process = subprocess.Popen(command, shell=True)

    return process
