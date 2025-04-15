import docker
import docker.models


def create_command(export_file: str) -> list:
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


def run_container(client: docker.client, sandbox: docker.models.containers.Container, export_file: str):
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
    command = create_command(export_file)
    tcpdump_container = client.containers.run(
        image="tcpdump",
        command=command,
        network_mode=f"container:{sandbox.id}",
        tty=True,
        detach=True,
    )
    print("PyDetective debug: Tcpdump container started: ID: ", tcpdump_container.id)
    return tcpdump_container
