import docker
import docker.models


def createCommand(exportFile: str, ignoredHosts: str = None) -> list:
    """
    Create a command to run tcpdump with the specified parameters.
    
    Args:
        exportFile (str): The path to the file where the tcpdump output will be saved.
        ignoredHosts (str, optional): A comma-separated list of IP addresses to ignore. Defaults to None.
    
    Returns:
        str: The command to run tcpdump.
    """
    ##command = f"tcpdump -i docker0 udp -w {exportFile}"
    command = ["tcpdump", "-N", "-t", "-w", "tcpdump_output.pcap"]
    # command = ["sh", "-c", "tcpdump -N -t > tcpdump_output.log"]
    if ignoredHosts:
        ignoredHostsList = ignoredHosts.split(",")
        for host in ignoredHostsList:
            command += f" and not host {host}"
    print(f"PyDetective debug: Tcpdump command: {command}")
    return command


def create_container(client: docker.client, sandbox: docker.models.containers.Container,exportFile: str, ignoredHosts: str = None):
    """

    """
    command = createCommand(exportFile, ignoredHosts)
    tcpdump_container = client.containers.run(
        image="tcpdump",
        command=command,
        network_mode=f"container:{sandbox.id}",
        tty=True,
        detach=True,
    )
    print("PyDetective debug: Tcpdump container started: ID: ", tcpdump_container.id)
    return tcpdump_container