import docker


def create_command(sandbox: docker.models.containers.Container,exportFile: str) -> list:

    command = [f"sudo sysdig -j -pc container.name={sandbox.name} and evt.type!=newfstatat -p'%proc.name %proc.cmdline %proc.args %evt.type %evt.info %evt.arg.flags %fd.name' > {exportFile}"]
    print(f"PyDetective debug: Sysdig command: {command}")
    return command


def create_container(client: docker.client, sandbox: docker.models.containers.Container):
    """
    Create a Docker container for running sysdig.
    
    Args:
        client (docker.client): The Docker client instance.
        sandbox (docker.models.containers.Container): The sandbox container instance.
    
    Returns:
        docker.models.containers.Container: The created sysdig container.
    """
    command = create_command()
    sysdig_container = client.containers.run(
        "sysdig/sysdig",
        command=command,
        network_mode=f"container:{sandbox.id}",
        stdin_open=True,
        tty=True,
        detach=True,
    )
    print("PyDetective debug: Sysdig container created: ID: ", sysdig_container.id)
    return sysdig_container