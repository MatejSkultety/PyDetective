import docker
import tarfile
import io
import os

def createImage(client: docker.client) -> docker.models.images.Image:
    """
    Build a Docker image for the sandbox environment.
    The image is built from the Dockerfile located in the `src/sandbox` directory.
    The image is tagged as "pydetective_sandbox_container".

    Args:
        client (docker.client): The Docker client instance.
    Returns:
        docker.models.images.Image: The created Docker image.
    """
    # TODO file object can be used instead of real file
    # TODO choose pip and python version
    print("PyDetective debug: Building sandbox image")
    sandbox_image = client.images.build(
        path="./src/sandbox",
        tag="pydetective_sandbox_container"
    )
    print("PyDetective debug: Sandbox image built: ", sandbox_image[0].tags)
    return sandbox_image


def createContainer(client: docker.client, requirements: str) -> docker.models.containers.Container:
    """
    Create a Docker container for the sandbox environment.
    The container is based on the "pydetective_sandbox_container" image.
    The container runs a command to install the specified requirements.

    Args:
        client (docker.client): The Docker client instance.
        requirements (str): Package to be installed or the path to the requirements file to install.
    Returns:
        docker.models.containers.Container: The created Docker container.
    """
    cmd = ["pip", "install", "--no-cache-dir", requirements]
    #cmd = ["sh", "-c", f"pip install --no-cache-dir {requirements}"]
    #cmd = ["sh", "-c", f"tcpdump udp"]
    print("PyDetective debug: Creating sandbox container with command: ", cmd)
    sandbox_container = client.containers.create(
        "pydetective_sandbox_container",
        stdin_open=True,
        tty=True,
        detach=True,
        command=cmd,
    )
    print("PyDetective debug: Sandbox container created: ", sandbox_container.id)
    return sandbox_container


def runContainer(sandbox_container: docker.models.containers.Container) -> None:
    """
    Start a Docker container that was created for the sandbox environment.
    This function executes the command specified during the container creation
    (e.g., pip install).

    Args:
        sandbox_container (docker.models.containers.Container): The Docker container instance.
    Returns:
        None
    """
    print("PyDetective debug: Starting sandbox container")
    sandbox_container.start()
    print("PyDetective debug: Sandbox container started: ", sandbox_container.id)


def logContainer(sandbox_container: docker.models.containers.Container, path: str = None) -> None:
    """
    Attach to the logs of a Docker container and print them to the console or save them to a file.
    The logs are streamed in real-time.

    Args:
        sandbox_container (docker.models.containers.Container): The Docker container instance.
        path (str, optional): The path to the file where the logs will be saved. If None, logs are printed to the console.

    Returns:
        None
    """
    logs = sandbox_container.logs()
    if path:
        with open(path, "w") as log_file:
            log_file.write(logs.decode("utf-8"))
    else:
        print(logs.decode("utf-8"))


def get_container_files(container: docker.models.containers.Container, src: str, target: str) -> None:
    """
    Download a file from a Docker container to the host machine.

    Args:
        container (docker.models.containers.Container): The Docker container instance.
        

    Returns:
        None
    """
    with open(target, "w") as trg_file:
        archive_stream, stat = container.get_archive(src)
        tar_data = b''.join(archive_stream)
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r|*") as tar:
            for member in tar:
                with tar.extractfile(member) as src_file:
                    trg_file.write(src_file.read().decode('utf-8'))
    print(f"PyDetective debug: File {src} downloaded from container {container.id}")
