import docker


def build_image(client: docker.client) -> docker.models.images.Image:
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
        tag="pydetective_sandbox_container:latest",
    )
    print("PyDetective debug: Sandbox image built: ", sandbox_image[0].tags, sandbox_image[0].short_id)
    return sandbox_image


def create_container(client: docker.client, requirements: str) -> docker.models.containers.Container:
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
