import docker
import tarfile
from io import BytesIO


def extract_file_from_container(container: docker.models.containers.Container, src_path: str, to_path: str) -> None:
    """
    Extracts a file from a Docker container to the host filesystem.

    Args:
        container (docker.models.containers.Container): The Docker container object.
        src_path (str): The path to the file inside the container.
        to_path (str): The destination path on the host filesystem.

    Returns:
        None

    Raises:
        docker.errors.APIError: If there is an error communicating with the Docker API.
        Exception: For any other unexpected errors.
    """
    try:
        bits, _ = container.get_archive(src_path)
        tar_stream = BytesIO(b''.join(bits))
        with tarfile.open(fileobj=tar_stream, mode="r|") as tar:
            # containrt.get_archive returns a tar stream, we need to extract it to the specified path
            tar.extractall(path=to_path)
        print(f"File extracted from {src_path} in container to {to_path}")

    except docker.errors.APIError as e:
        print(f"Error extracting file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


def get_logs_from_container(sandbox_container: docker.models.containers.Container, path: str = None) -> None:
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
        with open(path, "a") as log_file:
            log_file.write(logs.decode("utf-8"))
    else:
        print(logs.decode("utf-8"))
