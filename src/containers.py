import docker
import tarfile
from io import BytesIO
import subprocess
import os
import shutil


def build_sandbox_image(client: docker.client) -> docker.models.images.Image:
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
        path="./sandbox",
        tag="pydetective_sandbox_container:latest",
    )
    print("PyDetective debug: Sandbox image built: ", sandbox_image[0].tags, sandbox_image[0].short_id)
    return sandbox_image


def create_sandbox_container(client: docker.client) -> docker.models.containers.Container:
    """
    Create a Docker container for the sandbox environment.
    The container is based on the "pydetective_sandbox_container" image.
    The container runs a command to install the specified requirements.

    Args:
        client (docker.client): The Docker client instance.

    Returns:
        docker.models.containers.Container: The created Docker container.
    """
    cmd = ["sh", "-c", "pip install --no-cache-dir --break-system-packages ./downloaded_package && ls /app"]
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


def copy_package_to_container(container: docker.models.containers.Container, src_path: str, to_path: str) -> None:
    """
    Copy a package from the host to the Docker container.

    Args:
        container (docker.models.containers.Container): The Docker container object.
        src_path (str): The path to the package on the host.
        to_path (str): The destination path inside the container.

    Returns:
        None
    """
    try:
        tar_stream = BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.add(src_path, arcname=os.path.basename(src_path))
        tar_stream.seek(0)

        container.put_archive(to_path, tar_stream)
        print(f"Package {src_path} copied to container at {to_path}")
    except docker.errors.APIError as e:
        print(f"Error copying package to container: {e}")
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


def download_package(package_name: str, destination: str) -> str:
    """
    Downloads a Python package using `pip download`, extracts it, and returns the name of the extracted folder.

    Args:
        package_name (str): The name of the package to download.
        destination (str): The directory where the package will be downloaded and extracted.

    Returns:
        str: The name of the extracted folder.

    Raises:
        Exception: If the download or extraction fails.
    """
    tar_file_path = None

    # Download the package
    try:
        os.makedirs(destination, exist_ok=True)
        downloader = subprocess.Popen(f"pip download -d {destination} {package_name}", shell=True, stdout=subprocess.PIPE)
        downloader.wait()
        tar_files = [f for f in os.listdir(destination) if f.endswith(".tar.gz")]
        if not tar_files:
            # need to check if it's local package
            return None
        if len(tar_files) > 1:
            raise Exception(f"Multiple tar files found in the destination directory: {len(tar_files)}")
        tar_file_path = os.path.join(destination, tar_files[0])
    except Exception as e:
        raise Exception(f"Failed to download package: {e}")

    # Extract the package
    try:
        with tarfile.open(tar_file_path, "r:gz") as tar:
            tar.extractall(path=destination)
            extracted_folder_name = tar.getnames()[0]

        extracted_folder_path = os.path.join(destination, extracted_folder_name)
        renamed_folder_path = os.path.join(destination, "downloaded_package")
        if os.path.exists(renamed_folder_path):
            shutil.rmtree(renamed_folder_path)  # Remove existing folder if it exists
        os.rename(extracted_folder_path, renamed_folder_path)

        os.remove(tar_file_path)
        return os.path.join(destination, extracted_folder_name)
    except Exception as e:
        if tar_file_path and os.path.exists(tar_file_path):
            os.remove(tar_file_path)
        raise Exception(f"Failed to extract package: {e}")
