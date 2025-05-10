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
    print("PyDetective debug: Building sandbox image")
    sandbox_image = client.images.build(
        path="./sandbox",
        tag="pydetective_sandbox_container:latest",
    )
    print("PyDetective debug: Sandbox image built: ", sandbox_image[0].tags, sandbox_image[0].short_id)
    return sandbox_image


def create_docker_command(package_path: str) -> list[str]:
    """
    Create a Docker command to run a container with the specified package.

    Args:
        package_path (str): The path to the package to be installed.

    Returns:
        list[str]: The command to run the Docker container.
    """
    _, file_name = package_path.rsplit("/", 1)
    # TODO add options and checks
    cmd = ["sh", "-c", f"pip install --no-cache-dir --break-system-packages ./{file_name} && ls /app"]
    print("PyDetective debug: Docker command: ", cmd)
    return cmd


def create_sandbox_container(client: docker.client, image_name: str, package_path: str, secure_mode: bool = False) -> docker.models.containers.Container:
    """
    Create a Docker container for the sandbox environment.
    The container is based on the image specified by `image_name`.
    The container runs a command to install the specified requirements.

    Args:
        client (docker.client): The Docker client instance.
        image_name (str): The name of the Docker image to use.
        package_path (str): The path to the package to be installed.
        secure_mode (bool): Flag to indicate if secure mode is enabled. Defaults to False.

    Returns:
        docker.models.containers.Container: The created Docker container.
    """
    cmd = create_docker_command(package_path)
    sandbox_container = client.containers.create(
        image_name,
        stdin_open=True,
        tty=True,
        detach=True,
        command=cmd,
        network_disabled=secure_mode,
    )
    print("PyDetective debug: Sandbox container created: ", sandbox_container.id)
    return sandbox_container


def extract_file_from_container(container: docker.models.containers.Container, source_path: str, destination_path: str) -> None:
    """
    Extracts a file from a Docker container to the host filesystem.

    Args:
        container (docker.models.containers.Container): The Docker container object.
        source_path (str): The path to the file inside the container.
        to_pdestination_pathath (str): The destination path on the host filesystem.

    Returns:
        None

    Raises:
        docker.errors.APIError: If there is an error communicating with the Docker API.
        Exception: For any other unexpected errors.
    """
    try:
        bits, _ = container.get_archive(source_path)
        tar_stream = BytesIO(b''.join(bits))
        with tarfile.open(fileobj=tar_stream, mode="r|") as tar:
            # containrt.get_archive returns a tar stream, we need to extract it to the specified path
            tar.extractall(path=destination_path)
        print(f"File extracted from {source_path} in container to {destination_path}")
    except docker.errors.APIError as e:
        print(f"Error extracting file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


def copy_package_to_container(container: docker.models.containers.Container, source_path: str, destination_path: str) -> None:
    """
    Copy a package from the host to the Docker container.

    Args:
        container (docker.models.containers.Container): The Docker container object.
        source_path (str): The path to the package on the host.
        destination_path (str): The destination path inside the container.

    Returns:
        None
    """
    try:
        tar_stream = BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.add(source_path, arcname=os.path.basename(source_path))
        tar_stream.seek(0)
        container.put_archive(destination_path, tar_stream)
        print(f"Package {source_path} copied to container at {destination_path}")
    except docker.errors.APIError as e:
        print(f"Error copying package to container: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


def get_logs_from_container(sandbox_container: docker.models.containers.Container, destination_path: str = None) -> None:
    """
    Attach to the logs of a Docker container and print them to the console or save them to a file.
    The logs are streamed in real-time.

    Args:
        sandbox_container (docker.models.containers.Container): The Docker container instance.
        destination_path (str, optional): The path to the file where the logs will be saved. If None, logs are printed to the console.

    Returns:
        None
    """
    logs = sandbox_container.logs()
    if destination_path:
        with open(destination_path, "a") as log_file:
            log_file.write(logs.decode("utf-8"))
    else:
        print(logs.decode("utf-8"))


def download_package(package_name: str, destination_path: str) -> str:
    """
    Downloads a Python package using `pip download`, extracts it, and returns the name of the extracted folder.

    Args:
        package_name (str): The name of the package to download.
        destination_path (str): The directory where the package will be downloaded and extracted.

    Returns:
        str: The name of the extracted folder.

    Raises:
        Exception: If the download or extraction fails.
    """

    # Download the package
    try:
        os.makedirs(destination_path, exist_ok=True)
        downloader = subprocess.Popen(f"pip download -d {destination_path} {package_name}", shell=True, stdout=subprocess.PIPE)
        downloader.wait()
        tar_files = [f for f in os.listdir(destination_path) if f.endswith(".tar.gz")]
        if not tar_files:
            # TODO need to check if it's local package
            return None
        if len(tar_files) > 1:
            raise Exception(f"Multiple tar files found in the destination directory: {len(tar_files)}")
        tar_file_path = os.path.join(destination_path, tar_files[0])
    except Exception as e:
        raise Exception(f"Failed to download package: {e}")
    
    # Extract the package
    try:
        with tarfile.open(tar_file_path, "r:gz") as tar:
            tar.extractall(path=destination_path)
            extracted_folder_name = tar.getnames()[0]

        extracted_folder_path = os.path.join(destination_path, extracted_folder_name)
        renamed_folder_path = os.path.join(destination_path, "downloaded_package")
        if os.path.exists(renamed_folder_path):
            shutil.rmtree(renamed_folder_path)  # Remove existing folder if it exists
        os.rename(extracted_folder_path, renamed_folder_path)
        os.remove(tar_file_path)    # Clean up
        return os.path.join(destination_path, extracted_folder_name)
    except Exception as e:
        if tar_file_path and os.path.exists(tar_file_path):
            os.remove(tar_file_path)
        raise Exception(f"Failed to extract package: {e}")


def delete_package(package_path: str) -> None:
    """
    Deletes the specified package directory.

    Args:
        package_path (str): The path to the package directory to delete.

    Returns:
        None
    """
    if os.path.exists(package_path):
        try:
            shutil.rmtree(package_path)
        except Exception as e:
            print(f"Error deleting package: {e}")
