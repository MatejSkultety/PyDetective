import docker
import tarfile
import zipfile
from io import BytesIO
import subprocess
import os
import shutil

from . import profile


def build_sandbox_image(client: docker.client, build_path: str, image_tag: str) -> docker.models.images.Image:
    """
    Build a Docker image for the sandbox environment.
    The image is built from the Dockerfile located in the `src/sandbox` directory.
    The image is tagged as "pydetective_sandbox_container".

    Args:
        client (docker.client): The Docker client instance.
        build_path (str): The path to the directory containing the Dockerfile.
        image_tag (str): The tag to assign to the built image.

    Returns:
        docker.models.images.Image: The created Docker image.
    """
    print("PyDetective debug: Building sandbox image")
    sandbox_image = client.images.build(
        path=build_path,
        tag=image_tag,
    )
    print("PyDetective debug: Sandbox image built: ", sandbox_image[0].tags, sandbox_image[0].short_id)
    return sandbox_image


def create_docker_command() -> list[str]:
    """
    Create a Docker command to run a container with the specified package.

    Args:
        None
    
    Returns:
        list[str]: The command to run the Docker container.
    """
    # TODO add options and checks
    # command = ["sh", "-c", f"pip install --no-cache-dir --break-system-packages ./{file_name} && ls /app"]
    # command = ['sh', '-c', 'ls /app/archives']
    command = ["python3", "/app/executor.py"]
    print("PyDetective debug: Docker command: ", command)
    return command


def create_sandbox_container(client: docker.client, image_name: str, secure_mode: bool = False) -> docker.models.containers.Container:
    """
    Create a Docker container for the sandbox environment.
    The container is based on the image specified by `image_name`.
    The container runs a command to install the specified requirements.

    Args:
        client (docker.client): The Docker client instance.
        image_name (str): The name of the Docker image to use.
        secure_mode (bool): Flag to indicate if secure mode is enabled. Defaults to False.

    Returns:
        docker.models.containers.Container: The created Docker container.
    """
    command = create_docker_command()
    sandbox_container = client.containers.create(
        image_name,
        stdin_open=True,
        tty=True,
        detach=True,
        command=command,
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


def get_logs_from_container(sandbox_container: docker.models.containers.Container, destination_path: str, verbose: bool) -> None:
    """
    Attach to the logs of a Docker container and print them to the console or save them to a file.
    The logs are streamed in real-time.

    Args:
        sandbox_container (docker.models.containers.Container): The Docker container instance.
        destination_path (str): The path to the file where logs will be saved.
        verbose (bool): Flag to indicate if verbose logging is enabled. If True, logs are printed to the console.

    Returns:
        None
    """
    logs = sandbox_container.logs()
    with open(destination_path, "a") as log_file:
        log_file.write(logs.decode("utf-8"))
    if verbose:
        print(logs.decode("utf-8"))


def download_package(profile: profile.Profile) -> str:
    """
    Downloads a Python package using `pip download`, extracts it, and returns the name of the downloaded package folder.

    Args:
        profile (profile.Profile): The profile instance containing configuration.
        
    Returns:
        str: Path to the downloaded package folder.
    """
    # Make sure the destination is clean
    delete_package(profile.archives_path)
    delete_package(profile.extracted_path)
    try:
        downloader = subprocess.Popen(f"pip download -d {profile.archives_path} {profile.package_name}", shell=True, stdout=subprocess.PIPE)
        downloader.wait()
    except Exception as e:
        raise Exception(f"Failed to download package: {e}")
    extract_package(profile.archives_path, profile.extracted_path)
    return profile.archives_path


def extract_package(archives_path: str, extraction_path: str) -> None:
    """
    Extracts package archives from the specified path to the extraction path.

    Args:
        archives_path (str): Path to the folder containing package archives.
        extraction_path (str): Path to the folder where the archives will be extracted.

    Returns:
        None
    """
    archives = [f for f in os.listdir(archives_path)]
    if not archives:
        raise Exception("Package wasn't downloaded successfully.")
    for archive in archives:
        archive_path = os.path.join(archives_path, archive)
        if archive.endswith(".whl") or archive.endswith(".zip"):
            try:
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extraction_path)
            except Exception as e:
                if archive_path and os.path.exists(archive_path):
                    os.remove(archive_path)
                raise Exception(f"Failed to extract zip package: {e}")
        else:    
            try:
                with tarfile.open(archive_path) as tar_ref:
                    tar_ref.extractall(path=extraction_path)
            except Exception as e:
                if archive_path and os.path.exists(archive_path):
                    os.remove(archive_path)
                raise Exception(f"Failed to extract tar package: {e}")


def delete_package(delete_path: str) -> None:
    """
    Deletes the specified package directory.

    Args:
        delete_path (str): The path to the package directory to be deleted.

    Returns:
        None
    """
    if os.path.exists(delete_path):
        try:
            shutil.rmtree(delete_path)
        except Exception as e:
            print(f"Error deleting package: {e}")
