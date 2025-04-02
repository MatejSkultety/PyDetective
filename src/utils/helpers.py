import docker
import tarfile
from io import BytesIO

def extract_file_from_container(container, src_path, to_path):
    try:
        # Fetch the archive from the container at the specified source path
        bits, _ = container.get_archive(src_path)

        # Create a BytesIO object from the bits (tar content)
        tar_stream = BytesIO(b''.join(bits))

        # Open the tar stream and extract the file
        with tarfile.open(fileobj=tar_stream, mode="r|") as tar:
            # Extract the file (since there's only one file, we can grab the first one)
            tar.extractall(path=to_path)

        print(f"File extracted from {src_path} in container to {to_path}")

    except docker.errors.APIError as e:
        print(f"Error extracting file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")