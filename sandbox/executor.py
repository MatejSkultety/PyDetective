import os
import subprocess
import time


ARCHIVES_PATH = "/app/archives"


def wait_for_archives_path(archives_path: str) -> None:
    """
    Wait until the specified archives path exists and contains files.

    Args:
        archives_path (str): Path to the folder containing package archives.

    Returns:
        None
    """
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Waiting for archives path '{archives_path}' to become valid...")
    while not os.path.exists(archives_path):
        time.sleep(0.001)
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Archives path '{archives_path}' is now valid.")


def install_archives(archives_path: str) -> None:
    """
    Install all package archives in the specified folder using pip.

    Args:
        archives_path (str): Path to folder containing all package archives.

    Returns:
        None
    """
    archives = [f for f in os.listdir(archives_path)]
    if not archives:
        raise Exception("There are no archives to install.")

    for archive in archives:
        archive_path = os.path.join(archives_path, archive)
        try:
            command = f"pip install --no-cache-dir --break-system-packages {archive_path}"
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Installing archive '{archive_path}'...")
            installer = subprocess.Popen(command, shell=True)
            installer.wait()
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Successfully installed '{archive_path}'.")
        except subprocess.CalledProcessError as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] [CONTAINER] Failed to install archive '{archive_path}': {e}")


if __name__ == "__main__":
    """
    This script is intended to run and handle all activities in pydetective sandbox container.
    It waits for the archives path to become valid and then installs all package archives in default path.
    """
    try:
        wait_for_archives_path(ARCHIVES_PATH)
        install_archives(ARCHIVES_PATH)
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] [CONTAINER] {e}")
        exit(1)
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Analysis finished successfully.")
