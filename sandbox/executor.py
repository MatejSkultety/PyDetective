import os
import subprocess
import time
import argparse


ARCHIVES_PATH = "/app/archives"
DEEPSCAN_OUTPUT = "/app/deepscan_result.txt"


def install_archives(archives_path: str) -> None:
    """
    Install all package archives in the specified folder using pip.

    Args:
        archives_path (str): Path to folder containing all package archives.

    Returns:
        None
    """
    time.sleep(0.5) # Wait for the Network scanner to come up
    archives = [f for f in os.listdir(archives_path)]
    if not archives:
        raise Exception("There are no archives to install.")
    for archive in archives:
        archive_path = os.path.join(archives_path, archive)
        try:
            command = f"pip install --break-system-packages {archive_path}"
            print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Installing archive '{archive_path}'")
            installer = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            installer.wait()
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Successfully installed '{archive_path}'.")
        except subprocess.CalledProcessError as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] [CONTAINER] Failed to install archive '{archive_path}': {e}")


def scan_sandbox() -> None:
    """
    Scan the entire sandbox OS after package installation.

    Args:
        None

    Returns:
        None
    """
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Scanning entire sandbox OS ...")
    command = f"clamscan -i -r /home /tmp /var/tmp /etc /boot /usr/local/bin /lib /lib64 /usr/lib > {DEEPSCAN_OUTPUT}"
    subprocess.Popen(command, shell=True).wait()


if __name__ == "__main__":
    """
    This script is intended to run and handle all activities in pydetective sandbox container.
    It waits for the archives path to become valid and then installs all package archives in default path.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--deep', action="store_true", help="Scan entire sandbox OS after package installation")
    args = parser.parse_args()

    try:
        install_archives(ARCHIVES_PATH)
        if args.deep:
            scan_sandbox()
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] [CONTAINER] {e}")
        exit(1)
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Analysis finished successfully.")
