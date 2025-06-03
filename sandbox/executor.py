import argparse
import importlib
import os
import re
import subprocess
import time
import pkgutil


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


def import_packages(archives_path: str) -> None:
    """
    Try to import each installed package by inferring its name from the archive filename.

    Args:
        archives_path (str): Path to folder containing all package archives.

    Returns:
        None
    """
    archives = [f for f in os.listdir(archives_path)]
    for archive in archives:
        pkg_name = re.match(r"^(.*)-\d", archive)
        if pkg_name:
            pkg_name = pkg_name.group(1)
        else:
            pkg_name = archive.split('.')[0]
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Trying to import '{pkg_name}' ...")
        try:
            importlib.import_module(pkg_name)
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Successfully imported '{pkg_name}'.")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [WARNING] [CONTAINER] Could not import '{pkg_name}': {e}")


def scan_sandbox() -> None:
    """
    Scan the entire sandbox OS after package installation using ClamAV.
    This function scans common directories for malware and saves the output to a file.

    Args:
        None

    Returns:
        None
    """
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Scanning entire sandbox OS ...")
    target_directories = "/home /tmp /var/tmp /etc /boot /usr/local/bin /lib /lib64 /usr/lib"
    command = f"clamscan -i -r {target_directories} > {DEEPSCAN_OUTPUT}"
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
        import_packages(ARCHIVES_PATH)
        if args.deep:
            scan_sandbox()
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] [CONTAINER] {e}")
        exit(1)
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] [CONTAINER] Analysis finished successfully.")
