rule Suspicious_HTTPS_Env_Exfiltration
{
    meta:
        description = "Detects code that exfiltrates environment variables via HTTPS POST request or similar network exfiltration."
        author = "Matej Skultety"
        category = "network_exfiltration"
    strings:
        $env = "os.environ" nocase ascii wide
        $https = "HTTPSConnection" nocase ascii wide
        $post = "POST" nocase ascii wide
        $json = "json.dumps" nocase ascii wide
        $requests = "requests.post" nocase ascii wide
        $env2 = "environ[" nocase ascii wide
        $header = "Content-Type" nocase ascii wide
        $url = "https://" nocase ascii wide
    condition:
        ($env or $env2) and ($https or $requests) and ($post or $url) and ($json or $header)
}

rule Suspicious_SSH_Key_Access
{
    meta:
        description = "Detects code that accesses or modifies SSH keys in ~/.ssh directory or similar credential files."
        author = "Matej Skultety"
        category = "credential_access"
    strings:
        $ssh_dir = ".ssh" nocase ascii wide
        $open_r = "open(" nocase ascii wide
        $id_rsa = "id_rsa" nocase ascii wide
        $id_ed25519 = "id_ed25519" nocase ascii wide
    condition:
        $ssh_dir and ($id_rsa or $id_ed25519) and $open_r
}

rule Suspicious_Password_File_Access
{
    meta:
        description = "Detects code that accesses /etc/passwd, /etc/shadow, SAM, or other sensitive password files."
        author = "Matej Skultety"
        category = "credential_access"
    strings:
        $passwd = "/etc/passwd" nocase ascii wide
        $shadow = "/etc/shadow" nocase ascii wide
        $open = "open(" nocase ascii wide
        $read = "read(" nocase ascii wide
    condition:
        ($passwd or $shadow) and ($open or $read)
}

rule Suspicious_DNS_Exfiltration
{
    meta:
        description = "Detects code that performs DNS-based data exfiltration or constructs suspicious DNS queries."
        author = "Matej Skultety"
        category = "network_exfiltration"
    strings:
        $dns = "example.com" nocase ascii wide
        $leak = "data-leak-" nocase ascii wide
        $socket = "socket.gethostbyname" nocase ascii wide
        $dns_query = "dnspython" nocase ascii wide
        $resolve = "resolve(" nocase ascii wide
    condition:
        ($dns or $leak) and ($socket or $dns_query or $resolve)
}

rule Suspicious_Persistence_Simulation
{
    meta:
        description = "Detects code that creates persistence mechanisms and also updates or writes files."
        author = "Matej Skultety"
        category = "persistence"
        priority = "low"
    strings:
        $cron = "crontab" nocase ascii wide
        $autorun = "autorun" nocase ascii wide
        $schtasks = "schtasks" nocase ascii wide
        $open = "open(" nocase ascii wide
        $write = ".write" nocase ascii wide
        $replace = "os.replace" nocase ascii wide
    condition:
        (any of ($cron, $autorun, $schtasks)) and
        (any of ($open, $write, $replace))
}

rule Suspicious_Obfuscated_Code
{
    meta:
        description = "Detects base64, hex, or binary-encoded code that is decoded and executed dynamically."
        author = "Matej Skultety"
        category = "obfuscation"
        priority = "low"
    strings:
        $base64 = "base64.b64decode" nocase ascii wide
        $exec = "exec(" nocase ascii wide
        $marshal = "marshal.loads" nocase ascii wide
        $compile = "compile(" nocase ascii wide
        $hex = ".fromhex(" nocase ascii wide
        $open = "open(" nocase ascii wide
    condition:
        $open and ($base64 or $hex or $marshal) and ($exec or $compile)
}

rule Suspicious_System_Info_Collection
{
    meta:
        description = "Detects code that collects system information such as username, hostname, OS details, Python version, and environment variables."
        author = "Matej Skultety"
        category = "reconnaissance"
    strings:
        $uname = "platform.uname" nocase ascii wide
        $getuser = "getpass.getuser" nocase ascii wide
        $python_version = "platform.python_version" nocase ascii wide
        $hostname1 = "platform.node" nocase ascii wide
        $hostname2 = "socket.gethostname" nocase ascii wide
        $system = "platform.system" nocase ascii wide
        $env = "os.environ" nocase ascii wide
    condition:
        3 of ($uname, $getuser, $python_version, $hostname1, $hostname2, $system, $env)
}