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
        $expanduser = "os.path.expanduser" nocase ascii wide
        $id_rsa = "id_rsa" nocase ascii wide
        $id_ed25519 = "id_ed25519" nocase ascii wide
    condition:
        ($ssh_dir or $id_rsa or $id_ed25519) and $open_r and $expanduser
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
        $sam = "\\SAM" nocase ascii wide
        $open = "open(" nocase ascii wide
        $read = "read(" nocase ascii wide
    condition:
        ($passwd or $shadow or $sam) and ($open or $read)
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
        description = "Detects code that creates persistence mechanisms (e.g., crontab, autorun, registry run keys, systemd)."
        author = "Matej Skultety"
        category = "persistence"
    strings:
        $cron = "crontab" nocase ascii wide
        $autorun = "autorun" nocase ascii wide
        $persist_file = "persistence" nocase ascii wide
        $systemd = "systemd" nocase ascii wide
        $schtasks = "schtasks" nocase ascii wide
    condition:
        any of them
}

rule Suspicious_Obfuscated_Code
{
    meta:
        description = "Detects base64, hex, or binary-encoded code that is decoded and executed dynamically."
        author = "Matej Skultety"
        category = "obfuscation"
    strings:
        $base64 = "base64.b64decode" nocase ascii wide
        $exec = "exec(" nocase ascii wide
        $decode = ".decode(" nocase ascii wide
        $marshal = "marshal.loads" nocase ascii wide
        $compile = "compile(" nocase ascii wide
        $hex = ".fromhex(" nocase ascii wide
    condition:
        ($base64 or $hex or $marshal) and ($exec or $compile) and $decode
}

rule Suspicious_Binary_Exec
{
    meta:
        description = "Detects code execution from binary blobs (e.g., exec on decoded bytes, suspicious byte strings)."
        author = "Matej Skultety"
        category = "obfuscation"
    strings:
        $exec = "exec(" nocase ascii wide
        $decode = ".decode('utf-8')" nocase ascii wide
        $bytes = "\\x" nocase ascii wide
        $bytearray = "bytearray(" nocase ascii wide
        $b64 = "b64decode" nocase ascii wide
    condition:
        $exec and ($decode or $b64) and ($bytes or $bytearray)
}
