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

rule Suspicious_Obfuscated_Code_Durin_Instalation
{
    meta:
        description = "Detects base64, hex, or binary-encoded code that is decoded and executed dynamically."
        author = "Matej Skultety"
        category = "obfuscation"
    strings:
        $base64 = "base64.b64decode" nocase ascii wide
        $exec = "exec(" nocase ascii wide
        $marshal = "marshal.loads" nocase ascii wide
        $compile = "compile(" nocase ascii wide
        $hex = ".fromhex(" nocase ascii wide
        $setup = "setup(" nocase ascii wide
    condition:
        ($base64 or $hex or $marshal) and ($exec or $compile) and ($setup)
}

rule Suspicious_System_Info_Collection
{
    meta:
        description = "Detects code that collects system information such as username, hostname, OS details, Python version, and environment variables."
        author = "Matej Skultety"
        category = "reconnaissance"
        priority = "low"
    strings:
        $uname = "platform.uname" nocase ascii wide
        $getuser = "getpass.getuser" nocase ascii wide
        $hostname1 = "platform.node" nocase ascii wide
        $hostname2 = "socket.gethostname" nocase ascii wide
        $system = "platform.system" nocase ascii wide
    condition:
        2 of ($uname, $getuser, $hostname1, $hostname2, $system)
}

rule Suspicious_Process_Execution
{
    meta:
        description = "Detects code that opens or spawns new processes using subprocess or os modules, or executes suspicious commands."
        author = "Matej Skultety"
        category = "execution"
    strings:
        $subprocess_popen = "subprocess.Popen" nocase ascii wide
        $subprocess_call = "subprocess.call" nocase ascii wide
        $subprocess_run = "subprocess.run" nocase ascii wide
        $os_system = "os.system" nocase ascii wide
        $os_popen = "os.popen" nocase ascii wide
        $os_spawn = "os.spawn" nocase ascii wide
        $os_exec = "os.exec" nocase ascii wide

        $cmd2 = "curl " nocase ascii wide
        $cmd3 = "wget " nocase ascii wide
        $cmd7 = "powershell" nocase ascii wide
        $cmd9 = "chmod +x" nocase ascii wide
        $cmd11 = "pip install" nocase ascii wide
        $cmd12 = "kill " nocase ascii wide
        $cmd13 = "useradd" nocase ascii wide
        $cmd14 = "adduser" nocase ascii wide
        $cmd15 = "sudo " nocase ascii wide
        $cmd16 = "ifconfig" nocase ascii wide
        $cmd17 = "ipconfig" nocase ascii wide
        $cmd18 = "netstat" nocase ascii wide
        $cmd19 = "whoami" nocase ascii wide
    condition:
        any of ($subprocess_popen, $subprocess_call, $subprocess_run, $os_system, $os_popen, $os_spawn, $os_exec) and
        any of ($cmd*)
}
