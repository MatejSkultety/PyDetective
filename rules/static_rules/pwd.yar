rule Detect_Python_Env_Credential_Access
{
    meta:
        description = "Detects Python scripts accessing environment variables for credentials"
        author = "Your Name"
        date = "2025-05-08"
        reference = "Enhanced rule for detecting credential retrieval from environment variables"

    strings:
        // Import statements
        $import_os = "import os"
        $import_environ = "import environ"
        $import_dotenv = "from dotenv import load_dotenv"
        $import_os_dotenv = "import dotenv"

        // Access patterns
        $os_environ_get = /os\.environ\.get\s*\(\s*["']?(password|passwd|pwd|secret|token|api[_-]?key)["']?\s*\)/ nocase
        $os_environ_index = /os\.environ\s*\[\s*["']?(password|passwd|pwd|secret|token|api[_-]?key)["']?\s*\]/ nocase
        $environ_get = /environ\.get\s*\(\s*["']?(password|passwd|pwd|secret|token|api[_-]?key)["']?\s*\)/ nocase
        $env_str = /env\.str\s*\(\s*["']?(password|passwd|pwd|secret|token|api[_-]?key)["']?\s*\)/ nocase

    condition:
        (any of ($import_os, $import_environ, $import_dotenv, $import_os_dotenv)) or
        (any of ($os_environ_get, $os_environ_index, $environ_get, $env_str))
}
