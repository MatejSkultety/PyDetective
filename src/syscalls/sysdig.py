import docker
import subprocess

def create_command(sandbox: docker.models.containers.Container, export_file: str) -> list[str]:
    """
    Create the sysdig command inspecting syscalls of sandbox container.
    
    Args:
        sandbox (docker.models.containers.Container): The sandbox container instance.
        export_file (str): The file path to export the sysdig output.

    Returns:
        list[str]: The command to run sysdig.
    """
    command = [f"sudo sysdig -j -pc container.name={sandbox.name} and evt.type!=newfstatat -p'%proc.name %proc.cmdline %proc.args %evt.type %evt.info %evt.arg.flags %fd.name' > {export_file}"]
    print(f"PyDetective debug: Sysdig command: {command}")
    return command


def run_process(sandbox: docker.models.containers.Container, export_file: str) -> subprocess.Popen:
    """
    Create sysdig command and run it in a subprocess.

    Args:
        sandbox (docker.models.containers.Container): Sandbox container instance to inspect.
        export_file (str): The file path to export the sysdig output.

    Returns:
        subprocess.Popen: The process object for the running sysdig command.
    """
    command = create_command(sandbox, export_file)
    process = subprocess.Popen(command, shell=True)

    return process
