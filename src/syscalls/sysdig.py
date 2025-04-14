import docker
import subprocess

def create_command(sandbox: docker.models.containers.Container, export_file: str, filters: list[str]) -> list[str]:
    """
    Create the sysdig command inspecting syscalls of sandbox container.
    
    Args:
        sandbox (docker.models.containers.Container): The sandbox container instance.
        export_file (str): The file path to export the sysdig output.
        filters (list[str]): The filter to apply to the sysdig command.

    Returns:
        list[str]: The command to run sysdig.
    """
    if len(filters) == 0:
        filter_string = ""

    else:
        filter_string = "and " + " and ".join(filters) + " "
    command = [f"sudo sysdig -j -pc container.name={sandbox.name} {filter_string}-p'%proc.name %proc.cmdline %proc.args %evt.type %evt.info %evt.arg.flags %fd.name' > {export_file}"]
    print(f"PyDetective debug: Sysdig command: {command}")
    return command


def run_process(sandbox: docker.models.containers.Container, export_file: str, filters: list[str] = None) -> subprocess.Popen:
    """
    Create sysdig command and run it in a subprocess.

    Args:
        sandbox (docker.models.containers.Container): Sandbox container instance to inspect.
        export_file (str): The file path to export the sysdig output.
        filters (list[str], optional): List of custom filters to apply to the sysdig command. Defaults to None.

    Returns:
        subprocess.Popen: The process object for the running sysdig command.
    """
    # filters=["evt.type!=newfstatat"]
    command = create_command(sandbox, export_file, filters)
    process = subprocess.Popen(command, shell=True)

    return process
