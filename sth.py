import docker
import subprocess
import time
import json


def run_docker_container(client, image_name):
    """
    Start a Docker container with the specified image.
    
    """

    client.images.pull(image_name)
    container = client.containers.run(
        image_name,
        stdin_open=True,
        tty=True,
        detach=True,
    )
    print(f"PyDetective debug: Container {container.id} started.")
    return container.id


def capture_syscalls(container_id, duration=10, output_file=None, filter_events=None):
    """
    Capture system calls for a specific Docker container using Sysdig.
    
    """
    
    # Construct sysdig filter
    filter_expression = f"container.id={container_id}"
    if filter_events:
        event_filter = " or ".join([f"evt.type={evt}" for evt in filter_events])
        filter_expression += f" and ({event_filter})"
    
    command = ["sysdig", filter_expression]
    
    if output_file:
        with open(output_file, "w") as f:
            process = subprocess.Popen(command, stdout=f, text=True)
    else:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        for line in process.stdout:
            print(line.strip())
    
    # Run for the specified duration
    time.sleep(duration)
    process.terminate()
    print(f"Sysdig capture completed for container {container_id}.")


if __name__ == "__main__":
    print("PyDetective started!")
    client = docker.from_env()
    sysdig_container = run_docker_container(client, "sysdig/sysdig")
    tcpdump_container = run_docker_container(client, "tcpdump")

    sandbox_container = client.containers.create(
        "pandas_test",
        stdin_open=True,
        tty=True,
        detach=True,
    )
    
    duration = int(input("Enter capture duration (seconds): ") or 10)
    
    # Example filter: capturing only 'open' and 'write' system calls
    # filter_events = ["open", "write"]
    
    capture_syscalls(sandbox_container.id, duration)
    
    sandbox_container.start()

    time.sleep(1)
    for container in client.containers.list():
        container.stop()
    print("Good bye, PyDetective!")