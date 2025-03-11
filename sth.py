import subprocess
import time
import json

def start_docker_container(image_name):
    """Start a Docker container and return its container ID."""
    result = subprocess.run(["docker", "run", "-d", image_name], capture_output=True, text=True)
    container_id = result.stdout.strip()
    print(f"Started container {container_id} from image {image_name}.")
    return container_id

def capture_syscalls(container_id, duration=10, output_file=None, filter_events=None):
    """Capture system calls for a specific Docker container using Sysdig."""
    
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

def stop_docker_container(container_id):
    """Stop and remove the Docker container."""
    subprocess.run(["docker", "stop", container_id], capture_output=True, text=True)
    subprocess.run(["docker", "rm", container_id], capture_output=True, text=True)
    print(f"Stopped and removed container {container_id}.")

if __name__ == "__main__":
    image_name = input("Enter the Docker image name to start: ")
    container_id = start_docker_container(image_name)
    
    duration = int(input("Enter capture duration (seconds): ") or 10)
    output_file = input("Enter output file name (or leave blank for real-time output): ") or None
    
    # Example filter: capturing only 'open' and 'write' system calls
    filter_events = ["open", "write"]
    
    capture_syscalls(container_id, duration, output_file, filter_events)
    
    stop_docker_container(container_id)
