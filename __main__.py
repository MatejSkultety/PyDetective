import docker
import subprocess
import time

client = docker.from_env()
sysdig_container = client.containers.run(
    "sysdig/sysdig",
    stdin_open=True,
    tty=True,
    detach=True,
)
tcpdump_container = client.containers.run(
    "tcpdump",
    stdin_open=True,
    tty=True,
    detach=True,
)
tested_container = client.containers.run(
    "pandas_test",
    stdin_open=True,
    tty=True,
    detach=True,
)
print(tested_container)
print(tested_container.name)

print(subprocess.run([f"sudo sysdig -j -n 3 container.name={tested_container.name} > sysdig_output.json"], shell=True))
print(subprocess.run([f"sudo tcpdump -E json -w tcpdump_output.pcap -i any"], shell=True))

time.sleep(10)
for container in client.containers.list():
    container.stop()
print("Good bye, PyDetective!")