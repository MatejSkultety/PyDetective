import docker
import subprocess
import time

print("PyDetective started!")
client = docker.from_env()
sysdig_image = client.images.pull("sysdig/sysdig")
sysdig_container = client.containers.run(
    "sysdig/sysdig",
    stdin_open=True,
    tty=True,
    detach=True,
)
print("PyDetective debug: Sysdig container started")
tcpdump_image = client.images.pull("tcpdump")
tcpdump_container = client.containers.run(
    "tcpdump",
    stdin_open=True,
    tty=True,
    detach=True,
)
print("PyDetective debug: Tcpdump container started")
tested_container = client.containers.run(
    "pandas_test",
    stdin_open=True,
    tty=True,
    detach=True,
)
print("PyDetective debug: Tested container started: 'pandas'")
print(tested_container)

subprocess.run([f"sudo sysdig -j -n 3 container.name={tested_container.name} > sysdig_output.json"], shell=True)
print("PyDetective debug: Sysdig output saved to sysdig_output.json")
subprocess.run([f"sudo tcpdump -E json -w tcpdump_output.pcap -i any"], shell=True)
print("PyDetective debug: Tcpdump output saved to tcpdump_output.json")

time.sleep(1)
for container in client.containers.list():
    container.stop()
print("Good bye, PyDetective!")