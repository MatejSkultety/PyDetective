import docker
import subprocess

client = docker.from_env()
print(client.containers.list())
sysdig_container = client.containers.run(
    "sysdig/sysdig",
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


print(client.containers.list())


for container in client.containers.list():
    container.stop()
print("Good bye, Docker!")