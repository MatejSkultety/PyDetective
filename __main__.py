import docker
import subprocess
import time

from src.network import tcpdump
from src.sandbox import sandbox
from src.syscalls import sysdig
from src.analysis import parser
from src.utils import helpers

# def get_container_network_interface(container_id):
#     """
#     Get the network interface name associated with the Docker container using Docker SDK.
#     """
#     client = docker.from_env()
    
#     try:
#         # Inspect the container's details
#         container = client.containers.get(container_id)
#         networks = container.attrs['NetworkSettings']['Networks']
        
#         # Loop through the networks to find the interface name
#         print(f"# Networks: {len(networks)}")
#         for network_name, network_info in networks.items():
#             # The container could have multiple networks; we take the first one.
#             # Typically, the default bridge network or user-defined network is present here
#             interface_name = network_info.get('NetworkID')
#             container_ip = network_info.get('IPAddress')
            
#             print(f"Container {container_id} is connected to network '{network_name}' with IP address: {container_ip}")
#             print(f"Network Interface (NetworkID) used: {interface_name}")
#             return interface_name
        
#     except docker.errors.NotFound:
#         print(f"Container {container_id} not found.")
#     except Exception as e:
#         print(f"Error: {e}")
    
#     return None


# print("PyDetective started!")
# client = docker.from_env()
# # sysdig_image = client.images.pull("sysdig/sysdig")
# sysdig_container = client.containers.run(
#     "sysdig/sysdig",
#     stdin_open=True,
#     tty=True,
#     detach=True,
# )
# print("PyDetective debug: Sysdig container started")
# # tcpdump_image = client.images.pull("tcpdump/tcpdump")
# tcpdump_container = client.containers.run(
#     "tcpdump",
#     stdin_open=True,
#     tty=True,
#     detach=True,
# )
# print("PyDetective debug: Tcpdump container started")
# tested_container = client.containers.create(
#     "pandas_test",
#     stdin_open=True,
#     tty=True,
#     detach=True,
# )
# print("PyDetective debug: Tested container started: 'pandas'")
# print(tested_container)

# subprocess.Popen([f"sudo sysdig -j container.name={tested_container.name} > sysdig_output.json"], shell=True)
# print("PyDetective debug: Sysdig output saved to sysdig_output.json")
# interface_name = get_container_network_interface(tested_container.id)
# print(f"PyDetective debug: Interface name: {interface_name}")
# subprocess.Popen([f"sudo tcpdump -vvv -i docker0 -E json > tcpdump_output.json"], shell=True)
# print("PyDetective debug: Tcpdump output saved to tcpdump_output.json")

# tested_container.start()

# # time.sleep(1)
# for container in client.containers.list():
#     container.stop()
# print("Good bye, PyDetective!")


#"""

print("PyDetective started!")
client = docker.from_env()

sandbox.createImage(client)
sandbox_container = sandbox.createContainer(client, "progress")
sandbox.runContainer(sandbox_container)
sandbox_container.pause()

# sysdig_container = sysdig.create_container(client, sandbox_container)
subprocess.Popen(sysdig.create_command(sandbox_container, "out/sysdig_output.json"), shell=True)
tcpdump_container = tcpdump.create_container(client, sandbox_container, "test.pcap")

sandbox_container.unpause()
sandbox_container.wait()

tcpdump_container.stop()
helpers.extract_file_from_container(tcpdump_container, "tcpdump_output.pcap", "out")

# sysdig_container.stop()
# sandbox.logContainer(sysdig_container, "out/sysdig.json")

print("Good bye, PyDetective!")
for container in client.containers.list():
    container.stop()
    container.remove(force=True)

print(parser.parse_network_artefacts("out/tcpdump_output.pcap"))
#"""

# test_result = parser.parse_syscalls_artefacts("tmp/sysdig_test_stdout.json")
# print(test_result)