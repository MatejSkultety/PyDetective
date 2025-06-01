import sys
import os
import datetime
import pathlib

import setuptools

from src.sample_malicious_package import malicious


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(SCRIPT_DIR)

setuptools.setup(
    name="sample_malicious_package",
    version="0.0.1",
    packages=setuptools.find_packages(where="src"),
    package_dir={"": "src"},
)

try:
    pathlib.Path("/temp").mkdir(parents=True, exist_ok=True)
    with open("/temp/virus_setup.txt", "w", encoding="utf-8") as buffer:
        buffer.write(f"I was here at {datetime.datetime.now()} ;>")
except Exception as e:
    print(f"An error occurred while writing to /temp/virus.txt: {e}")

try:
    malicious.main()
except Exception as e:
    print(f"An error occurred while executing simulated techniques: {e}")
