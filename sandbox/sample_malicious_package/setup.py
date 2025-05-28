import sys
import os
import datetime
import pathlib

import setuptools

from src.malicious import *


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(SCRIPT_DIR)

setuptools.setup(name= "sample_malicious_package", packages = setuptools.find_packages(),)

try:
    pathlib.Path("/temp").mkdir(parents=True, exist_ok=True)
    with open("/temp/virus.txt", "w", encoding="utf-8") as buffer:
        buffer.write(f"I was here at {datetime.datetime.now()} ;>")
except Exception as e:
    print(f"An error occurred while writing to /temp/virus.txt: {e}")

try:
    [f("setup.py", True) for f in simulated_techniques]
except Exception as e:
    print(f"An error occurred while executing simulated techniques: {e}")
