import sys
import os
from datetime import datetime
from pathlib import Path
from malicious import *

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(SCRIPT_DIR)

[f("__init__.py", True) for f in simulated_techniques]

Path("/temp").mkdir(parents=True, exist_ok=True)
with open("/temp/virus.txt", "w", encoding="utf-8") as buffer:
    buffer.write(f"I was here at {datetime.now()} ;>")
