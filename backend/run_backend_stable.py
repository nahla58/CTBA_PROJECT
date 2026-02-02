#!/usr/bin/env python3
import subprocess
import sys

# Run main.py without uvicorn's auto-reload (which causes watch file issues)
if __name__ == '__main__':
    subprocess.run([sys.executable, 'main.py'], env={**dict(os.environ), 'UVICORN_RELOAD': '0'})

import os
subprocess.run([sys.executable, '-m', 'uvicorn', 'main:app', '--host', '0.0.0.0', '--port', '8000'])
