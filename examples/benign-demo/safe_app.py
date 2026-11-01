"""Small benign fixture for the AIShield custom-rule smoke benchmark."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def load_settings(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def show_version() -> str:
    result = subprocess.run(["python", "--version"], check=True, capture_output=True, text=True, shell=False)
    return result.stdout or result.stderr
