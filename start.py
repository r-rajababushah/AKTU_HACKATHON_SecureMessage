"""Create the project virtual environment if needed, install crypto support, and launch."""
import os
import subprocess
import sys
import venv
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
VENV_DIR = PROJECT_DIR / ".venv"
PYTHON = VENV_DIR / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def main():
    if not PYTHON.exists():
        print("Creating the SecureMessage virtual environment...")
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)

    dependency_check = subprocess.run(
        [str(PYTHON), "-c", "import cryptography"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if dependency_check.returncode != 0:
        print("Installing the cryptography dependency...")
        subprocess.check_call([str(PYTHON), "-m", "pip", "install", "-r", str(PROJECT_DIR / "requirements.txt")])

    os.execv(str(PYTHON), [str(PYTHON), str(PROJECT_DIR / "run_showcase.py")])


if __name__ == "__main__":
    main()
