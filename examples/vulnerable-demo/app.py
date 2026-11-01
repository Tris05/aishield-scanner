"""Intentionally insecure fixture for scanner testing. Never deploy this example."""
import pickle
import subprocess


def load_model(path):
    # Intentionally unsafe: do not load untrusted pickle files.
    with open(path, "rb") as f:
        return pickle.load(f)


def run_generated_command(model_output):
    # Intentionally unsafe: model output must not be treated as a shell command.
    return subprocess.run(model_output, shell=True, check=False)
