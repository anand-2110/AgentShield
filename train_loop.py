
import subprocess
import time
import sys
from pathlib import Path
from datetime import datetime

# Project paths
PROJECT_DIR = Path(__file__).resolve().parent
MAIN_FILE = PROJECT_DIR / "src" / "main.py"

# Settings
WAIT_SECONDS = 5

def run_training_loop():
    run_count = 0

    print("Starting AI training loop...")
    print(f"Target: {MAIN_FILE}")
    print(f"Interval: {WAIT_SECONDS} seconds")
    print("Press Ctrl+C to stop.\n")

    while True:
        run_count += 1
        start_time = datetime.now()

        print(f"[{start_time:%Y-%m-%d %H:%M:%S}] Run #{run_count} starting...")

        try:
            result = subprocess.run(
                [sys.executable, str(MAIN_FILE)],
                cwd=PROJECT_DIR,
                check=False
            )

            print(
                f"Run #{run_count} finished "
                f"with exit code {result.returncode}"
            )

        except Exception as error:
            print(f"Error during run #{run_count}: {error}")

        print(f"Waiting {WAIT_SECONDS} seconds before next run...\n")

        try:
            time.sleep(WAIT_SECONDS)
        except KeyboardInterrupt:
            break

    print("\nLoop stopped. Goodbye!")


if __name__ == "__main__":
    try:
        run_training_loop()
    except KeyboardInterrupt:
        print("\nLoop stopped. Goodbye!")
