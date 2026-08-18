import subprocess
import csv
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

output_file = os.path.join(
    BASE_DIR,
    "..",
    "..",
    "datasets",
    "realtime_alerts.csv"
)

# Create CSV if not exists
with open(output_file, "a", newline="") as f:
    writer = csv.writer(f)

    if f.tell() == 0:
        writer.writerow([
            "time",
            "attack_type",
            "process_name",
            "pid",
            "risk_score",
            "risk_level",
            "source",
            "details"
        ])

print("Monitoring Mac sudo failed password attempts...\n")

cmd = [
    "log",
    "stream",
    "--style",
    "compact"
]

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

for line in process.stdout:

    lower_line = line.lower()

    if (
        "incorrect password" in lower_line
        or "authentication failure" in lower_line
        or "failed password" in lower_line
        or "sudo" in lower_line and "fail" in lower_line
    ):

        print("[ALERT] Failed sudo password detected")

        with open(output_file, "a", newline="") as f:
            writer = csv.writer(f)

            writer.writerow([
                datetime.now(),
                "Failed Password Attempt",
                "sudo",
                "N/A",
                75,
                "High",
                "Mac Failed Login Monitor",
                line.strip()
            ])