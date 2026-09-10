import psutil
import csv
import time
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

suspicious_keywords = [
    "nmap",
    "tcpdump",
    "wireshark",
    "sqlmap",
    "hydra",
    "john",
    "hashcat",
    "netcat",
    "nc"
]

seen_pids = set()

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

print("Real-time Mac Threat Agent Started...", flush=True)
print("Monitoring real Mac processes...", flush=True)
print("Run nmap/tcpdump/wireshark/sqlmap to test.\n", flush=True)

while True:
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or ""
            cmdline = " ".join(proc.info["cmdline"] or "")
            full_text = f"{name} {cmdline}".lower()

            if pid in seen_pids:
                continue

            for keyword in suspicious_keywords:
                if keyword in full_text:
                    seen_pids.add(pid)

                    alert = [
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "Suspicious Process Execution",
                        name,
                        pid,
                        85,
                        "High",
                        "Mac Real-Time Agent",
                        f"Detected suspicious keyword: {keyword}"
                    ]

                    with open(output_file, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow(alert)
                        f.flush()

                    print(f"[ALERT] {name} detected | PID: {pid} | Keyword: {keyword}", flush=True)
                    break

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(2)