import subprocess
import csv
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

realtime_file = os.path.abspath(os.path.join(
    BASE_DIR,
    "..",
    "..",
    "datasets",
    "realtime_alerts.csv"
))

mac_logins_file = os.path.abspath(os.path.join(
    BASE_DIR,
    "..",
    "..",
    "datasets",
    "mac_failed_logins.csv"
))

# Initialize realtime_alerts.csv if missing or empty
if not os.path.exists(realtime_file) or os.path.getsize(realtime_file) == 0:
    with open(realtime_file, "a", newline="") as f:
        writer = csv.writer(f)
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

# Initialize mac_failed_logins.csv if missing or empty
if not os.path.exists(mac_logins_file) or os.path.getsize(mac_logins_file) == 0:
    with open(mac_logins_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "time",
            "attack_type",
            "risk_score",
            "risk_level",
            "source",
            "event"
        ])

print("🛡️ Real-Time Mac Unified Log Monitor Started...", flush=True)
print("Listening to live macOS log stream for authentication & sudo events...\n", flush=True)

cmd = [
    "/usr/bin/log",
    "stream",
    "--style",
    "compact",
    "--predicate",
    'process == "sudo" or process == "loginwindow" or process == "SecurityAgent" or process == "authorizationhost" or process == "opendirectoryd" or process == "coreauthd" or eventMessage contains[c] "password" or eventMessage contains[c] "authFail" or eventMessage contains[c] "authentication failure" or eventMessage contains[c] "incorrect password"'
]

try:
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
except Exception as e:
    print(f"Error launching /usr/bin/log stream: {e}", flush=True)
    sys.exit(1)

MATCH_KEYWORDS = [
    "incorrect password",
    "authfail",
    "authentication failure",
    "failed password",
    "failed to authenticate",
    "sudo",
    "authreq_result",
    "fail"
]

for line in iter(process.stdout.readline, ''):
    if not line:
        break

    lower_line = line.lower()

    if any(kw in lower_line for kw in MATCH_KEYWORDS):
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean_line = line.strip()

        print(f"[ALERT] Mac Security Log Event: {clean_line}", flush=True)

        # Write to realtime_alerts.csv
        try:
            with open(realtime_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp_str,
                    "Mac Failed Login / Sudo Alert",
                    "mac_log_stream",
                    "N/A",
                    75,
                    "High",
                    "Mac Unified Log Monitor",
                    clean_line
                ])
                f.flush()
        except Exception as err:
            print(f"Error writing to realtime_alerts.csv: {err}")

        # Write to mac_failed_logins.csv
        try:
            with open(mac_logins_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp_str,
                    "Mac Failed Login",
                    75,
                    "High",
                    "Mac Unified Log Monitor",
                    clean_line
                ])
                f.flush()
        except Exception as err:
            print(f"Error writing to mac_failed_logins.csv: {err}")