import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

import time
import random
try:
    from database import insert_alert
except ImportError:
    from backend.database import insert_alert

attack_types = [
    "Brute Force Attack",
    "DDoS Attack",
    "Suspicious PowerShell",
    "SQL Injection",
    "Malware Activity",
    "Privilege Escalation"
]

risk_levels = ["Low", "Medium", "High"]

sources = [
    "Firewall Logs",
    "Endpoint Logs",
    "SIEM Engine",
    "IDS Sensor",
    "Threat Intel Feed"
]

while True:

    attack = random.choice(attack_types)
    risk = random.choice(risk_levels)

    if risk == "High":
        score = random.randint(80, 100)
    elif risk == "Medium":
        score = random.randint(50, 79)
    else:
        score = random.randint(10, 49)

    source = random.choice(sources)

    details = f"Detected {attack} from {source}"

    insert_alert(
        attack,
        risk,
        score,
        source,
        details
    )

    print(f"[+] Inserted: {attack}")

    time.sleep(5)