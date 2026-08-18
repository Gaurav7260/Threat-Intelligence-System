import csv
from datetime import datetime
from getpass import getpass

output_file = "../datasets/mac_failed_logins.csv"

correct_password = "demo123"

print("Mac Failed Login Detection Demo")
print("Enter wrong password 2-3 times to simulate failed login.\n")

with open(output_file, "a", newline="") as f:
    writer = csv.writer(f)

    if f.tell() == 0:
        writer.writerow(["time", "attack_type", "risk_score", "risk_level", "source", "event"])

    for attempt in range(1, 4):
        password = getpass("Enter Mac password: ")

        if password != correct_password:
            writer.writerow([
                datetime.now(),
                "Mac Failed Login",
                70,
                "Medium",
                "Mac Local System",
                f"Failed login attempt {attempt}"
            ])
            f.flush()
            print("[ALERT] Failed login detected")
        else:
            print("Login successful")
            break