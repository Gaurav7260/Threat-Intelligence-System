import os
import time
import requests
import pandas as pd
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

# Load API key
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not ABUSEIPDB_API_KEY:
    raise ValueError("API key not found in .env file")

# Load your exported CSV
input_csv = os.path.join(PROJECT_ROOT, "datasets", "endpoint_risk_logs.csv")
output_csv = os.path.join(PROJECT_ROOT, "datasets", "enriched_endpoint_logs.csv")
df = pd.read_csv(input_csv)

# IMPORTANT:
# Change this if your CSV uses another IP column name
ip_column = "IpAddress"

# Remove empty IPs
df = df[df[ip_column].notna()]

# Keep unique IPs only
unique_ips = df[ip_column].unique()

# Store enrichment results
results = []

# AbuseIPDB URL
url = "https://api.abuseipdb.com/api/v2/check"

headers = {
    "Key": ABUSEIPDB_API_KEY,
    "Accept": "application/json"
}

print(f"Checking {len(unique_ips)} IPs...")

for ip in unique_ips:

    try:
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        response = requests.get(url, headers=headers, params=params)

        data = response.json()["data"]

        results.append({
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "total_reports": data.get("totalReports")
        })

        print(f"[+] Checked {ip}")

        # Avoid API rate limit
        time.sleep(1)

    except Exception as e:
        print(f"[-] Error checking {ip}: {e}")

# Convert results to dataframe
intel_df = pd.DataFrame(results)

# Merge with original logs
merged_df = df.merge(
    intel_df,
    left_on=ip_column,
    right_on="ip",
    how="left"
)

# Save enriched dataset
merged_df.to_csv(output_csv, index=False)

print(f"\nEnriched dataset saved successfully to {output_csv}.")