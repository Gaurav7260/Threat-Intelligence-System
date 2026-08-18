import os
import requests
import pandas as pd
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VT_API_KEY:
    raise ValueError("VirusTotal API key not found in .env")

indicator = "8.8.8.8"

url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"

headers = {
    "x-apikey": VT_API_KEY
}

response = requests.get(url, headers=headers)
data = response.json()

stats = data["data"]["attributes"]["last_analysis_stats"]

result = {
    "indicator": indicator,
    "malicious": stats.get("malicious", 0),
    "suspicious": stats.get("suspicious", 0),
    "harmless": stats.get("harmless", 0),
    "undetected": stats.get("undetected", 0),
}

output_csv = os.path.join(PROJECT_ROOT, "datasets", "virustotal_results.csv")
df = pd.DataFrame([result])
df.to_csv(output_csv, index=False)

print(f"VirusTotal result saved to {output_csv}")
print(df)