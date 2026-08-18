import os
import requests
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not ABUSEIPDB_API_KEY:
    raise ValueError("ABUSEIPDB_API_KEY not found. Check your .env file.")

ip = "8.8.8.8"

url = "https://api.abuseipdb.com/api/v2/check"

headers = {
    "Key": ABUSEIPDB_API_KEY,
    "Accept": "application/json"
}

params = {
    "ipAddress": ip,
    "maxAgeInDays": 90
}

response = requests.get(url, headers=headers, params=params)

print(response.json())