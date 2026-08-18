import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from fastapi import FastAPI
try:
    from database import fetch_alerts
    from jwt_auth import create_access_token
except ImportError:
    from backend.database import fetch_alerts
    from backend.jwt_auth import create_access_token

app = FastAPI()

@app.get("/")
def home():
    return {"message": "SOC Backend Running"}

@app.get("/alerts")
def get_alerts():
    alerts = fetch_alerts()
    return {"alerts": alerts}
@app.post("/login")
def login():

    token = create_access_token(
        {"sub": "socadmin"}
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }