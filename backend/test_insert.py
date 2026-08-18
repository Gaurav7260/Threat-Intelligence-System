import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

try:
    from database import create_tables, insert_alert, fetch_alerts
except ImportError:
    from backend.database import create_tables, insert_alert, fetch_alerts

create_tables()

insert_alert(
    attack_type="Suspicious Process Execution",
    risk_level="High",
    risk_score=85,
    source="Backend Test",
    details="This is a test alert inserted into SQLite database."
)

alerts = fetch_alerts()

for alert in alerts:
    print(alert)