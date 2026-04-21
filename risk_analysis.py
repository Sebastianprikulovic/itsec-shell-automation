import json
import csv

# --- Läs JSON ---
with open("events.json") as f:
    events = json.load(f)["events"]

# --- Läs CSV ---
users = {}

with open("users.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        users[row["username"]] = {
            "status": row["status"],
            "fails": 0
        }

# --- Räkna fails ---
for event in events:
    if event["event"] == "failed_login":
        user = event["user"]
        if user in users:
            users[user]["fails"] += 1

# --- Riskklassificering ---
def classify(userinfo):
    fails = userinfo["fails"]
    status = userinfo["status"]

    if status == "disabled" and fails > 0:
        return "CRITICAL"
    if fails >= 3:
        return "HIGH"
    if fails >= 1:
        return "MEDIUM"
    return "LOW"

# --- Loggning ---
with open("risk_report.txt", "w") as report:
    for username, info in users.items():
        risk = classify(info)
        report.write(
            f"{username}: {risk} (fails: {info['fails']}, status: {info['status']})\n"
        )

print("Analysen är klar. Se risk_report.txt")