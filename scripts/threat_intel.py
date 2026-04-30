import json
import os

def generate_shap_alert(filepath):
    # 1. Read the evasive sample data the AI Guy dropped
    with open(filepath, 'r') as f:
        data = json.load(f)

    sample_id = data.get("sample_id", "Unknown_Sample")

    # 2. Mocking the SHAP Analysis (Person 1 will add the real math here later)
    # This generates the human-readable Threat Intel
    alert = {
        "alert_type": "Evasion Detection via SHAP",
        "sample_id": sample_id,
        "threat_intel": f"Alert: Evasive sample detected. The attacker heavily modified Feature #405 (Entropy) and Feature #1012 (Imports) to drop malicious probability.",
        "action_required": "Triggering MLflow retrain pipeline."
    }

    # 3. Save the alert to the /data folder so the Dashboard Guy can display it
    alert_path = f"./data/alert_{sample_id}.json"
    with open(alert_path, 'w') as f:
        json.dump(alert, f, indent=4)

    print(f"\n[+] THREAT INTEL GENERATED: {alert['threat_intel']}")