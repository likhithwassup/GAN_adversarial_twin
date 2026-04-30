import json
import os

def generate_shap_alert(filepath):
    # 1. Read the evasive sample data
    with open(filepath, 'r') as f:
        data = json.load(f)

    sample_id = data.get("sample_id", "Unknown_Sample")

    # 2. Mocking the SHAP Analysis 
    alert = {
        "alert_type": "Evasion Detection via SHAP",
        "sample_id": sample_id,
        "threat_intel": f"Alert: Evasive sample detected. The attacker heavily modified Feature #405 (Entropy) and Feature #1012 (Imports) to drop malicious probability.",
        "action_required": "Triggering MLflow retrain pipeline."
    }

    # SAFETY CHECK: Make sure the data folder exists before trying to save!
    os.makedirs("./data", exist_ok=True)

    # 3. Save the alert to the /data folder
    alert_path = f"./data/alert_{sample_id}.json"
    with open(alert_path, 'w') as f:
        json.dump(alert, f, indent=4)

    # THE FIX: Added flush=True so Docker doesn't hide the message!
    print(f"\n[+] THREAT INTEL GENERATED: {alert['threat_intel']}", flush=True)
    print(f"[*] Alert saved to {alert_path}", flush=True)
    print("[*] Resuming background scan...\n", flush=True)