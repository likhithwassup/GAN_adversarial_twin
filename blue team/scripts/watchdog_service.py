import time
import os
import glob
import json
from threat_intel import generate_shap_alert 

# THE FIX: Change from a Set to a Dictionary to track "Last Modified" times
processed_files = {} 

def scan_for_malware(path):
    search_pattern = os.path.join(path, "*.json")
    current_files = glob.glob(search_pattern)
    
    for filepath in current_files:
        try:
            # 1. Get the exact millisecond the file was last saved/modified
            current_mtime = os.path.getmtime(filepath)
            
            # 2. Trigger ONLY IF it's a brand new file OR the timestamp changed
            if filepath not in processed_files or processed_files[filepath] != current_mtime:
                
                # Skip empty files (user is still pasting data)
                if os.path.getsize(filepath) == 0:
                    continue 

                # Try reading the JSON
                with open(filepath, 'r') as f:
                    data = json.load(f)

                # FIRE THE ALARM
                print(f"\n[!] ALERT: Evasive Malware Detected/Updated: {os.path.basename(filepath)}", flush=True)
                print("[+] Initializing SHAP Explainer...", flush=True)
                
                generate_shap_alert(filepath)
                
                # 3. Update our memory with the new timestamp so we don't scan it again until it changes
                processed_files[filepath] = current_mtime
                
        except json.JSONDecodeError:
            # User is mid-paste, ignore for now
            pass
        except Exception as e:
            # SAFETY NET: If anything else goes wrong, print the error but DON'T CRASH
            print(f"[!] Error processing {filepath}: {e}", flush=True)

if __name__ == "__main__":
    # Using our secure .env vault!
    target_path = os.getenv("WATCH_DIRECTORY", "./output")
    
    if not os.path.exists(target_path):
        os.makedirs(target_path)
        
    print(f"[*] Blue Team Orchestrator is LIVE. Scanning {target_path} every 2 seconds...", flush=True)

    try:
        while True:
            scan_for_malware(target_path)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[!] Orchestrator shutting down.", flush=True)