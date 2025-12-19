import os
import re

SENSITIVE_KEYWORDS = [
    "password", "passwd", "apikey", "api_key",
    "secret", "token", "private_key"
]

SUSPICIOUS_FILES = [
    "password", "otp", "token", "secret"
]

risk_score = 0

def scan_file(path):
    global risk_score
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                for key in SENSITIVE_KEYWORDS:
                    if key in line.lower():
                        print(f"[HIGH] {path} → contains '{key}'")
                        risk_score += 20
                        return
    except:
        pass

def scan_folder(folder):
    for root, _, files in os.walk(folder):
        for file in files:
            full_path = os.path.join(root, file)

            name = file.lower()
            if any(s in name for s in SUSPICIOUS_FILES):
                print(f"[MED] {full_path} → suspicious filename")
                global risk_score
                risk_score += 10

            if file.endswith((".txt", ".env", ".cfg", ".log")):
                scan_file(full_path)

def main():
    folder = input("Folder to scan: ").strip()
    if not os.path.isdir(folder):
        print("Invalid folder")
        return

    scan_folder(folder)
    print(f"\nRISK SCORE: {risk_score} / 100")

if __name__ == "__main__":
    main()
