import os
import hashlib
import shutil

# Load malware signatures
def load_signatures():
    with open("signatures.txt", "r") as f:
        return f.read().splitlines()

# Calculate MD5 hash of a file
def calculate_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# Scan files for malware
def scan_files(directory):
    malware_found = []
    signatures = load_signatures()
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)
            if file_hash in signatures:
                malware_found.append(file_path)
    return malware_found

# Quarantine detected files
def quarantine_files(files):
    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    for file in files:
        shutil.move(file, quarantine_dir)
    print(f"Quarantined files: {files}")


def log_to_file(message):
    with open("antivirus_logs.txt", "a") as log_file:
        log_file.write(message + "\n")

# the main program
if infected_files:
    log_to_file(f"Malware detected: {infected_files}")
    quarantine_files(infected_files)
else:
    log_to_file("No malware detected.")

