import hashlib
import os
import json
import sys
import ctypes
import platform
import shutil
import time
import yara
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -------------------------------
# Configuration
# -------------------------------
HASH_FILE = 'hashes.json'
QUARANTINE_DIR = 'quarantine'
BACKUP_DIR = 'backup'
YARA_RULES_FILE = 'rules.yar'
ALERT_LOG = 'alerts.log'
ALLOWED_FILE_TYPES = ['.txt', '.py', '.docx', '.pdf']  # Add allowed extensions
SCRIPT_HASH = None

# -------------------------------
# Admin Check
# -------------------------------
def is_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

if not is_admin():
    print("[ERROR] Admin privileges are required.")
    if platform.system() == "Windows":
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    else:
        print(f"Please run using: sudo python3 {__file__}")
    sys.exit()

# -------------------------------
# Utility Functions
# -------------------------------
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        log_alert(f"Failed to hash {file_path}: {e}", level="ERROR")
        return None

def save_hashes(hashes):
    with open(HASH_FILE, 'w') as f:
        json.dump(hashes, f, indent=4)

def load_hashes():
    if not os.path.exists(HASH_FILE):
        return {}
    with open(HASH_FILE, 'r') as f:
        return json.load(f)

def log_alert(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{level.upper():<7}] [{timestamp}] {message}"
    with open(ALERT_LOG, 'a') as f:
        f.write(formatted + '\n')
    print(formatted)

def is_valid_file_type(file_path):
    return os.path.splitext(file_path)[1].lower() in ALLOWED_FILE_TYPES

def ensure_directories():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

def backup_file(file_path):
    rel_path = os.path.relpath(file_path)
    backup_path = os.path.join(BACKUP_DIR, os.path.basename(rel_path))
    try:
        shutil.copy2(file_path, backup_path)
    except Exception as e:
        log_alert(f"Backup failed for {file_path}: {e}", level="ERROR")

def quarantine_file(file_path):
    ensure_directories()
    try:
        backup_file(file_path)
        dest = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
        shutil.move(file_path, dest)
        log_alert(f"Quarantined: {file_path}", level="ALERT")
    except Exception as e:
        log_alert(f"Failed to quarantine {file_path}: {e}", level="ERROR")

def restore_from_quarantine(filename):
    source = os.path.join(QUARANTINE_DIR, filename)
    dest = os.path.join('.', filename)
    if os.path.exists(source):
        shutil.move(source, dest)
        log_alert(f"{filename} restored from quarantine.", level="INFO")
    else:
        log_alert(f"Restore failed: {filename} not found in quarantine.", level="ERROR")

# -------------------------------
# YARA Threat Detection
# -------------------------------
def run_yara_scan(file_path):
    try:
        rules = yara.compile(filepath=YARA_RULES_FILE)
        matches = rules.match(file_path)
        return matches
    except Exception as e:
        log_alert(f"YARA error on {file_path}: {e}", level="ERROR")
        return []

# -------------------------------
# Tamper Detection
# -------------------------------
def check_script_integrity():
    global SCRIPT_HASH
    script_path = os.path.abspath(__file__)
    current_hash = calculate_hash(script_path)
    if SCRIPT_HASH and current_hash != SCRIPT_HASH:
        log_alert("Script has been tampered with!", level="ALERT")
        sys.exit()
    SCRIPT_HASH = current_hash

# -------------------------------
# File Event Handler
# -------------------------------
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self, baseline, base_dir):
        self.baseline = baseline
        self.base_dir = base_dir

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_event(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.handle_event(event.src_path)

    def handle_event(self, path):
        time.sleep(0.5)
        if not os.path.exists(path):
            log_alert(f"Skipped missing file: {path}", level="SKIPPED")
            return

        rel_path = os.path.relpath(path, self.base_dir)
        current_hash = calculate_hash(path)
        old_hash = self.baseline.get(rel_path)

        if current_hash != old_hash:
            log_alert(f"Detected change in: {rel_path}", level="ALERT")

            if not is_valid_file_type(path):
                log_alert(f"Invalid file type: {rel_path}", level="ERROR")
                quarantine_file(path)
                return

            threats = run_yara_scan(path)
            if threats:
                log_alert(f"YARA threat detected in {rel_path}: {threats}", level="ALERT")
                quarantine_file(path)
                return

            self.baseline[rel_path] = current_hash
            save_hashes(self.baseline)

# -------------------------------
# Main
# -------------------------------
def main():
    check_script_integrity()
    print("\n[INFO   ] File Integrity Checker is running...\n")

    directory = input("Enter the directory to monitor: ").strip()
    if not os.path.isdir(directory):
        print("[ERROR  ] Invalid directory.")
        return

    baseline = load_hashes()
    observer = Observer()
    event_handler = IntegrityHandler(baseline, directory)
    observer.schedule(event_handler, path=directory, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(10)
            check_script_integrity()
    except KeyboardInterrupt:
        print("\n[INFO   ] Monitoring was interrupted by user.")
        choice = input("Do you want to restart monitoring? (y/n): ").strip().lower()
        if choice == 'y':
            main()
        else:
            print("[INFO   ] Exiting the File Integrity Checker.")
            observer.stop()
    observer.join()

if __name__ == '__main__':
    while True:
        try:
            main()
            break
        except Exception as e:
            print(f"[ERROR  ] Unexpected error: {e}")
            print("[INFO   ] Restarting in 5 seconds...")
            time.sleep(5)
