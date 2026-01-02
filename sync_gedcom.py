#!/usr/bin/env python3
"""
GEDCOM Sync Script for MacFamilyTree
=====================================
Watches for changes to your MacFamilyTree file and auto-uploads to server.

Two modes:
1. Watch .rmtree file → prompt to export → upload GEDCOM
2. Watch GEDCOM file directly → auto-upload when it changes

Usage:
  python3 sync_gedcom.py --setup    # Configure settings
  python3 sync_gedcom.py            # Run the watcher
"""

import os
import sys
import time
import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime

# Configuration file
CONFIG_FILE = Path(__file__).parent / ".sync_config.json"

DEFAULT_CONFIG = {
    "rmtree_path": "",
    "gedcom_path": "stefano_full.ged",
    "server_host": "stefanomorello.com",
    "server_user": "",
    "server_path": "/public_html/gen/",
    "watch_mode": "gedcom",  # "gedcom" or "rmtree"
    "check_interval": 5,  # seconds
}


def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            config = json.load(f)
            # Merge with defaults for any missing keys
            return {**DEFAULT_CONFIG, **config}
    return DEFAULT_CONFIG.copy()


def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)  # Private - contains server info
    print(f"✓ Config saved to {CONFIG_FILE}")


def setup_wizard():
    """Interactive setup wizard"""
    print("\n" + "="*50)
    print("GEDCOM Sync Setup")
    print("="*50 + "\n")

    config = load_config()

    # Find available rmtree files
    rmtree_files = list(Path(__file__).parent.glob("*.rmtree"))
    if rmtree_files:
        print("Found MacFamilyTree files:")
        for i, f in enumerate(rmtree_files, 1):
            print(f"  {i}. {f.name}")
        choice = input("\nWhich one to watch? (number or Enter to skip): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(rmtree_files):
            config["rmtree_path"] = str(rmtree_files[int(choice)-1])

    # GEDCOM path
    current_ged = config.get("gedcom_path", "stefano_full.ged")
    ged_input = input(f"\nGEDCOM filename [{current_ged}]: ").strip()
    if ged_input:
        config["gedcom_path"] = ged_input

    # Server settings
    print("\n--- Server Settings ---")

    current_host = config.get("server_host", "stefanomorello.com")
    host = input(f"Server hostname [{current_host}]: ").strip()
    if host:
        config["server_host"] = host

    current_user = config.get("server_user", "")
    user = input(f"SSH username [{current_user or 'your-username'}]: ").strip()
    if user:
        config["server_user"] = user

    current_path = config.get("server_path", "/public_html/gen/")
    path = input(f"Server path [{current_path}]: ").strip()
    if path:
        config["server_path"] = path

    # Watch mode
    print("\n--- Watch Mode ---")
    print("1. Watch GEDCOM file (upload when you export from MacFamilyTree)")
    print("2. Watch .rmtree file (notify when MacFamilyTree saves)")
    mode = input("Choose [1]: ").strip()
    config["watch_mode"] = "rmtree" if mode == "2" else "gedcom"

    save_config(config)

    print("\n" + "="*50)
    print("Setup complete! Run 'python3 sync_gedcom.py' to start watching.")
    print("="*50 + "\n")


def get_file_hash(filepath):
    """Get MD5 hash of file for change detection"""
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()


def upload_to_server(config):
    """Upload GEDCOM to server via scp"""
    gedcom_path = Path(__file__).parent / config["gedcom_path"]

    if not gedcom_path.exists():
        print(f"✗ GEDCOM file not found: {gedcom_path}")
        return False

    if not config.get("server_user"):
        print("✗ Server user not configured. Run: python3 sync_gedcom.py --setup")
        return False

    remote = f"{config['server_user']}@{config['server_host']}:{config['server_path']}"

    print(f"↑ Uploading {config['gedcom_path']} to {config['server_host']}...")

    try:
        result = subprocess.run(
            ["scp", "-q", str(gedcom_path), remote],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            print(f"✓ Uploaded successfully at {datetime.now().strftime('%H:%M:%S')}")
            return True
        else:
            print(f"✗ Upload failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print("✗ Upload timed out")
        return False
    except FileNotFoundError:
        print("✗ scp not found. Make sure SSH is configured.")
        return False


def notify_export_needed():
    """Show macOS notification to export GEDCOM"""
    try:
        subprocess.run([
            "osascript", "-e",
            'display notification "MacFamilyTree file changed. Please export GEDCOM." '
            'with title "GEDCOM Sync" sound name "Ping"'
        ], capture_output=True)
    except:
        pass
    print("\n⚠ MacFamilyTree file changed!")
    print("  → Please export GEDCOM: File → Export → GEDCOM")
    print(f"  → Save as: {load_config()['gedcom_path']}")


def watch_files(config):
    """Main file watching loop"""
    gedcom_path = Path(__file__).parent / config["gedcom_path"]
    rmtree_path = Path(config["rmtree_path"]) if config.get("rmtree_path") else None

    print("\n" + "="*50)
    print("GEDCOM Sync Watcher")
    print("="*50)
    print(f"Mode: {'GEDCOM' if config['watch_mode'] == 'gedcom' else '.rmtree'}")
    print(f"Watching: {gedcom_path if config['watch_mode'] == 'gedcom' else rmtree_path}")
    print(f"Server: {config['server_user']}@{config['server_host']}")
    print("="*50)
    print("\nPress Ctrl+C to stop\n")

    # Get initial hashes
    gedcom_hash = get_file_hash(gedcom_path)
    rmtree_hash = get_file_hash(rmtree_path) if rmtree_path else None

    last_upload_hash = gedcom_hash

    try:
        while True:
            time.sleep(config.get("check_interval", 5))

            if config["watch_mode"] == "gedcom":
                # Watch GEDCOM file directly
                new_hash = get_file_hash(gedcom_path)
                if new_hash and new_hash != gedcom_hash:
                    gedcom_hash = new_hash
                    print(f"\n✓ GEDCOM changed at {datetime.now().strftime('%H:%M:%S')}")

                    if new_hash != last_upload_hash:
                        if upload_to_server(config):
                            last_upload_hash = new_hash

            else:
                # Watch .rmtree file
                if rmtree_path:
                    new_hash = get_file_hash(rmtree_path)
                    if new_hash and new_hash != rmtree_hash:
                        rmtree_hash = new_hash
                        notify_export_needed()

                # Still watch GEDCOM for auto-upload after export
                new_ged_hash = get_file_hash(gedcom_path)
                if new_ged_hash and new_ged_hash != gedcom_hash:
                    gedcom_hash = new_ged_hash
                    if new_ged_hash != last_upload_hash:
                        print(f"\n✓ GEDCOM exported at {datetime.now().strftime('%H:%M:%S')}")
                        if upload_to_server(config):
                            last_upload_hash = new_ged_hash

    except KeyboardInterrupt:
        print("\n\nStopped watching.")


def main():
    if "--setup" in sys.argv or "-s" in sys.argv:
        setup_wizard()
        return

    if "--upload" in sys.argv or "-u" in sys.argv:
        config = load_config()
        upload_to_server(config)
        return

    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        print("Options:")
        print("  --setup, -s    Run setup wizard")
        print("  --upload, -u   Upload GEDCOM now")
        print("  --help, -h     Show this help")
        return

    config = load_config()

    if not config.get("server_user"):
        print("First time? Let's set things up.\n")
        setup_wizard()
        config = load_config()

    watch_files(config)


if __name__ == "__main__":
    main()
