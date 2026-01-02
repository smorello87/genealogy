#!/usr/bin/env python3
"""
FamilySearch Tree Sync Script
Pulls complete family trees for multiple starting persons and merges them.
Designed to capture all branches (cousins, distant relatives, etc.)

Usage:
  python sync_familysearch.py --setup          # First time setup
  python sync_familysearch.py --sync           # Run full sync
  python sync_familysearch.py --quick          # Quick sync (fewer generations)
  python sync_familysearch.py --schedule       # Show cron schedule command
"""

import subprocess
import sys
import os
import json
import argparse
from datetime import datetime
from pathlib import Path

# Configuration file path
CONFIG_FILE = Path(__file__).parent / ".familysearch_config.json"
OUTPUT_DIR = Path(__file__).parent / "gedcom_exports"
MERGED_OUTPUT = Path(__file__).parent / "merged_family_tree.ged"

def check_dependencies():
    """Check if getmyancestors is installed"""
    try:
        import getmyancestors
        return True
    except ImportError:
        print("Installing getmyancestors...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "getmyancestors"])
        return True

def load_config():
    """Load configuration from file"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def save_config(config):
    """Save configuration to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)  # Protect credentials
    print(f"Configuration saved to {CONFIG_FILE}")

def setup():
    """Interactive setup for credentials and person IDs"""
    print("\n=== FamilySearch Sync Setup ===\n")

    config = load_config() or {}

    # Credentials
    print("Enter your FamilySearch credentials:")
    username = input(f"Username [{config.get('username', '')}]: ").strip()
    if username:
        config['username'] = username

    password = input("Password (leave blank to keep existing): ").strip()
    if password:
        config['password'] = password

    # Starting persons
    print("\n--- Starting Persons ---")
    print("Find Person IDs in the URL when viewing someone on FamilySearch")
    print("Example: https://www.familysearch.org/tree/person/details/XXXX-XXX")
    print("         The ID is: XXXX-XXX\n")

    persons = config.get('persons', [])

    # Show existing persons
    if persons:
        print("Current starting persons:")
        for i, p in enumerate(persons):
            print(f"  {i+1}. {p.get('name', 'Unknown')} - {p['id']}")

        if input("\nKeep existing persons? [Y/n]: ").strip().lower() == 'n':
            persons = []

    # Add new persons
    while True:
        print(f"\nAdding person {len(persons) + 1}:")
        name = input("  Name (for reference, e.g., 'Me', 'Wife'): ").strip()
        if not name:
            break

        person_id = input("  FamilySearch Person ID: ").strip().upper()
        if not person_id:
            break

        persons.append({
            'name': name,
            'id': person_id
        })

        if input("Add another person? [y/N]: ").strip().lower() != 'y':
            break

    config['persons'] = persons

    # Sync settings
    print("\n--- Sync Settings ---")
    config['ancestor_generations'] = int(input(f"Ancestor generations [{config.get('ancestor_generations', 8)}]: ").strip() or config.get('ancestor_generations', 8))
    config['descendant_generations'] = int(input(f"Descendant generations [{config.get('descendant_generations', 4)}]: ").strip() or config.get('descendant_generations', 4))

    save_config(config)
    print("\nSetup complete! Run 'python sync_familysearch.py --sync' to start syncing.")

def run_getmyancestors(config, person, ancestors=8, descendants=4):
    """Run getmyancestors for a single person"""
    OUTPUT_DIR.mkdir(exist_ok=True)

    output_file = OUTPUT_DIR / f"{person['name'].lower().replace(' ', '_')}_{person['id']}.ged"

    print(f"\nFetching tree for {person['name']} ({person['id']})...")
    print(f"  Ancestors: {ancestors} generations")
    print(f"  Descendants: {descendants} generations")

    cmd = [
        sys.executable, "-m", "getmyancestors",
        "-u", config['username'],
        "-p", config['password'],
        "-i", person['id'],
        "-o", str(output_file),
        "-a", str(ancestors),
        "-d", str(descendants),
        "-c",  # Include all children (captures more branches)
        "-v",  # Verbose output
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # 1 hour timeout

        if result.returncode == 0:
            print(f"  Success! Saved to {output_file}")
            return output_file
        else:
            print(f"  Error: {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        print("  Timeout - tree may be very large. Try reducing generations.")
        return None
    except Exception as e:
        print(f"  Exception: {e}")
        return None

def merge_gedcom_files(input_files, output_file):
    """Merge multiple GEDCOM files into one, deduplicating individuals"""
    print(f"\nMerging {len(input_files)} GEDCOM files...")

    individuals = {}  # id -> lines
    families = {}     # id -> lines
    header_lines = []
    other_records = []

    for filepath in input_files:
        if not filepath or not filepath.exists():
            continue

        print(f"  Processing {filepath.name}...")

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        lines = content.split('\n')
        current_record = []
        current_id = None
        current_type = None
        in_header = False

        for line in lines:
            # Detect record starts
            if line.startswith('0 '):
                # Save previous record
                if current_id and current_record:
                    if current_type == 'INDI':
                        if current_id not in individuals:
                            individuals[current_id] = current_record
                    elif current_type == 'FAM':
                        if current_id not in families:
                            families[current_id] = current_record

                # Parse new record
                parts = line.split(' ', 2)
                if len(parts) >= 2:
                    if parts[1] == 'HEAD':
                        in_header = True
                        current_record = [line]
                        current_id = None
                        current_type = 'HEAD'
                    elif parts[1] == 'TRLR':
                        current_record = []
                        current_id = None
                        current_type = None
                    elif parts[1].startswith('@') and len(parts) >= 3:
                        current_id = parts[1]
                        current_type = parts[2].strip()
                        current_record = [line]
                        in_header = False
                    else:
                        current_record = [line]
                        current_id = None
                        current_type = 'OTHER'
            else:
                current_record.append(line)

                # Capture header (only once)
                if in_header and not header_lines:
                    header_lines = current_record.copy()

    # Write merged file
    print(f"  Writing merged file with {len(individuals)} individuals and {len(families)} families...")

    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        if header_lines:
            f.write('\n'.join(header_lines) + '\n')
        else:
            # Default header
            f.write('0 HEAD\n')
            f.write('1 SOUR FamilySearch Sync\n')
            f.write('1 GEDC\n')
            f.write('2 VERS 5.5.1\n')
            f.write('1 CHAR UTF-8\n')

        # Individuals
        for indi_id, lines in sorted(individuals.items()):
            f.write('\n'.join(lines) + '\n')

        # Families
        for fam_id, lines in sorted(families.items()):
            f.write('\n'.join(lines) + '\n')

        # Trailer
        f.write('0 TRLR\n')

    print(f"  Merged file saved to {output_file}")
    return output_file

def sync(quick=False):
    """Run full sync for all configured persons"""
    config = load_config()
    if not config:
        print("No configuration found. Run --setup first.")
        return

    if not config.get('username') or not config.get('password'):
        print("Missing credentials. Run --setup first.")
        return

    if not config.get('persons'):
        print("No starting persons configured. Run --setup first.")
        return

    check_dependencies()

    # Adjust generations for quick sync
    ancestors = 4 if quick else config.get('ancestor_generations', 8)
    descendants = 2 if quick else config.get('descendant_generations', 4)

    print(f"\n{'='*50}")
    print(f"FamilySearch Sync - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")
    print(f"Mode: {'Quick' if quick else 'Full'}")
    print(f"Persons to sync: {len(config['persons'])}")

    # Sync each person
    output_files = []
    for person in config['persons']:
        result = run_getmyancestors(config, person, ancestors, descendants)
        if result:
            output_files.append(result)

    if not output_files:
        print("\nNo files were generated. Check your credentials and person IDs.")
        return

    # Merge all files
    merge_gedcom_files(output_files, MERGED_OUTPUT)

    # Save sync timestamp
    config['last_sync'] = datetime.now().isoformat()
    save_config(config)

    print(f"\n{'='*50}")
    print("Sync complete!")
    print(f"Merged GEDCOM: {MERGED_OUTPUT}")
    print(f"{'='*50}")
    print("\nYou can now load this file in your genealogy app.")

def show_schedule():
    """Show cron command for scheduling"""
    script_path = Path(__file__).resolve()

    print("\n=== Scheduling Periodic Sync ===\n")
    print("Add one of these to your crontab (crontab -e):\n")
    print("# Weekly full sync (Sundays at 2 AM)")
    print(f"0 2 * * 0 cd {script_path.parent} && {sys.executable} {script_path} --sync >> sync.log 2>&1")
    print()
    print("# Daily quick sync (every day at 3 AM)")
    print(f"0 3 * * * cd {script_path.parent} && {sys.executable} {script_path} --quick >> sync.log 2>&1")
    print()
    print("# Monthly full sync (1st of each month at 2 AM)")
    print(f"0 2 1 * * cd {script_path.parent} && {sys.executable} {script_path} --sync >> sync.log 2>&1")
    print()

    # macOS launchd alternative
    print("\n--- macOS launchd alternative ---")
    print("Create ~/Library/LaunchAgents/com.familysearch.sync.plist")

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.familysearch.sync</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{script_path}</string>
        <string>--sync</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{script_path.parent}</string>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>0</integer>
        <key>Hour</key>
        <integer>2</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>{script_path.parent}/sync.log</string>
    <key>StandardErrorPath</key>
    <string>{script_path.parent}/sync_error.log</string>
</dict>
</plist>"""

    print(plist_content)
    print("\nThen run: launchctl load ~/Library/LaunchAgents/com.familysearch.sync.plist")

def status():
    """Show current configuration status"""
    config = load_config()

    print("\n=== FamilySearch Sync Status ===\n")

    if not config:
        print("Not configured. Run --setup first.")
        return

    print(f"Username: {config.get('username', 'Not set')}")
    print(f"Password: {'*****' if config.get('password') else 'Not set'}")
    print(f"Ancestor generations: {config.get('ancestor_generations', 8)}")
    print(f"Descendant generations: {config.get('descendant_generations', 4)}")
    print(f"Last sync: {config.get('last_sync', 'Never')}")

    print(f"\nStarting persons ({len(config.get('persons', []))}):")
    for p in config.get('persons', []):
        print(f"  - {p['name']}: {p['id']}")

    print(f"\nOutput directory: {OUTPUT_DIR}")
    print(f"Merged output: {MERGED_OUTPUT}")

    if MERGED_OUTPUT.exists():
        size = MERGED_OUTPUT.stat().st_size / 1024
        print(f"Merged file size: {size:.1f} KB")

def main():
    parser = argparse.ArgumentParser(description="FamilySearch Tree Sync")
    parser.add_argument('--setup', action='store_true', help='Interactive setup')
    parser.add_argument('--sync', action='store_true', help='Run full sync')
    parser.add_argument('--quick', action='store_true', help='Run quick sync (fewer generations)')
    parser.add_argument('--schedule', action='store_true', help='Show scheduling commands')
    parser.add_argument('--status', action='store_true', help='Show current status')

    args = parser.parse_args()

    if args.setup:
        setup()
    elif args.sync:
        sync(quick=False)
    elif args.quick:
        sync(quick=True)
    elif args.schedule:
        show_schedule()
    elif args.status:
        status()
    else:
        parser.print_help()
        print("\n--- Quick Start ---")
        print("1. python sync_familysearch.py --setup")
        print("2. python sync_familysearch.py --sync")
        print("3. Load merged_family_tree.ged in the genealogy app")

if __name__ == "__main__":
    main()
