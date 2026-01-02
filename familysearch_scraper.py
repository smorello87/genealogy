#!/usr/bin/env python3
"""
FamilySearch Tree Scraper using Playwright
Uses browser automation to extract family tree data after manual login.

Usage:
  python familysearch_scraper.py --person L5Y7-ZSY --ancestors 8 --descendants 4
  python familysearch_scraper.py --persons L5Y7-ZSY,GZX1-RZM --output merged.ged
"""

import asyncio
import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright

class FamilySearchScraper:
    def __init__(self):
        self.browser = None
        self.context = None
        self.page = None
        self.persons = {}  # id -> person data
        self.families = {}  # id -> family data
        self.session_file = Path(__file__).parent / ".familysearch_session.json"

    async def start(self, headless=False):
        """Start browser and load session if available"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=headless)

        # Try to load existing session
        storage_state = None
        if self.session_file.exists():
            try:
                storage_state = str(self.session_file)
                print("Loading saved session...")
            except:
                pass

        self.context = await self.browser.new_context(
            storage_state=storage_state,
            viewport={'width': 1280, 'height': 800}
        )
        self.page = await self.context.new_page()

    async def login(self):
        """Navigate to FamilySearch and let user log in, capture auth token"""
        self.auth_token = None

        # Intercept requests to capture the authorization token
        async def capture_auth(route, request):
            auth = request.headers.get('authorization', '')
            if auth and auth.startswith('Bearer '):
                self.auth_token = auth
            await route.continue_()

        await self.page.route("**/api.familysearch.org/**", capture_auth)

        print("\nNavigating to FamilySearch...")
        await self.page.goto("https://www.familysearch.org/tree/person/details/")

        # Check if we need to log in
        await asyncio.sleep(2)
        current_url = self.page.url

        if "ident.familysearch.org" in current_url or "/auth/" in current_url:
            print("\n" + "="*50)
            print("Please log in to FamilySearch in the browser window.")
            print("The script will continue automatically after login.")
            print("="*50 + "\n")

            # Wait for redirect to tree page (login complete)
            try:
                await self.page.wait_for_url("**/tree/**", timeout=300000)  # 5 minute timeout
                print("Login successful!")

                # Save session for future use
                await self.context.storage_state(path=str(self.session_file))
                print("Session saved for future use.")
            except:
                print("Login timeout or cancelled.")
                return False

        # Navigate to a tree page to trigger API calls and capture the token
        print("Capturing authentication token...")
        await self.page.goto("https://www.familysearch.org/tree/pedigree/landscape/")
        await asyncio.sleep(3)  # Wait for API calls to happen

        if self.auth_token:
            print(f"Auth token captured!")
        else:
            # Try to get token from localStorage
            token = await self.page.evaluate("""
                () => {
                    // Try various storage locations
                    const ls = localStorage.getItem('fssessionId') ||
                               localStorage.getItem('fs_token') ||
                               sessionStorage.getItem('fssessionId');
                    return ls;
                }
            """)
            if token:
                self.auth_token = f"Bearer {token}"
                print("Auth token retrieved from storage!")

        if not self.auth_token:
            print("Warning: Could not capture auth token. API calls may fail.")

        print("Logged in to FamilySearch!")
        return True

    async def api_request(self, url):
        """Make an API request using the captured auth token"""
        try:
            headers = {
                'Accept': 'application/json',
            }

            # Add auth token if we have it
            if self.auth_token:
                headers['Authorization'] = self.auth_token

            # Use Playwright's request API
            response = await self.context.request.get(url, headers=headers)

            if response.ok:
                return await response.json()
            else:
                print(f"  API returned {response.status}")
                return None
        except Exception as e:
            print(f"  API request error: {e}")
            return None

    async def get_person_data(self, person_id):
        """Get data for a single person via API"""
        if person_id in self.persons:
            return self.persons[person_id]

        response = await self.api_request(
            f'https://api.familysearch.org/platform/tree/persons/{person_id}'
        )

        if response and 'persons' in response and len(response['persons']) > 0:
            person = response['persons'][0]
            self.persons[person_id] = person
            return person

        return None

    async def get_ancestry(self, person_id, generations=8):
        """Get ancestors using the ancestry API endpoint"""
        print(f"\nFetching {generations} generations of ancestors for {person_id}...")

        response = await self.api_request(
            f'https://api.familysearch.org/platform/tree/ancestry?person={person_id}&generations={generations}&personDetails=true'
        )

        if response and 'persons' in response:
            persons = response['persons']
            print(f"  Found {len(persons)} ancestors")
            for person in persons:
                pid = person.get('id')
                if pid:
                    self.persons[pid] = person
            return persons

        print("  Error fetching ancestry")
        return []

    async def get_descendancy(self, person_id, generations=4, depth=0, max_depth=8):
        """Get descendants using the descendancy API endpoint. Chains calls for >4 generations."""
        # FamilySearch API limits to 4 generations per call, so we chain if needed
        api_gens = min(generations, 4)

        if depth == 0:
            print(f"  Fetching descendants for {person_id} ({max_depth} generations total)...")

        response = await self.api_request(
            f'https://api.familysearch.org/platform/tree/descendancy?person={person_id}&generations={api_gens}&personDetails=true'
        )

        if response and 'persons' in response:
            persons = response['persons']
            leaf_persons = []  # Persons at the deepest level (need to continue from)

            for person in persons:
                pid = person.get('id')
                if pid and pid not in self.persons:
                    self.persons[pid] = person

                    # Track persons at generation 4 (the leaves) for chaining
                    desc_num = person.get('display', {}).get('descendancyNumber', '')
                    if desc_num:
                        # Count dots to determine generation depth
                        gen_depth = desc_num.count('.') + 1 if '.' in desc_num else 1
                        if gen_depth >= api_gens:
                            leaf_persons.append(pid)

            # If we need more generations, recursively fetch from leaf persons
            remaining_gens = generations - api_gens
            current_depth = depth + api_gens

            if remaining_gens > 0 and current_depth < max_depth and leaf_persons:
                await asyncio.sleep(0.5)  # Small delay between chained calls
                for leaf_id in leaf_persons[:20]:  # Limit to prevent explosion
                    await self.get_descendancy(leaf_id, remaining_gens, current_depth, max_depth)
                    await asyncio.sleep(0.3)

            return persons

        return []

    async def get_all_relatives(self, start_persons, ancestor_gens=8, descendant_gens=8, full_mode=False):
        """Get all relatives by climbing up ancestors then down selected branches"""
        all_ancestors = []  # List of (id, generation) tuples

        # Phase 1: Get all ancestors for each starting person (FAST - 1 API call each)
        for person_id in start_persons:
            print(f"\n{'='*50}")
            print(f"Phase 1: Getting ancestors for {person_id}")
            print(f"{'='*50}")

            ancestors = await self.get_ancestry(person_id, ancestor_gens)
            for a in ancestors:
                aid = a.get('id')
                # Get generation from ascendancyNumber if available
                gen = a.get('display', {}).get('ascendancyNumber', '1')
                if aid:
                    all_ancestors.append((aid, gen))

            await asyncio.sleep(1)  # Rate limiting

        # Deduplicate ancestors
        seen = set()
        unique_ancestors = []
        for aid, gen in all_ancestors:
            if aid not in seen:
                seen.add(aid)
                unique_ancestors.append((aid, gen))

        print(f"\nFound {len(unique_ancestors)} unique ancestors across all starting persons")

        # Phase 2: Smart descendancy - only descend from oldest ancestors
        # This dramatically reduces API calls while still getting all cousins

        if full_mode:
            # Full mode: descend from ALL ancestors (slow, comprehensive)
            ancestors_to_descend = [aid for aid, _ in unique_ancestors]
            print(f"\nFULL MODE: Will descend from all {len(ancestors_to_descend)} ancestors")
            print("This will take a while but captures everyone...")
        else:
            # Smart mode: only descend from ancestors at generation 4+ (great-great-grandparents and up)
            # This captures all 2nd cousins and beyond with far fewer API calls
            ancestors_to_descend = []
            for aid, gen in unique_ancestors:
                # ascendancyNumber format: "1" for self, "2" for father, "3" for mother, etc.
                # Generation 4 starts at number 8 (2^3)
                try:
                    num = int(gen) if gen else 1
                    if num >= 8:  # Great-grandparents and up
                        ancestors_to_descend.append(aid)
                except:
                    pass

            # If we didn't find enough, fall back to top 50 oldest
            if len(ancestors_to_descend) < 20:
                ancestors_to_descend = [aid for aid, _ in unique_ancestors[-50:]]

            print(f"\nSMART MODE: Descending from {len(ancestors_to_descend)} oldest ancestors")
            print("(Use --full for complete tree, but it takes longer)")

        print(f"\n{'='*50}")
        print(f"Phase 2: Getting descendants ({len(ancestors_to_descend)} API calls)")
        print(f"Estimated time: {len(ancestors_to_descend) * 2} seconds")
        print(f"{'='*50}")

        processed = 0
        for ancestor_id in ancestors_to_descend:
            await self.get_descendancy(ancestor_id, descendant_gens, depth=0, max_depth=descendant_gens)
            processed += 1
            print(f"  Progress: {processed}/{len(ancestors_to_descend)} ({len(self.persons)} persons found)")
            await asyncio.sleep(1.5)  # Respectful rate limiting - 1.5 sec between calls

        print(f"\n{'='*50}")
        print(f"Total persons collected: {len(self.persons)}")
        print(f"{'='*50}")

    def to_gedcom(self):
        """Convert collected data to GEDCOM format"""
        lines = []

        # Header
        lines.append("0 HEAD")
        lines.append("1 SOUR FamilySearchScraper")
        lines.append("2 VERS 1.0")
        lines.append("1 GEDC")
        lines.append("2 VERS 5.5.1")
        lines.append("2 FORM LINEAGE-LINKED")
        lines.append("1 CHAR UTF-8")
        lines.append(f"1 DATE {datetime.now().strftime('%d %b %Y').upper()}")

        # Individuals
        for person_id, person in self.persons.items():
            lines.append(f"0 @{person_id}@ INDI")

            # Name
            display = person.get('display', {})
            name = display.get('name', 'Unknown')
            lines.append(f"1 NAME {name}")

            # Extract given/surname if available
            if 'names' in person and person['names']:
                name_obj = person['names'][0]
                if 'nameForms' in name_obj and name_obj['nameForms']:
                    name_form = name_obj['nameForms'][0]
                    parts = name_form.get('parts', [])
                    for part in parts:
                        if part.get('type') == 'http://gedcomx.org/Given':
                            lines.append(f"2 GIVN {part.get('value', '')}")
                        elif part.get('type') == 'http://gedcomx.org/Surname':
                            lines.append(f"2 SURN {part.get('value', '')}")

            # Sex
            gender = display.get('gender', person.get('gender', {}).get('type', ''))
            if 'Male' in gender:
                lines.append("1 SEX M")
            elif 'Female' in gender:
                lines.append("1 SEX F")

            # Birth
            birth_date = display.get('birthDate', '')
            birth_place = display.get('birthPlace', '')
            if birth_date or birth_place:
                lines.append("1 BIRT")
                if birth_date:
                    lines.append(f"2 DATE {birth_date}")
                if birth_place:
                    lines.append(f"2 PLAC {birth_place}")

            # Death
            death_date = display.get('deathDate', '')
            death_place = display.get('deathPlace', '')
            if death_date or death_place:
                lines.append("1 DEAT")
                if death_date:
                    lines.append(f"2 DATE {death_date}")
                if death_place:
                    lines.append(f"2 PLAC {death_place}")

            # FamilySearch ID as reference
            lines.append(f"1 _FSFTID {person_id}")

        # Trailer
        lines.append("0 TRLR")

        return '\n'.join(lines)

    async def close(self):
        """Clean up"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()


async def main():
    parser = argparse.ArgumentParser(description="FamilySearch Tree Scraper")
    parser.add_argument('--persons', '-p', required=True, help='Comma-separated person IDs (e.g., L5Y7-ZSY,GZX1-RZM)')
    parser.add_argument('--ancestors', '-a', type=int, default=8, help='Generations of ancestors (default: 8)')
    parser.add_argument('--descendants', '-d', type=int, default=8, help='Generations of descendants (default: 8)')
    parser.add_argument('--output', '-o', default='familysearch_tree.ged', help='Output GEDCOM file')
    parser.add_argument('--headless', action='store_true', help='Run browser in headless mode (requires saved session)')
    parser.add_argument('--full', action='store_true', help='Full mode: descend from ALL ancestors (slower but complete)')

    args = parser.parse_args()

    person_ids = [p.strip() for p in args.persons.split(',')]

    print(f"\n{'='*60}")
    print("FamilySearch Tree Scraper")
    print(f"{'='*60}")
    print(f"Starting persons: {', '.join(person_ids)}")
    print(f"Ancestor generations: {args.ancestors}")
    print(f"Descendant generations: {args.descendants}")
    print(f"Mode: {'FULL (all ancestors)' if args.full else 'SMART (oldest ancestors only)'}")
    print(f"Output file: {args.output}")
    print(f"{'='*60}\n")

    scraper = FamilySearchScraper()

    try:
        await scraper.start(headless=args.headless)

        if not await scraper.login():
            print("Login failed. Exiting.")
            return

        await scraper.get_all_relatives(person_ids, args.ancestors, args.descendants, args.full)

        # Export to GEDCOM
        print(f"\nExporting {len(scraper.persons)} persons to GEDCOM...")
        gedcom = scraper.to_gedcom()

        output_path = Path(args.output)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(gedcom)

        print(f"Saved to {output_path}")
        print(f"\n{'='*60}")
        print("DONE! Load this file in your genealogy app.")
        print(f"{'='*60}\n")

    finally:
        await scraper.close()


if __name__ == "__main__":
    asyncio.run(main())
