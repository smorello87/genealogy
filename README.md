# Family Archives Genealogy Explorer

A beautiful, interactive web application for exploring GEDCOM genealogy files. View your family tree, search individuals, analyze statistics, and visualize geographic data—all in your browser.

## Features

- **Interactive Family Tree** - Navigate ancestors and descendants with an elegant pedigree visualization
- **Smart Search** - Find individuals by name, date, or location with highlighted results
- **Relationship Filtering** - Filter by relationship type (ancestors, descendants, cousins, etc.) relative to a reference person
- **Color-Coded Relationships** - Visual relationship indicators throughout the app
- **Statistics Dashboard** - Birth/death timelines, gender distribution, surname analysis, and lifespan charts
- **Geographic Map** - Plot birthplaces on an interactive world map
- **Mobile Responsive** - Fully optimized for phones and tablets

## Getting Started

### Quick Start (Local)

1. Clone this repository
2. Open `index.html` in your browser
3. Upload a GEDCOM file (.ged) to begin exploring

No server or build process required—it's a pure client-side application.

### Hosting

To host publicly, simply serve the files from any web server:

```bash
# Python
python -m http.server 8000

# Node.js
npx serve .

# Or upload to any static host (GitHub Pages, Netlify, Vercel, etc.)
```

## GEDCOM Compatibility

Supports standard GEDCOM 5.5.1 format exported from:
- MacFamilyTree
- RootsMagic
- Gramps
- Ancestry
- FamilySearch
- And most other genealogy software

## File Structure

```
genealogy/
├── index.html              # Main application (HTML + CSS)
├── app.js                  # Application logic
├── .htaccess               # Apache configuration (optional)
├── familysearch_scraper.py # FamilySearch export tool (optional)
├── sync_gedcom.py          # GEDCOM sync utility (optional)
└── README.md
```

## Privacy

This application processes GEDCOM files entirely in your browser. No data is sent to external servers. Your family data stays on your device.

## Optional Tools

### FamilySearch Scraper (`familysearch_scraper.py`)

Export your FamilySearch tree to GEDCOM format:

```bash
pip install playwright
playwright install chromium

python familysearch_scraper.py --persons YOUR-PERSON-ID --ancestors 8 --descendants 4
```

### GEDCOM Sync (`sync_gedcom.py`)

Auto-upload GEDCOM files to your server when they change:

```bash
python sync_gedcom.py --setup  # Configure
python sync_gedcom.py          # Start watching
```

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers (iOS Safari, Chrome for Android)

## License

MIT License - Feel free to use, modify, and distribute.

## Credits

Developed by **Stefano Morello**

---

*Upload a GEDCOM file to start exploring your family history.*
