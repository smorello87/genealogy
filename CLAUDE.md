# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Morello Family Archives - a single-page web application for visualizing GEDCOM genealogy data. Vanilla HTML/CSS/JS with no build step.

## Quick Start

```bash
python3 -m http.server 8000
# Visit http://localhost:8000
```

## Architecture

### Files

- `index.html` - HTML structure + all CSS (inline `<style>`)
- `app.js` - All JavaScript classes and logic
- `stefano_full.ged` - Default GEDCOM file (auto-loaded on startup)
- `sync_gedcom.py` - Optional file watcher for auto-uploading GEDCOM changes

### Main Classes (app.js)

| Class | Line | Purpose |
|-------|------|---------|
| `FamilySearchClient` | ~10 | OAuth2 client for FamilySearch API |
| `GenealogyDataIndexer` | ~605 | Indexes data for AI queries |
| `AIQueryEngine` | ~1170 | Natural language query processing |
| `GedcomParser` | ~1447 | Parses GEDCOM format into structured data |
| `GenealogyApp` | ~1750 | Main controller - UI, rendering, state |

### Data Flow

1. GEDCOM loaded → `GedcomParser.parse()` → `this.data` (Maps of individuals, families, sources)
2. `GenealogyDataIndexer` builds search indexes
3. UI renders via D3.js (tree, charts) and Leaflet (maps)

### Key Data Structures

```javascript
this.data = {
  individuals: Map<id, Person>,  // '@I123@' → person object
  families: Map<id, Family>,
  sources: Map<id, Source>
}

// Person object
{
  id: '@I123@',
  name: { given, surname, full },
  sex: 'M' | 'F',
  birth: { date: { year, month, day }, place },
  death: { date, place },
  familySpouse: ['@F1@'],  // Families as spouse
  familyChild: ['@F2@']   // Families as child
}
```

### Relationship System

Reference-based calculation from selected person:
- `this.referencePerson` - currently selected person ID
- `this.relationshipCache` - Map of personId → relationship data
- Colors defined in `this.relationshipColors` (ancestor=blue, descendant=green, etc.)

## UI Tabs

1. **Search** - Text search with relationship filtering
2. **Tree** - D3.js family tree (ancestors + descendants)
3. **Statistics** - Birth timeline, surname charts
4. **Map** - Leaflet map with birth locations
5. **AI** - Natural language queries

## Dependencies (CDN)

- D3.js v7
- Leaflet 1.9.4
- Google Fonts (Fraunces, DM Sans, Cormorant Garamond, Source Serif 4)

## Deployment

```bash
chmod 644 index.html app.js *.ged
```

Deploy to any static file server. `.htaccess` included for Apache.

## Key Methods

- `loadDefaultGedcom()` - Change default GEDCOM file (~line 1737)
- `renderBothTree()` - Tree visualization with D3
- `calculateRelationships(personId)` - BFS relationship calculation
- `showEmptyState()` - Welcome page when no data loaded
- `performSearch()` - Search with filters applied
