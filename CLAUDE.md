# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Family Archives Genealogy Explorer - a single-page web application for visualizing GEDCOM genealogy data. Pure vanilla HTML/CSS/JS with no build step.

## Quick Start

```bash
python3 -m http.server 8000
# Visit http://localhost:8000, upload a GEDCOM file
```

## Architecture

### Files

- `index.html` - HTML structure + all CSS (inline `<style>`)
- `app.js` - All JavaScript classes and logic (~5000 lines)
- `familysearch_scraper.py` - Playwright-based FamilySearch tree exporter
- `sync_gedcom.py` - File watcher for auto-uploading GEDCOM changes

### Main Classes (app.js)

| Class | Purpose |
|-------|---------|
| `FamilySearchClient` | OAuth2 client for FamilySearch API integration |
| `GenealogyDataIndexer` | Indexes parsed data for AI natural language queries |
| `AIQueryEngine` | Processes natural language questions about the family tree |
| `GedcomParser` | Parses GEDCOM 5.5.1/7.0 format into structured Maps |
| `GenealogyApp` | Main controller - UI state, rendering, event handling |

### Data Flow

1. GEDCOM uploaded → `GedcomParser.parse()` → `this.data` (Maps of individuals, families, sources)
2. `GenealogyDataIndexer` builds search indexes for AI queries
3. UI renders via D3.js (tree, charts) and Leaflet (map with birth locations)

### Key Data Structures

```javascript
this.data = {
  individuals: Map<id, Person>,  // '@I123@' → person object
  families: Map<id, Family>,
  sources: Map<id, Source>
}

// Person object
{
  id, name: { given, surname, full },
  sex: 'M' | 'F',
  birth: { date: { year, month, day }, place, coords: { lat, lng } },
  death: { date, place },
  familySpouse: ['@F1@'],  // Families where person is spouse
  familyChild: ['@F2@']   // Families where person is child
}
```

### Relationship System

All filtering is relative to a reference person:
- `this.referencePerson` - selected person ID for relationship calculations
- `this.relationshipCache` - Map of personId → { type, generation, degree }
- `calculateRelationships(personId)` - BFS traversal to classify all individuals
- Colors: ancestor=blue, descendant=green, sibling=teal, cousin=purple, spouse=pink, in-law=orange

## UI Tabs

1. **Search** - Text search with relationship type filtering
2. **Tree** - D3.js pedigree visualization (ancestors + descendants)
3. **Statistics** - Birth timeline, surname distribution, lifespan charts
4. **Map** - Leaflet map with clustered birth location markers
5. **AI Query** - Natural language questions (requires API key config)

## Dependencies (CDN-loaded)

- D3.js v7 (tree visualization, charts)
- Leaflet 1.9.4 (geographic map)
- Google Fonts (Fraunces, DM Sans, Source Serif 4)

## Key Methods

- `showEmptyState()` - Welcome page when no GEDCOM loaded
- `performSearch()` - Search with relationship and attribute filters
- `renderBothTree(personId)` - D3 tree with both ancestors and descendants
- `initMap()` - Leaflet map initialization (call `invalidateSize()` after tab switch)
- `calculateRelationships(personId)` - BFS relationship classification

## Styling Notes

- All CSS is inline in `index.html` `<style>` block
- CSS variables for theming in `:root` and `[data-theme="dark"]`
- Mobile breakpoints: 768px (tablet), 480px (phone), 360px (small phone)
- Do NOT add `display: flex` to body - breaks child element layouts
