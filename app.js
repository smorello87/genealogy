/**
 * Family Archives Genealogy Explorer
 * GEDCOM 7.0 Parser and Interactive Visualization
 */

// ============================================================================
// FAMILYSEARCH API CLIENT - OAuth2 + Tree Crawler + Photo Sync
// ============================================================================

class FamilySearchClient {
  constructor() {
    this.baseUrl = 'https://api.familysearch.org';
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;
    this.clientId = null; // User provides their own app key
    this.redirectUri = window.location.origin + window.location.pathname;

    // Rate limiting
    this.requestQueue = [];
    this.isProcessingQueue = false;
    this.minRequestInterval = 200; // ms between requests
    this.retryAfter = 0;

    // Crawl state
    this.visitedPersons = new Set();
    this.persons = new Map();
    this.families = new Map();
    this.memories = new Map();
    this.crawlProgress = { total: 0, processed: 0, photos: 0 };

    // Load saved credentials
    this.loadCredentials();
  }

  loadCredentials() {
    try {
      const saved = localStorage.getItem('familysearch_credentials');
      if (saved) {
        const creds = JSON.parse(saved);
        this.accessToken = creds.accessToken;
        this.refreshToken = creds.refreshToken;
        this.tokenExpiry = creds.tokenExpiry ? new Date(creds.tokenExpiry) : null;
        this.clientId = creds.clientId;
      }
    } catch (e) {
      console.warn('Failed to load FamilySearch credentials:', e);
    }
  }

  saveCredentials() {
    try {
      localStorage.setItem('familysearch_credentials', JSON.stringify({
        accessToken: this.accessToken,
        refreshToken: this.refreshToken,
        tokenExpiry: this.tokenExpiry?.toISOString(),
        clientId: this.clientId
      }));
    } catch (e) {
      console.warn('Failed to save FamilySearch credentials:', e);
    }
  }

  setClientId(clientId) {
    this.clientId = clientId;
    this.saveCredentials();
  }

  // OAuth2 Authorization Code flow with PKCE
  generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, array))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  async generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode.apply(null, new Uint8Array(digest)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  async initiateAuth() {
    if (!this.clientId) {
      throw new Error('Client ID (App Key) is required. Get one from developers.familysearch.org');
    }

    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = await this.generateCodeChallenge(codeVerifier);

    // Store verifier for token exchange
    sessionStorage.setItem('fs_code_verifier', codeVerifier);

    const authUrl = new URL('https://ident.familysearch.org/cis-web/oauth2/v3/authorization');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', this.clientId);
    authUrl.searchParams.set('redirect_uri', this.redirectUri);
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    // Redirect to FamilySearch login
    window.location.href = authUrl.toString();
  }

  async handleAuthCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');

    if (error) {
      throw new Error(`Auth error: ${error}`);
    }

    if (!code) {
      return false; // No auth callback
    }

    const codeVerifier = sessionStorage.getItem('fs_code_verifier');
    if (!codeVerifier) {
      throw new Error('Code verifier not found');
    }

    // Exchange code for token
    const tokenUrl = 'https://ident.familysearch.org/cis-web/oauth2/v3/token';
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: this.clientId,
        redirect_uri: this.redirectUri,
        code_verifier: codeVerifier
      })
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Token exchange failed: ${err}`);
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    this.tokenExpiry = new Date(Date.now() + (data.expires_in * 1000));

    sessionStorage.removeItem('fs_code_verifier');
    this.saveCredentials();

    // Clean URL
    window.history.replaceState({}, document.title, this.redirectUri);

    return true;
  }

  async refreshAccessToken() {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch('https://ident.familysearch.org/cis-web/oauth2/v3/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: this.refreshToken,
        client_id: this.clientId
      })
    });

    if (!response.ok) {
      this.accessToken = null;
      this.refreshToken = null;
      this.saveCredentials();
      throw new Error('Token refresh failed - please re-authenticate');
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token || this.refreshToken;
    this.tokenExpiry = new Date(Date.now() + (data.expires_in * 1000));
    this.saveCredentials();
  }

  isAuthenticated() {
    return this.accessToken && (!this.tokenExpiry || this.tokenExpiry > new Date());
  }

  async ensureAuthenticated() {
    if (!this.accessToken) {
      throw new Error('Not authenticated');
    }

    if (this.tokenExpiry && this.tokenExpiry <= new Date()) {
      await this.refreshAccessToken();
    }
  }

  // Rate-limited API request
  async apiRequest(endpoint, options = {}) {
    await this.ensureAuthenticated();

    // Wait if we're being throttled
    if (this.retryAfter > Date.now()) {
      await new Promise(r => setTimeout(r, this.retryAfter - Date.now()));
    }

    const url = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.accessToken}`,
        'Accept': 'application/json',
        ...options.headers
      }
    });

    // Handle throttling
    if (response.status === 429) {
      const retryAfterSec = parseInt(response.headers.get('Retry-After') || '5');
      this.retryAfter = Date.now() + (retryAfterSec * 1000);
      console.log(`Throttled, waiting ${retryAfterSec}s...`);
      await new Promise(r => setTimeout(r, retryAfterSec * 1000));
      return this.apiRequest(endpoint, options); // Retry
    }

    if (!response.ok) {
      throw new Error(`API error ${response.status}: ${await response.text()}`);
    }

    // Rate limit ourselves
    await new Promise(r => setTimeout(r, this.minRequestInterval));

    return response.json();
  }

  // Get current user's person ID
  async getCurrentUser() {
    const data = await this.apiRequest('/platform/users/current');
    return data.users?.[0];
  }

  // Get ancestry (up to 8 generations UP)
  async getAncestry(personId, generations = 8) {
    const params = new URLSearchParams({
      person: personId,
      generations: Math.min(generations, 8),
      personDetails: 'true',
      marriageDetails: 'true'
    });
    return this.apiRequest(`/platform/tree/ancestry?${params}`);
  }

  // Get descendancy (up to 4 generations DOWN)
  async getDescendancy(personId, generations = 4) {
    const params = new URLSearchParams({
      person: personId,
      generations: Math.min(generations, 4),
      personDetails: 'true',
      marriageDetails: 'true'
    });
    return this.apiRequest(`/platform/tree/descendancy?${params}`);
  }

  // Get full person details
  async getPerson(personId) {
    return this.apiRequest(`/platform/tree/persons/${personId}`);
  }

  // Get memories (photos) for a person
  async getPersonMemories(personId) {
    try {
      return await this.apiRequest(`/platform/tree/persons/${personId}/memories`);
    } catch (e) {
      // Some persons don't have memories access
      return { sourceDescriptions: [] };
    }
  }

  // Download a memory/photo
  async downloadMemory(memoryUrl) {
    await this.ensureAuthenticated();
    const response = await fetch(memoryUrl, {
      headers: { 'Authorization': `Bearer ${this.accessToken}` }
    });
    if (!response.ok) return null;
    return response.blob();
  }

  // ========================================================================
  // TREE CRAWLER - Fetches full tree with all branches
  // ========================================================================

  async crawlFullTree(startPersonIds, options = {}) {
    const {
      ancestorGenerations = 8,
      descendantGenerations = 8,
      includePhotos = true,
      onProgress = () => {}
    } = options;

    this.visitedPersons.clear();
    this.persons.clear();
    this.families.clear();
    this.memories.clear();
    this.crawlProgress = { total: 0, processed: 0, photos: 0, status: 'Starting...' };

    const toProcess = [...startPersonIds];
    const ancestorsToDescend = new Set();

    // Phase 1: Get all ancestors for each starting person
    this.crawlProgress.status = 'Fetching ancestors...';
    onProgress(this.crawlProgress);

    for (const personId of startPersonIds) {
      try {
        const ancestry = await this.getAncestry(personId, ancestorGenerations);
        this.processAncestryResponse(ancestry, ancestorsToDescend);
        this.crawlProgress.processed++;
        onProgress(this.crawlProgress);
      } catch (e) {
        console.warn(`Failed to get ancestry for ${personId}:`, e);
      }
    }

    // Phase 2: Get descendants for all ancestors (to capture all branches)
    this.crawlProgress.status = 'Fetching all family branches...';
    this.crawlProgress.total = ancestorsToDescend.size;
    this.crawlProgress.processed = 0;
    onProgress(this.crawlProgress);

    for (const ancestorId of ancestorsToDescend) {
      await this.crawlDescendantsRecursive(ancestorId, descendantGenerations, onProgress);
      this.crawlProgress.processed++;
      onProgress(this.crawlProgress);
    }

    // Phase 3: Fetch photos
    if (includePhotos) {
      this.crawlProgress.status = 'Downloading photos...';
      this.crawlProgress.total = this.persons.size;
      this.crawlProgress.processed = 0;
      onProgress(this.crawlProgress);

      for (const [personId, person] of this.persons) {
        try {
          const memories = await this.getPersonMemories(personId);
          if (memories.sourceDescriptions?.length > 0) {
            this.memories.set(personId, memories.sourceDescriptions);
            this.crawlProgress.photos += memories.sourceDescriptions.length;
          }
        } catch (e) {
          // Continue on memory errors
        }
        this.crawlProgress.processed++;
        if (this.crawlProgress.processed % 10 === 0) {
          onProgress(this.crawlProgress);
        }
      }
    }

    this.crawlProgress.status = 'Complete!';
    onProgress(this.crawlProgress);

    return {
      persons: this.persons,
      families: this.families,
      memories: this.memories,
      stats: {
        totalPersons: this.persons.size,
        totalFamilies: this.families.size,
        totalPhotos: this.crawlProgress.photos
      }
    };
  }

  processAncestryResponse(data, ancestorsToDescend) {
    if (!data.persons) return;

    for (const person of data.persons) {
      if (!this.visitedPersons.has(person.id)) {
        this.visitedPersons.add(person.id);
        this.persons.set(person.id, this.normalizePerson(person));
        ancestorsToDescend.add(person.id);
      }
    }

    // Process relationships
    if (data.childAndParentsRelationships) {
      for (const rel of data.childAndParentsRelationships) {
        this.processRelationship(rel);
      }
    }
  }

  async crawlDescendantsRecursive(personId, maxDepth, onProgress, currentDepth = 0) {
    if (currentDepth >= maxDepth) return;

    try {
      const descendancy = await this.getDescendancy(personId, 4);

      if (descendancy.persons) {
        for (const person of descendancy.persons) {
          if (!this.visitedPersons.has(person.id)) {
            this.visitedPersons.add(person.id);
            this.persons.set(person.id, this.normalizePerson(person));

            // Recursively get their descendants if we need more depth
            if (currentDepth + 4 < maxDepth) {
              await this.crawlDescendantsRecursive(person.id, maxDepth, onProgress, currentDepth + 4);
            }
          }
        }
      }

      if (descendancy.childAndParentsRelationships) {
        for (const rel of descendancy.childAndParentsRelationships) {
          this.processRelationship(rel);
        }
      }
    } catch (e) {
      console.warn(`Failed to get descendants for ${personId}:`, e);
    }
  }

  processRelationship(rel) {
    const familyId = rel.id || `FAM_${rel.parent1?.resourceId}_${rel.parent2?.resourceId}`;

    if (!this.families.has(familyId)) {
      this.families.set(familyId, {
        id: familyId,
        husband: rel.parent1?.resourceId || rel.father?.resourceId,
        wife: rel.parent2?.resourceId || rel.mother?.resourceId,
        children: []
      });
    }

    const family = this.families.get(familyId);
    const childId = rel.child?.resourceId;
    if (childId && !family.children.includes(childId)) {
      family.children.push(childId);
    }
  }

  normalizePerson(fsPerson) {
    const display = fsPerson.display || {};
    const facts = fsPerson.facts || [];

    const getBirthFact = () => facts.find(f => f.type === 'http://gedcomx.org/Birth');
    const getDeathFact = () => facts.find(f => f.type === 'http://gedcomx.org/Death');
    const getOccupation = () => facts.find(f => f.type === 'http://gedcomx.org/Occupation');

    const birth = getBirthFact();
    const death = getDeathFact();
    const occupation = getOccupation();

    // Parse name
    const nameParts = display.name?.split(' ') || [];
    const surname = display.familyName || nameParts.pop() || '';
    const given = display.givenName || nameParts.join(' ') || '';

    return {
      id: fsPerson.id,
      name: {
        given: given,
        surname: surname,
        full: display.name || `${given} ${surname}`.trim()
      },
      gender: fsPerson.gender?.type?.includes('Male') ? 'M' :
              fsPerson.gender?.type?.includes('Female') ? 'F' : 'U',
      birth: {
        date: birth?.date?.original || display.birthDate,
        place: birth?.place?.original || display.birthPlace,
        latitude: birth?.place?.latitude,
        longitude: birth?.place?.longitude
      },
      death: {
        date: death?.date?.original || display.deathDate,
        place: death?.place?.original || display.deathPlace
      },
      occupation: occupation?.value,
      familySearchId: fsPerson.id,
      lifespan: display.lifespan
    };
  }

  // ========================================================================
  // GEDCOM EXPORT
  // ========================================================================

  toGedcom() {
    const lines = [];
    const now = new Date().toISOString().split('T')[0].replace(/-/g, '');

    // Header
    lines.push('0 HEAD');
    lines.push('1 GEDC');
    lines.push('2 VERS 7.0');
    lines.push('1 SOUR FamilySearchSync');
    lines.push('2 NAME Family Archives Genealogy Explorer');
    lines.push(`1 DATE ${now}`);
    lines.push('1 CHAR UTF-8');

    // Individuals
    for (const [id, person] of this.persons) {
      const gedId = this.toGedcomId(id);
      lines.push(`0 @${gedId}@ INDI`);

      if (person.name?.full) {
        const surname = person.name.surname || '';
        const given = person.name.given || '';
        lines.push(`1 NAME ${given} /${surname}/`);
        if (given) lines.push(`2 GIVN ${given}`);
        if (surname) lines.push(`2 SURN ${surname}`);
      }

      if (person.gender) {
        lines.push(`1 SEX ${person.gender}`);
      }

      if (person.birth?.date || person.birth?.place) {
        lines.push('1 BIRT');
        if (person.birth.date) lines.push(`2 DATE ${person.birth.date}`);
        if (person.birth.place) {
          lines.push(`2 PLAC ${person.birth.place}`);
          if (person.birth.latitude && person.birth.longitude) {
            lines.push('3 MAP');
            lines.push(`4 LATI ${person.birth.latitude >= 0 ? 'N' : 'S'}${Math.abs(person.birth.latitude)}`);
            lines.push(`4 LONG ${person.birth.longitude >= 0 ? 'E' : 'W'}${Math.abs(person.birth.longitude)}`);
          }
        }
      }

      if (person.death?.date || person.death?.place) {
        lines.push('1 DEAT');
        if (person.death.date) lines.push(`2 DATE ${person.death.date}`);
        if (person.death.place) lines.push(`2 PLAC ${person.death.place}`);
      }

      if (person.occupation) {
        lines.push('1 OCCU ' + person.occupation);
      }

      // Link to FamilySearch
      lines.push(`1 _FSID ${id}`);
    }

    // Families
    for (const [id, family] of this.families) {
      const famId = this.toGedcomId(id);
      lines.push(`0 @${famId}@ FAM`);

      if (family.husband) {
        lines.push(`1 HUSB @${this.toGedcomId(family.husband)}@`);
      }
      if (family.wife) {
        lines.push(`1 WIFE @${this.toGedcomId(family.wife)}@`);
      }
      for (const childId of family.children) {
        lines.push(`1 CHIL @${this.toGedcomId(childId)}@`);
      }
    }

    lines.push('0 TRLR');
    return lines.join('\n');
  }

  toGedcomId(fsId) {
    // Convert FamilySearch ID to valid GEDCOM ID
    return fsId.replace(/-/g, '');
  }

  // Get last sync info
  getLastSyncInfo() {
    try {
      const info = localStorage.getItem('familysearch_last_sync');
      return info ? JSON.parse(info) : null;
    } catch (e) {
      return null;
    }
  }

  saveLastSyncInfo(stats) {
    localStorage.setItem('familysearch_last_sync', JSON.stringify({
      timestamp: new Date().toISOString(),
      ...stats
    }));
  }

  logout() {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;
    localStorage.removeItem('familysearch_credentials');
  }
}

// ============================================================================
// DATA INDEXER - Builds efficient indexes for large GEDCOM files
// ============================================================================

class GenealogyDataIndexer {
  constructor() {
    this.indexes = {
      bySurname: new Map(),      // surname -> [person ids]
      byPlace: new Map(),         // place -> [person ids]
      byCountry: new Map(),       // country -> [person ids]
      byDecade: new Map(),        // decade -> [person ids]
      byOccupation: new Map(),    // occupation -> [person ids]
      familyBranches: new Map(),  // surname -> family tree summary
    };
    this.summary = null;
  }

  buildIndexes(individuals, families) {
    this.indexes = {
      bySurname: new Map(),
      byPlace: new Map(),
      byCountry: new Map(),
      byDecade: new Map(),
      byOccupation: new Map(),
      familyBranches: new Map(),
    };

    const places = new Set();
    const countries = new Map(); // country -> count
    const occupations = new Map(); // occupation -> count
    const surnames = new Map(); // surname -> count

    individuals.forEach((person, id) => {
      // Index by surname
      const surname = person.name?.surname;
      if (surname) {
        if (!this.indexes.bySurname.has(surname)) {
          this.indexes.bySurname.set(surname, []);
        }
        this.indexes.bySurname.get(surname).push(id);
        surnames.set(surname, (surnames.get(surname) || 0) + 1);
      }

      // Index by birth place
      if (person.birth?.place) {
        const place = person.birth.place;
        places.add(place);

        if (!this.indexes.byPlace.has(place)) {
          this.indexes.byPlace.set(place, []);
        }
        this.indexes.byPlace.get(place).push(id);

        // Extract country (last part of place)
        const parts = place.split(',').map(p => p.trim());
        const country = parts[parts.length - 1];
        if (country) {
          if (!this.indexes.byCountry.has(country)) {
            this.indexes.byCountry.set(country, []);
          }
          this.indexes.byCountry.get(country).push(id);
          countries.set(country, (countries.get(country) || 0) + 1);
        }
      }

      // Index by birth decade
      if (person.birth?.date?.year) {
        const decade = Math.floor(person.birth.date.year / 10) * 10;
        if (!this.indexes.byDecade.has(decade)) {
          this.indexes.byDecade.set(decade, []);
        }
        this.indexes.byDecade.get(decade).push(id);
      }

      // Index by occupation
      if (person.occupation) {
        const occ = person.occupation.toLowerCase();
        if (!this.indexes.byOccupation.has(occ)) {
          this.indexes.byOccupation.set(occ, []);
        }
        this.indexes.byOccupation.get(occ).push(id);
        occupations.set(person.occupation, (occupations.get(person.occupation) || 0) + 1);
      }
    });

    // Build summary
    this.summary = {
      totalIndividuals: individuals.size,
      totalFamilies: families.size,
      surnames: Array.from(surnames.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 30)
        .map(([name, count]) => ({ name, count })),
      countries: Array.from(countries.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({ name, count })),
      places: Array.from(places).slice(0, 50),
      occupations: Array.from(occupations.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([name, count]) => ({ name, count })),
      yearRange: this.getYearRange(individuals),
    };

    return this.summary;
  }

  getYearRange(individuals) {
    let min = Infinity, max = -Infinity;
    individuals.forEach(p => {
      if (p.birth?.date?.year) {
        min = Math.min(min, p.birth.date.year);
        max = Math.max(max, p.birth.date.year);
      }
    });
    return { min: min === Infinity ? null : min, max: max === -Infinity ? null : max };
  }

  // Get relevant context based on query keywords
  getRelevantContext(query, individuals, families, maxPersons = 100, relationshipContext = null) {
    const queryLower = query.toLowerCase();
    const relevantIds = new Set();
    const context = { persons: [], families: [], stats: {}, relationshipInfo: null };

    // Relationship keywords for detecting relationship-based queries
    const relationshipKeywords = {
      cousin: ['cousin', 'cousins'],
      ancestor: ['ancestor', 'ancestors', 'grandparent', 'grandparents', 'great-grandparent', 'forefather', 'forefathers'],
      descendant: ['descendant', 'descendants', 'grandchild', 'grandchildren', 'great-grandchild'],
      sibling: ['sibling', 'siblings', 'brother', 'brothers', 'sister', 'sisters'],
      parent: ['parent', 'parents', 'father', 'mother', 'dad', 'mom'],
      child: ['child', 'children', 'son', 'sons', 'daughter', 'daughters'],
      aunt_uncle: ['aunt', 'aunts', 'uncle', 'uncles'],
      niece_nephew: ['niece', 'nieces', 'nephew', 'nephews'],
      spouse: ['spouse', 'spouses', 'husband', 'wife', 'married'],
      inlaw: ['in-law', 'in-laws', 'inlaw', 'inlaws', 'father-in-law', 'mother-in-law', 'brother-in-law', 'sister-in-law'],
      // "relatives" or "family" means ALL relationship types
      _all: ['relative', 'relatives', 'family', 'family members', 'related to', 'kin', 'kinfolk']
    };

    // Detect if this is a relationship-based query
    let requestedRelationshipTypes = [];
    let searchAllRelatives = false;

    for (const [relType, keywords] of Object.entries(relationshipKeywords)) {
      if (keywords.some(kw => queryLower.includes(kw))) {
        if (relType === '_all') {
          // "relatives" means search ALL relationship types
          searchAllRelatives = true;
          requestedRelationshipTypes = ['ancestor', 'descendant', 'sibling', 'cousin', 'aunt_uncle', 'niece_nephew', 'spouse', 'inlaw'];
          break;
        } else {
          requestedRelationshipTypes.push(relType);
        }
      }
    }

    // Find the subject person (e.g., "Stefano Morello" in "cousins of Stefano Morello")
    let subjectPersonId = null;
    let subjectPersonName = null;
    let matchedByGivenNameOnly = false;

    // Try to find a person name in the query
    if (requestedRelationshipTypes.length > 0) {
      const candidates = [];

      // Helper to escape special regex characters
      const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // Check if query mentions a specific person
      individuals.forEach((person, id) => {
        const fullName = person.name?.full?.toLowerCase();
        const givenName = person.name?.given?.toLowerCase();
        const surname = person.name?.surname?.toLowerCase();

        // Skip names with unusual characters that would cause issues
        if (!fullName || fullName.length < 2) return;

        // Priority 1: Full name match (query contains full name)
        if (fullName && queryLower.includes(fullName)) {
          candidates.push({ id, name: person.name.full, priority: 1 });
        }
        // Priority 2: Given + surname both mentioned as word boundaries
        else if (givenName && surname && givenName.length > 2 && surname.length > 2) {
          try {
            const givenPattern = new RegExp(`\\b${escapeRegex(givenName)}\\b`, 'i');
            const surnamePattern = new RegExp(`\\b${escapeRegex(surname)}\\b`, 'i');
            if (givenPattern.test(queryLower) && surnamePattern.test(queryLower)) {
              candidates.push({ id, name: person.name.full, priority: 2 });
            }
          } catch (e) {
            // Skip invalid regex patterns
          }
        }
        // Priority 3: Just given name (if it appears as a word boundary)
        else if (givenName && givenName.length > 2) {
          try {
            const givenNamePattern = new RegExp(`\\b${escapeRegex(givenName)}\\b`, 'i');
            if (givenNamePattern.test(queryLower)) {
              candidates.push({ id, name: person.name.full, priority: 3, givenOnly: true });
            }
          } catch (e) {
            // Skip invalid regex patterns
          }
        }
      });

      // Sort by priority and pick best match
      candidates.sort((a, b) => a.priority - b.priority);

      if (candidates.length > 0) {
        // If only given name matches, check if it's unique enough
        const bestMatch = candidates[0];
        if (bestMatch.givenOnly) {
          // Count how many people share this given name
          const givenNameMatches = candidates.filter(c => c.givenOnly);
          if (givenNameMatches.length === 1) {
            // Unique given name, use it
            subjectPersonId = bestMatch.id;
            subjectPersonName = bestMatch.name;
            matchedByGivenNameOnly = true;
          } else if (givenNameMatches.length <= 5) {
            // Few matches - use the first one but note ambiguity
            subjectPersonId = bestMatch.id;
            subjectPersonName = bestMatch.name;
            matchedByGivenNameOnly = true;
            console.log(`Note: "${bestMatch.name}" matched by given name only. ${givenNameMatches.length} people share this name.`);
          }
        } else {
          subjectPersonId = bestMatch.id;
          subjectPersonName = bestMatch.name;
        }
      }

      // If no specific person mentioned but we have a reference person, use that
      if (!subjectPersonId && relationshipContext?.referencePerson) {
        // Check for possessive pronouns like "my cousins" or just "the cousins"
        if (queryLower.includes('my ') || queryLower.includes(' my') ||
            !queryLower.match(/of\s+\w+/)) {
          subjectPersonId = relationshipContext.referencePerson;
          subjectPersonName = relationshipContext.referencePersonName;
        }
      }

    }

    // Detect follow-up queries (e.g., "What about Brazil?", "And the Caruzzos?")
    const followUpPatterns = [
      /^(?:what about|how about|and (?:in |the )?|what of|any in)/i,
      /^(?:show me|list|find)(?: the| those| ones)? (?:in|from|who)/i
    ];
    const isFollowUp = followUpPatterns.some(p => p.test(query.trim())) ||
                       (query.length < 50 && !requestedRelationshipTypes.length && relationshipContext?.lastQueryContext);

    // If this looks like a follow-up and we have previous context, reuse it
    if (isFollowUp && relationshipContext?.lastQueryContext && !subjectPersonId) {
      const prevCtx = relationshipContext.lastQueryContext;
      subjectPersonId = prevCtx.subjectPersonId;
      subjectPersonName = prevCtx.subjectPerson;
      if (!requestedRelationshipTypes.length) {
        requestedRelationshipTypes = prevCtx.requestedTypes || ['cousin'];
      }
    }

    // Handle relationship query without subject person - inform about the issue
    if (requestedRelationshipTypes.length > 0 && !subjectPersonId) {
      context.relationshipInfo = {
        subjectPerson: null,
        requestedTypes: requestedRelationshipTypes,
        error: 'Could not identify the person in the query. Please use their full name (e.g., "cousins of Maria Rossi") or set a Reference Person in the filter bar.'
      };
      // Still return empty context - the prompt will explain the issue
      context.stats.summary = this.summary;
      return context;
    }

    // If we have a relationship query with a subject person, use the relationship cache
    if (requestedRelationshipTypes.length > 0 && subjectPersonId && relationshipContext) {
      // Get the appropriate relationship cache
      // First check if we can reuse from previous context (for follow-ups)
      let cacheToUse = null;

      if (isFollowUp && relationshipContext.lastQueryContext?._cacheUsed &&
          relationshipContext.lastQueryContext.subjectPersonId === subjectPersonId) {
        cacheToUse = relationshipContext.lastQueryContext._cacheUsed;
      } else if (subjectPersonId === relationshipContext.referencePerson) {
        cacheToUse = relationshipContext.relationshipCache;
      } else if (relationshipContext.recalculateForPerson) {
        cacheToUse = relationshipContext.recalculateForPerson(subjectPersonId);
      }

      if (!cacheToUse || cacheToUse.size === 0) {
        return context;
      }

      context.relationshipInfo = {
        subjectPerson: subjectPersonName,
        subjectPersonId: subjectPersonId,
        requestedTypes: searchAllRelatives ? ['all relatives'] : requestedRelationshipTypes,
        _cacheUsed: cacheToUse,  // Store for later lookup
        _searchAllRelatives: searchAllRelatives
      };

      // Find all people matching the requested relationship types
      cacheToUse.forEach((relData, personId) => {
        // If searching all relatives, include everyone except 'self' and 'unrelated'
        if (searchAllRelatives) {
          if (relData.type !== 'self' && relData.type !== 'unrelated') {
            relevantIds.add(personId);
          }
        } else if (requestedRelationshipTypes.includes(relData.type)) {
          relevantIds.add(personId);
        }
        // Handle parent/child as subset of ancestor/descendant
        if (requestedRelationshipTypes.includes('parent') && relData.type === 'ancestor' && relData.generation === 1) {
          relevantIds.add(personId);
        }
        if (requestedRelationshipTypes.includes('child') && relData.type === 'descendant' && relData.generation === 1) {
          relevantIds.add(personId);
        }
      });

      // Now filter by other criteria (location, etc.)
      const locationFilter = this.extractLocationFilter(queryLower);
      if (locationFilter) {
        const filteredIds = new Set();
        const { location, locations, exclude, multi } = locationFilter;
        const locationList = multi ? locations : [location];

        relevantIds.forEach(id => {
          const person = individuals.get(id);
          const birthPlace = person?.birth?.place?.toLowerCase() || '';
          const deathPlace = person?.death?.place?.toLowerCase() || '';

          // Check if matches any of the locations
          const matchesLocation = locationList.some(loc =>
            birthPlace.includes(loc) || deathPlace.includes(loc)
          );

          // If exclude is true, we want people NOT in that location
          // If exclude is false, we want people IN that location
          if (exclude ? !matchesLocation : matchesLocation) {
            filteredIds.add(id);
          }
        });

        // Add context about the location filter
        const locDesc = locationList.join(' or ');
        context.relationshipInfo.locationFilter = {
          location: locDesc,
          exclude: exclude,
          description: exclude ? `NOT in ${locDesc}` : `in ${locDesc}`
        };

        relevantIds.clear();
        filteredIds.forEach(id => relevantIds.add(id));
      }
    } else {
      // Original keyword-based search for non-relationship queries
      // Check for surname mentions
      this.indexes.bySurname.forEach((ids, surname) => {
        if (queryLower.includes(surname.toLowerCase())) {
          ids.forEach(id => relevantIds.add(id));
        }
      });

      // Check for place/country mentions
      const placeKeywords = ['argentina', 'italy', 'sicily', 'new york', 'america', 'usa',
        'united states', 'brazil', 'spain', 'france', 'germany', 'migrate', 'migration',
        'moved', 'emigrate', 'immigrate'];

      if (placeKeywords.some(kw => queryLower.includes(kw))) {
        this.indexes.byCountry.forEach((ids, country) => {
          if (queryLower.includes(country.toLowerCase())) {
            ids.forEach(id => relevantIds.add(id));
          }
        });
        this.indexes.byPlace.forEach((ids, place) => {
          if (queryLower.includes(place.toLowerCase().split(',')[0])) {
            ids.forEach(id => relevantIds.add(id));
          }
        });
      }

      // Check for occupation queries
      if (queryLower.includes('job') || queryLower.includes('occupation') ||
          queryLower.includes('work') || queryLower.includes('profession')) {
        this.indexes.byOccupation.forEach((ids, occ) => {
          ids.slice(0, 20).forEach(id => relevantIds.add(id));
        });
        context.stats.occupations = this.summary.occupations;
      }

      // Check for time-based queries
      const decadeMatch = queryLower.match(/(\d{4})s?|(\d{2})th century/);
      if (decadeMatch || queryLower.includes('oldest') || queryLower.includes('earliest') ||
          queryLower.includes('oldest') || queryLower.includes('ancient')) {
        const sortedByYear = Array.from(individuals.entries())
          .filter(([id, p]) => p.birth?.date?.year)
          .sort((a, b) => a[1].birth.date.year - b[1].birth.date.year);

        if (queryLower.includes('oldest') || queryLower.includes('earliest')) {
          sortedByYear.slice(0, 20).forEach(([id]) => relevantIds.add(id));
        }
      }

      // If no specific matches, provide a general sample
      if (relevantIds.size === 0) {
        const sample = Array.from(individuals.keys()).slice(0, 50);
        sample.forEach(id => relevantIds.add(id));
      }
    }

    // Limit and format persons
    const selectedIds = Array.from(relevantIds).slice(0, maxPersons);
    selectedIds.forEach(id => {
      const person = individuals.get(id);
      if (person) {
        // Include relationship info if available - use the correct cache
        const cacheForLookup = context.relationshipInfo?._cacheUsed || relationshipContext?.relationshipCache;
        const relData = cacheForLookup?.get(id);
        context.persons.push(this.formatPersonForContext(id, person, families, relData));
      }
    });

    // Add relevant family connections
    families.forEach((family, famId) => {
      const relevantFamily =
        (family.husband && relevantIds.has(family.husband)) ||
        (family.wife && relevantIds.has(family.wife)) ||
        family.children?.some(c => relevantIds.has(c));

      if (relevantFamily) {
        context.families.push(this.formatFamilyForContext(famId, family, individuals));
      }
    });

    context.stats.summary = this.summary;

    return context;
  }

  extractLocationFilter(queryLower) {
    const locationAliases = {
      'united states': 'united states',
      'us': 'united states',
      'usa': 'united states',
      'america': 'united states',
      'u.s.': 'united states',
      'u.s.a.': 'united states'
    };

    // Check for "outside of" / "not in" patterns (negative filter)
    const negativePatterns = [
      /(?:outside\s+(?:of\s+)?|not\s+in\s+|(?:don't|doesn't|didn't)\s+live\s+in\s+)(?:the\s+)?([a-z\s]+)/i,
      /(?:live|living|lived|born)\s+(?:outside\s+(?:of\s+)?|not\s+in\s+)(?:the\s+)?([a-z\s]+)/i
    ];

    for (const pattern of negativePatterns) {
      const match = queryLower.match(pattern);
      if (match) {
        const location = match[1].trim().replace(/[?.!,]$/, '');
        return {
          location: locationAliases[location] || location,
          exclude: true
        };
      }
    }

    // Positive location patterns
    const positivePatterns = [
      /(?:live|living|lived|born|moved|emigrated?|immigrated?)\s+(?:in|to)\s+(?:the\s+)?([a-z\s]+)/i,
      /(?:in|from)\s+(?:the\s+)?([a-z]+\s+states?|[a-z]+)/i
    ];

    for (const pattern of positivePatterns) {
      const match = queryLower.match(pattern);
      if (match) {
        const location = match[1].trim().replace(/[?.!,]$/, '');
        return {
          location: locationAliases[location] || location,
          exclude: false
        };
      }
    }

    // Direct keyword check for common locations
    for (const [alias, canonical] of Object.entries(locationAliases)) {
      if (queryLower.includes(alias)) {
        return { location: canonical, exclude: false };
      }
    }

    // Check for other country names - support multiple locations (Brazil AND Argentina)
    const countries = ['italy', 'argentina', 'brazil', 'france', 'germany', 'spain', 'sicily', 'new york', 'chicago', 'friuli'];
    const foundLocations = [];

    for (const country of countries) {
      if (queryLower.includes(country)) {
        // Check if it's a negative context
        const negContext = queryLower.includes(`outside ${country}`) ||
                          queryLower.includes(`outside of ${country}`) ||
                          queryLower.includes(`not in ${country}`) ||
                          queryLower.includes(`not from ${country}`);
        foundLocations.push({ location: country, exclude: negContext });
      }
    }

    if (foundLocations.length > 0) {
      // If multiple locations, return as array
      if (foundLocations.length > 1) {
        return { locations: foundLocations.map(l => l.location), exclude: foundLocations[0].exclude, multi: true };
      }
      return foundLocations[0];
    }

    return null;
  }

  formatPersonForContext(id, person, families, relData = null) {
    const formatted = {
      id,
      name: person.name?.full || 'Unknown',
      surname: person.name?.surname || '',
      sex: person.sex,
      birth: person.birth?.date?.year ? {
        year: person.birth.date.year,
        place: person.birth.place || null
      } : null,
      death: person.death?.date?.year ? {
        year: person.death.date.year,
        place: person.death.place || null
      } : null,
      occupation: person.occupation || null,
    };

    // Add relationship info if available
    if (relData) {
      formatted.relationship = {
        type: relData.type,
        label: relData.label,
        generation: relData.generation,
        degree: relData.degree,
        distance: relData.distance
      };
    }

    return formatted;
  }

  formatFamilyForContext(famId, family, individuals) {
    const getPersonName = (id) => {
      const p = individuals.get(id);
      return p?.name?.full || 'Unknown';
    };

    return {
      id: famId,
      husband: family.husband ? getPersonName(family.husband) : null,
      wife: family.wife ? getPersonName(family.wife) : null,
      children: family.children?.map(getPersonName) || []
    };
  }
}

// ============================================================================
// AI QUERY ENGINE - Handles API calls and context building
// ============================================================================

class AIQueryEngine {
  constructor(indexer) {
    this.indexer = indexer;
    this.settings = this.loadSettings();
    this.conversationHistory = [];
    this.lastQueryContext = null; // Remember subject person from previous query
  }

  loadSettings() {
    const saved = localStorage.getItem('genealogy_ai_settings');
    if (saved) {
      return JSON.parse(saved);
    }
    return {
      provider: 'openrouter',
      apiKey: '',
      model: 'anthropic/claude-3.5-sonnet'
    };
  }

  saveSettings(settings) {
    this.settings = { ...this.settings, ...settings };
    localStorage.setItem('genealogy_ai_settings', JSON.stringify(this.settings));
  }

  buildSystemPrompt(context) {
    let relationshipNote = '';
    if (context.relationshipInfo && !context.relationshipInfo.error) {
      const { subjectPerson, requestedTypes, locationFilter } = context.relationshipInfo;
      relationshipNote = `
## RELATIONSHIP QUERY - IMPORTANT
You are answering a query about ${requestedTypes.join('/')} of **${subjectPerson}**.
${locationFilter ? `Location filter: ${locationFilter.description}` : ''}

The data below contains ONLY verified ${requestedTypes.join('/')} of ${subjectPerson} based on actual genealogical calculations.
- Each person has a [relationship label] showing their exact relationship (e.g., "1st cousin", "2nd cousin 1x removed")
- If the list shows ${context.persons.length} people, that's exactly how many matching relatives were found
- If the list is empty, there are NO ${requestedTypes.join('/')} matching the criteria - say this clearly

DO NOT say "${subjectPerson} was not found" or "no data available" - we already found them and calculated their relatives.
`;
    } else if (context.relationshipInfo?.error) {
      relationshipNote = `
## QUERY ISSUE
${context.relationshipInfo.error}
`;
    }

    return `You are a helpful genealogy research assistant. You analyze family tree data and provide accurate answers.

## Database Summary
- Total: ${context.stats.summary.totalIndividuals} individuals, ${context.stats.summary.totalFamilies} families
- Years: ${context.stats.summary.yearRange.min || '?'} - ${context.stats.summary.yearRange.max || '?'}
- Surnames: ${context.stats.summary.surnames.slice(0, 8).map(s => s.name).join(', ')}
- Countries: ${context.stats.summary.countries.slice(0, 6).map(c => c.name).join(', ')}
${relationshipNote}
## Response Guidelines
- List ALL matching people with names, dates, and places
- Include each person's [relationship label] from the data
- If 0 results: clearly state "No [relatives] of [person] were found [in location]"
- Never claim someone "doesn't exist" if data was provided about their relatives
- Be specific and list actual names from the provided data`;
  }

  buildUserPrompt(query, context) {
    let prompt = `Question: ${query}\n\n`;

    // Add relationship context if this is a relationship-based query
    if (context.relationshipInfo) {
      const { subjectPerson, requestedTypes, locationFilter, error } = context.relationshipInfo;

      // Handle error case (couldn't find subject person)
      if (error) {
        prompt += `## Relationship Query Issue\n`;
        prompt += `The user is asking about: ${requestedTypes.join(', ')}\n`;
        prompt += `**ERROR: ${error}**\n\n`;
        prompt += `Please explain to the user that you couldn't identify the person they're asking about, and suggest they:\n`;
        prompt += `1. Use the full name (e.g., "cousins of Maria Rossi" instead of just "Maria")\n`;
        prompt += `2. Set themselves as the Reference Person in the filter bar to use "my cousins"\n\n`;
      } else {
        prompt += `## Relationship Query Context\n`;
        prompt += `Subject Person: ${subjectPerson}\n`;
        prompt += `Looking for: ${requestedTypes.join(', ')}\n`;
        if (locationFilter) {
          prompt += `Location filter: ${locationFilter.description}\n`;
        }
        prompt += `Found ${context.persons.length} matching relatives.\n\n`;

        if (context.persons.length === 0) {
          prompt += `**NOTE: No ${requestedTypes.join('/')} of ${subjectPerson} were found`;
          if (locationFilter) {
            prompt += ` ${locationFilter.description}`;
          }
          prompt += `.** Please inform the user clearly that the search found no matches.\n\n`;
        }
      }
    }

    if (context.persons.length > 0) {
      const headerNote = (context.relationshipInfo && context.relationshipInfo.subjectPerson)
        ? `(all are ${context.relationshipInfo.requestedTypes.join('/')} of ${context.relationshipInfo.subjectPerson})`
        : '';
      prompt += `## Relevant Individuals (${context.persons.length} people) ${headerNote}\n`;

      context.persons.forEach(p => {
        let line = `- ${p.name}`;

        // Add relationship label if available
        if (p.relationship?.label) {
          line += ` [${p.relationship.label}]`;
        }

        if (p.birth) {
          line += ` (b. ${p.birth.year}${p.birth.place ? ', ' + p.birth.place : ''})`;
        }
        if (p.death) {
          line += ` (d. ${p.death.year})`;
        }
        if (p.occupation) {
          line += ` - ${p.occupation}`;
        }
        prompt += line + '\n';
      });
    }

    if (context.families.length > 0 && context.families.length <= 30) {
      prompt += `\n## Family Connections\n`;
      context.families.slice(0, 30).forEach(f => {
        let line = '';
        if (f.husband && f.wife) {
          line = `- ${f.husband} married ${f.wife}`;
        } else if (f.husband) {
          line = `- ${f.husband}`;
        } else if (f.wife) {
          line = `- ${f.wife}`;
        }
        if (f.children.length > 0) {
          line += ` → children: ${f.children.join(', ')}`;
        }
        if (line) prompt += line + '\n';
      });
    }

    prompt += '\nPlease answer the question based on this genealogical data.';
    return prompt;
  }

  async query(userQuery, individuals, families, relationshipContext = null) {
    if (!this.settings.apiKey) {
      throw new Error('Please enter an API key in the settings above.');
    }

    // Add last query context for follow-up detection
    if (relationshipContext) {
      relationshipContext.lastQueryContext = this.lastQueryContext;
    }

    // Build context with relationship awareness
    const context = this.indexer.getRelevantContext(userQuery, individuals, families, 200, relationshipContext);

    // Save context for follow-up queries
    if (context.relationshipInfo && context.relationshipInfo.subjectPersonId) {
      this.lastQueryContext = {
        subjectPersonId: context.relationshipInfo.subjectPersonId,
        subjectPerson: context.relationshipInfo.subjectPerson,
        requestedTypes: context.relationshipInfo.requestedTypes,
        _cacheUsed: context.relationshipInfo._cacheUsed
      };
    }

    // Build messages
    const systemPrompt = this.buildSystemPrompt(context);
    const userPrompt = this.buildUserPrompt(userQuery, context);

    const messages = [
      { role: 'system', content: systemPrompt },
      ...this.conversationHistory.slice(-4), // Keep last 2 exchanges
      { role: 'user', content: userPrompt }
    ];

    // Make API call
    const response = await this.callAPI(messages);

    // Update conversation history
    this.conversationHistory.push(
      { role: 'user', content: userQuery },
      { role: 'assistant', content: response }
    );

    return response;
  }

  async callAPI(messages) {
    const { provider, apiKey, model } = this.settings;

    let url, headers, body;

    if (provider === 'openrouter') {
      url = 'https://openrouter.ai/api/v1/chat/completions';
      headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'HTTP-Referer': window.location.href,
        'X-Title': 'Genealogy Explorer'
      };
      body = {
        model: model,
        messages: messages,
        max_tokens: 2000,
        temperature: 0.7
      };
    } else if (provider === 'openai') {
      url = 'https://api.openai.com/v1/chat/completions';
      headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      };
      // Convert model name for OpenAI
      const openaiModel = model.includes('/') ? model.split('/')[1] : model;
      body = {
        model: openaiModel.startsWith('gpt') ? openaiModel : 'gpt-5.2-mini',
        messages: messages,
        max_completion_tokens: 16000,
        temperature: 0.7
      };
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      console.error('API Error Response:', error);
      throw new Error(error.error?.message || `API error: ${response.status}`);
    }

    const data = await response.json();

    if (!data.choices || !data.choices[0]) {
      console.error('Invalid API response structure:', data);
      throw new Error('Invalid response from AI - no choices returned');
    }

    // Try multiple content locations (different API formats)
    const choice = data.choices[0];
    const content = choice.message?.content ||
                    choice.delta?.content ||
                    choice.text ||
                    '';

    if (!content) {
      // Check for refusal or other issues
      if (choice.message?.refusal) {
        return `AI refused to answer: ${choice.message.refusal}`;
      }
      if (choice.finish_reason === 'content_filter') {
        return 'Response was filtered by content policy.';
      }
      console.warn('Empty content from AI, finish_reason:', choice.finish_reason);
      return 'No response generated. The AI returned empty content.';
    }

    return content;
  }

  clearHistory() {
    this.conversationHistory = [];
  }
}

// ============================================================================
// GEDCOM PARSER - Simple line-by-line approach
// ============================================================================

class GedcomParser {
  constructor() {
    this.individuals = new Map();
    this.families = new Map();
  }

  parse(gedcomText) {
    const lines = gedcomText.split('\n');

    let currentIndividual = null;
    let currentFamily = null;
    let currentContext = null; // 'BIRT', 'DEAT', etc.
    let inPlace = false;
    let inMap = false;

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;

      // Parse: level [xref] tag [value]
      const match = line.match(/^(\d+)\s+(@[^@]+@)?\s*(\S+)\s*(.*)$/);
      if (!match) continue;

      const level = parseInt(match[1]);
      const xref = match[2] || null;
      const tag = match[3];
      const value = match[4]?.trim() || '';

      // Level 0 - new record
      if (level === 0) {
        currentIndividual = null;
        currentFamily = null;
        currentContext = null;
        inPlace = false;
        inMap = false;

        if (tag === 'INDI' && xref) {
          currentIndividual = {
            id: xref,
            name: null,
            sex: null,
            birth: null,
            death: null,
            occupation: null,
            familyChild: [],
            familySpouse: []
          };
          this.individuals.set(xref, currentIndividual);
        } else if (tag === 'FAM' && xref) {
          currentFamily = {
            id: xref,
            husband: null,
            wife: null,
            children: []
          };
          this.families.set(xref, currentFamily);
        }
        continue;
      }

      // Level 1 - main properties
      if (level === 1) {
        currentContext = null;
        inPlace = false;
        inMap = false;

        if (currentIndividual) {
          if (tag === 'NAME') {
            currentIndividual.name = this.parseName(value);
          } else if (tag === 'SEX') {
            currentIndividual.sex = value;
          } else if (tag === 'BIRT') {
            currentIndividual.birth = { date: null, place: null, coordinates: null };
            currentContext = 'BIRT';
          } else if (tag === 'DEAT') {
            currentIndividual.death = { date: null, place: null, coordinates: null, occurred: true };
            currentContext = 'DEAT';
          } else if (tag === 'OCCU') {
            currentIndividual.occupation = value;
          } else if (tag === 'FAMC') {
            currentIndividual.familyChild.push(value);
          } else if (tag === 'FAMS') {
            currentIndividual.familySpouse.push(value);
          }
        }

        if (currentFamily) {
          if (tag === 'HUSB') {
            currentFamily.husband = value;
          } else if (tag === 'WIFE') {
            currentFamily.wife = value;
          } else if (tag === 'CHIL') {
            currentFamily.children.push(value);
          }
        }
        continue;
      }

      // Level 2 - sub-properties
      if (level === 2) {
        inPlace = false;
        inMap = false;

        if (currentIndividual && currentIndividual.name && tag === 'GIVN') {
          currentIndividual.name.given = value;
        } else if (currentIndividual && currentIndividual.name && tag === 'SURN') {
          currentIndividual.name.surname = value;
        }

        if (currentContext === 'BIRT' && currentIndividual?.birth) {
          if (tag === 'DATE') {
            currentIndividual.birth.date = this.parseDate(value);
          } else if (tag === 'PLAC') {
            currentIndividual.birth.place = value;
            inPlace = true;
          }
        } else if (currentContext === 'DEAT' && currentIndividual?.death) {
          if (tag === 'DATE') {
            currentIndividual.death.date = this.parseDate(value);
          } else if (tag === 'PLAC') {
            currentIndividual.death.place = value;
            inPlace = true;
          }
        }
        continue;
      }

      // Level 3 - place sub-properties
      if (level === 3 && inPlace) {
        if (tag === 'MAP') {
          inMap = true;
        }
        continue;
      }

      // Level 4 - map coordinates
      if (level === 4 && inMap) {
        if (currentContext === 'BIRT' && currentIndividual?.birth) {
          if (!currentIndividual.birth.coordinates) {
            currentIndividual.birth.coordinates = { lat: null, lng: null };
          }
          if (tag === 'LATI') {
            currentIndividual.birth.coordinates.lat = this.parseCoordinate(value);
          } else if (tag === 'LONG') {
            currentIndividual.birth.coordinates.lng = this.parseCoordinate(value);
          }
        } else if (currentContext === 'DEAT' && currentIndividual?.death) {
          if (!currentIndividual.death.coordinates) {
            currentIndividual.death.coordinates = { lat: null, lng: null };
          }
          if (tag === 'LATI') {
            currentIndividual.death.coordinates.lat = this.parseCoordinate(value);
          } else if (tag === 'LONG') {
            currentIndividual.death.coordinates.lng = this.parseCoordinate(value);
          }
        }
      }
    }

    console.log(`Parsed ${this.individuals.size} individuals and ${this.families.size} families`);

    // Debug: check coordinates
    let withCoords = 0;
    this.individuals.forEach(p => {
      if (p.birth?.coordinates?.lat && p.birth?.coordinates?.lng) withCoords++;
    });
    console.log(`${withCoords} individuals have birth coordinates`);

    // Debug: check family links
    let withFamilyChild = 0;
    let withFamilySpouse = 0;
    this.individuals.forEach(p => {
      if (p.familyChild.length > 0) withFamilyChild++;
      if (p.familySpouse.length > 0) withFamilySpouse++;
    });
    console.log(`${withFamilyChild} individuals have familyChild, ${withFamilySpouse} have familySpouse`);

    return {
      individuals: this.individuals,
      families: this.families
    };
  }

  parseName(nameStr) {
    const match = nameStr.match(/^([^\/]*)\/?([^\/]*)\/?(.*)$/);
    if (match) {
      return {
        full: nameStr.replace(/\//g, '').trim(),
        given: match[1].trim(),
        surname: match[2].trim(),
        suffix: match[3].trim()
      };
    }
    return { full: nameStr, given: nameStr, surname: '', suffix: '' };
  }

  parseDate(dateStr) {
    const months = {
      'JAN': 0, 'FEB': 1, 'MAR': 2, 'APR': 3, 'MAY': 4, 'JUN': 5,
      'JUL': 6, 'AUG': 7, 'SEP': 8, 'OCT': 9, 'NOV': 10, 'DEC': 11
    };

    const yearMatch = dateStr.match(/(\d{4})/);
    const year = yearMatch ? parseInt(yearMatch[1]) : null;

    const monthMatch = dateStr.match(/([A-Z]{3})/i);
    const month = monthMatch ? months[monthMatch[1].toUpperCase()] : null;

    const dayMatch = dateStr.match(/^(\d{1,2})\s+[A-Z]/i);
    const day = dayMatch ? parseInt(dayMatch[1]) : null;

    return {
      original: dateStr,
      year,
      month,
      day
    };
  }

  parseCoordinate(coordStr) {
    const match = coordStr.match(/([NSEW])?([\d.]+)/);
    if (match) {
      const direction = match[1];
      const value = parseFloat(match[2]);
      return (direction === 'S' || direction === 'W') ? -value : value;
    }
    return parseFloat(coordStr);
  }
}

// ============================================================================
// GENEALOGY APP
// ============================================================================

class GenealogyApp {
  constructor() {
    this.parser = new GedcomParser();
    this.data = null;
    this.map = null;
    this.treeZoom = null;

    // AI Query components
    this.indexer = new GenealogyDataIndexer();
    this.aiEngine = new AIQueryEngine(this.indexer);

    // FamilySearch client
    this.fsClient = new FamilySearchClient();
    this.fsSyncResult = null;

    // Filtering and relationship tracking
    this.referencePerson = null;
    this.relationshipCache = new Map();
    this.activeFilters = {
      surname: '',
      gender: '',
      birthYearMin: null,
      birthYearMax: null,
      birthPlace: '',
      relationshipTypes: ['self', 'ancestor', 'descendant', 'sibling', 'cousin', 'aunt_uncle', 'niece_nephew', 'spouse', 'inlaw'],
      maxGenerations: 10,
      maxDistance: null,  // null = no limit, number = max kinship distance
    };
    this.filteredResults = null;

    // Relationship color scheme
    this.relationshipColors = {
      self: '#FFD700',
      ancestor: '#3B82F6',
      descendant: '#10B981',
      sibling: '#14B8A6',
      cousin: '#8B5CF6',
      aunt_uncle: '#6366F1',
      niece_nephew: '#34D399',
      inlaw: '#F59E0B',
      spouse: '#EC4899',
      unrelated: '#6B7280'
    };

    this.init();
  }

  async init() {
    this.setupEventListeners();
    this.setupThemeToggle();
    this.setupAIInterface();
    this.setupFamilySearchInterface();
    await this.handleFamilySearchCallback();
    await this.loadDefaultGedcom();
  }

  async loadDefaultGedcom() {
    try {
      const response = await fetch('stefano_full.ged');
      if (response.ok) {
        const text = await response.text();
        this.currentFileName = 'stefano_full.ged';
        this.parseAndDisplay(text);
      } else {
        // File not found (404) - show empty state
        this.showEmptyState();
      }
    } catch (e) {
      console.log('No default GEDCOM file found:', e);
      this.showEmptyState();
    }
  }

  showEmptyState() {
    const self = this;
    document.getElementById('results-grid').innerHTML = `
      <div class="welcome-page">
        <div class="welcome-hero">
          <div class="welcome-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
              <circle cx="9" cy="7" r="4"/>
              <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
              <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
            </svg>
          </div>
          <h1 class="welcome-title">Welcome to Family Archives</h1>
          <p class="welcome-subtitle">Explore your genealogy with interactive visualizations, maps, and AI-powered insights</p>
        </div>

        <div class="welcome-upload">
          <label class="welcome-upload-btn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Upload GEDCOM File
            <input type="file" id="welcome-file-upload" accept=".ged,.gedcom">
          </label>
          <p class="welcome-upload-hint">Supports GEDCOM 5.5 and 7.0 formats</p>
        </div>

        <div class="welcome-features">
          <div class="welcome-feature">
            <div class="welcome-feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="M21 21l-4.35-4.35"/>
              </svg>
            </div>
            <h4>Smart Search</h4>
            <p>Find ancestors instantly with powerful filtering by name, date, location, and relationship</p>
          </div>

          <div class="welcome-feature">
            <div class="welcome-feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
              </svg>
            </div>
            <h4>Interactive Tree</h4>
            <p>Visualize your family tree with expandable ancestors and descendants</p>
          </div>

          <div class="welcome-feature">
            <div class="welcome-feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="10" r="3"/>
                <path d="M12 21.7C17.3 17 20 13 20 10a8 8 0 1 0-16 0c0 3 2.7 7 8 11.7z"/>
              </svg>
            </div>
            <h4>Geographic Map</h4>
            <p>See where your ancestors lived with an interactive world map</p>
          </div>

          <div class="welcome-feature">
            <div class="welcome-feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
              </svg>
            </div>
            <h4>AI Assistant</h4>
            <p>Ask questions about your family history in natural language</p>
          </div>
        </div>

        <div class="welcome-info">
          <div class="welcome-info-title">What is GEDCOM?</div>
          <p>GEDCOM is the standard file format for genealogy data. Export from apps like Ancestry, FamilySearch, MyHeritage, or Gramps. <a href="https://en.wikipedia.org/wiki/GEDCOM" target="_blank" rel="noopener">Learn more</a></p>
        </div>
      </div>
    `;

    // Add file upload handler for welcome page
    const welcomeUpload = document.getElementById('welcome-file-upload');
    if (welcomeUpload) {
      welcomeUpload.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
          self.currentFileName = file.name;
          const reader = new FileReader();
          reader.onload = (event) => {
            self.parseAndDisplay(event.target.result);
          };
          reader.readAsText(file);
        }
      });
    }
  }

  // ==================== RELATIONSHIP CALCULATION ====================

  calculateRelationships(referenceId) {
    if (!this.data || !referenceId) return;

    this.relationshipCache.clear();
    this.referencePerson = referenceId;

    // Self
    this.relationshipCache.set(referenceId, {
      type: 'self',
      generation: 0,
      degree: 0,
      distance: 0,  // Kinship distance: 0 for self
      label: 'You'
    });

    // Helper to get parents of a person
    const getParents = (personId) => {
      const person = this.data.individuals.get(personId);
      if (!person || !person.familyChild) return [];
      const parents = [];
      for (const famId of person.familyChild) {
        const family = this.data.families.get(famId);
        if (family) {
          if (family.husband) parents.push(family.husband);
          if (family.wife) parents.push(family.wife);
        }
      }
      return parents;
    };

    // Helper to get children of a person
    const getChildren = (personId) => {
      const person = this.data.individuals.get(personId);
      if (!person || !person.familySpouse) return [];
      const children = [];
      for (const famId of person.familySpouse) {
        const family = this.data.families.get(famId);
        if (family && family.children) {
          children.push(...family.children);
        }
      }
      return children;
    };

    // Helper to get spouses of a person
    const getSpouses = (personId) => {
      const person = this.data.individuals.get(personId);
      if (!person || !person.familySpouse) return [];
      const spouses = [];
      for (const famId of person.familySpouse) {
        const family = this.data.families.get(famId);
        if (family) {
          if (family.husband && family.husband !== personId) spouses.push(family.husband);
          if (family.wife && family.wife !== personId) spouses.push(family.wife);
        }
      }
      return spouses;
    };

    // Helper to get siblings of a person
    const getSiblings = (personId) => {
      const person = this.data.individuals.get(personId);
      if (!person || !person.familyChild) return [];
      const siblings = [];
      for (const famId of person.familyChild) {
        const family = this.data.families.get(famId);
        if (family && family.children) {
          for (const childId of family.children) {
            if (childId !== personId) siblings.push(childId);
          }
        }
      }
      return siblings;
    };

    // BFS for ancestors
    const ancestorQueue = [{ id: referenceId, gen: 0 }];
    const ancestorVisited = new Set([referenceId]);

    while (ancestorQueue.length > 0) {
      const { id, gen } = ancestorQueue.shift();
      const parents = getParents(id);

      for (const parentId of parents) {
        if (!ancestorVisited.has(parentId)) {
          ancestorVisited.add(parentId);
          const newGen = gen + 1;
          const label = this.getAncestorLabel(newGen, this.data.individuals.get(parentId)?.sex);
          this.relationshipCache.set(parentId, {
            type: 'ancestor',
            generation: newGen,
            degree: 0,
            distance: newGen,  // Kinship distance = generation for direct ancestors
            label
          });
          ancestorQueue.push({ id: parentId, gen: newGen });
        }
      }
    }

    // BFS for descendants
    const descendantQueue = [{ id: referenceId, gen: 0 }];
    const descendantVisited = new Set([referenceId]);

    while (descendantQueue.length > 0) {
      const { id, gen } = descendantQueue.shift();
      const children = getChildren(id);

      for (const childId of children) {
        if (!descendantVisited.has(childId) && !this.relationshipCache.has(childId)) {
          descendantVisited.add(childId);
          const newGen = gen + 1;
          const label = this.getDescendantLabel(newGen);
          this.relationshipCache.set(childId, {
            type: 'descendant',
            generation: newGen,
            degree: 0,
            distance: newGen,  // Kinship distance = generation for direct descendants
            label
          });
          descendantQueue.push({ id: childId, gen: newGen });
        }
      }
    }

    // Direct spouses
    const refSpouses = getSpouses(referenceId);
    for (const spouseId of refSpouses) {
      if (!this.relationshipCache.has(spouseId)) {
        this.relationshipCache.set(spouseId, {
          type: 'spouse',
          generation: 0,
          degree: 0,
          distance: 1,  // Spouse = 1 degree of separation
          label: 'Spouse'
        });
      }
    }

    // Siblings
    const refSiblings = getSiblings(referenceId);
    for (const sibId of refSiblings) {
      if (!this.relationshipCache.has(sibId)) {
        this.relationshipCache.set(sibId, {
          type: 'sibling',
          generation: 0,
          degree: 0,
          distance: 2,  // Sibling = 2 (1 up to parent + 1 down)
          label: 'Sibling'
        });
      }
    }

    // Find ALL cousins by going up the ENTIRE ancestor tree
    // For each ancestor, find their siblings and mark all descendants as cousins
    // Cousin degree = how many generations up to the common ancestor
    // 1st cousin = share grandparent (parent's sibling's child)
    // 2nd cousin = share great-grandparent (grandparent's sibling's grandchild)
    // etc.

    // Collect all ancestors with their generation
    const ancestorsWithGen = [];
    for (const [personId, rel] of this.relationshipCache) {
      if (rel.type === 'ancestor') {
        ancestorsWithGen.push({ id: personId, generation: rel.generation });
      }
    }

    // For each ancestor, find their siblings and trace down their descendants
    for (const ancestor of ancestorsWithGen) {
      const ancestorSiblings = getSiblings(ancestor.id);

      for (const siblingId of ancestorSiblings) {
        // Skip if already categorized
        if (this.relationshipCache.has(siblingId)) continue;

        // This is a great-aunt/uncle at some level
        const sex = this.data.individuals.get(siblingId)?.sex;
        let label;
        if (ancestor.generation === 1) {
          label = sex === 'F' ? 'Aunt' : sex === 'M' ? 'Uncle' : 'Aunt/Uncle';
        } else {
          const greats = ancestor.generation - 1;
          const prefix = greats === 1 ? 'Great' : `${greats}x Great`;
          label = sex === 'F' ? `${prefix}-Aunt` : sex === 'M' ? `${prefix}-Uncle` : `${prefix}-Aunt/Uncle`;
        }

        this.relationshipCache.set(siblingId, {
          type: 'aunt_uncle',
          generation: ancestor.generation,
          degree: 0,
          distance: ancestor.generation + 1,  // Up to ancestor, then +1 for sibling
          label
        });

        // Mark all their descendants as cousins (passing ancestor generation for calculation)
        this.markCousins(siblingId, ancestor.generation, getChildren);
      }
    }

    // Nieces/Nephews (children of siblings) and their descendants
    for (const sibId of refSiblings) {
      this.markNiecesNephews(sibId, 1, getChildren);
    }

    // In-laws (spouses of blood relatives)
    const bloodRelatives = new Map(this.relationshipCache);
    for (const [personId, rel] of bloodRelatives) {
      if (rel.type !== 'spouse' && rel.type !== 'inlaw' && rel.type !== 'self') {
        const spouses = getSpouses(personId);
        for (const spouseId of spouses) {
          if (!this.relationshipCache.has(spouseId)) {
            this.relationshipCache.set(spouseId, {
              type: 'inlaw',
              generation: rel.generation,
              degree: rel.degree,
              distance: (rel.distance || 0) + 1,  // Blood relative's distance + 1 for marriage
              label: `${rel.label}'s spouse`
            });
          }
        }
      }
    }

    console.log(`Calculated relationships for ${this.relationshipCache.size} people relative to ${referenceId}`);
  }

  markCousins(ancestorSiblingId, ancestorGeneration, getChildren) {
    // Mark all descendants of this ancestor's sibling as cousins
    // ancestorGeneration = how many generations up the ancestor is (1=parent, 2=grandparent, etc.)
    //
    // Cousin calculation:
    // - My distance to common ancestor = ancestorGeneration + 1
    // - Descendant's distance to common ancestor = generation from sibling + 1
    // - Cousin degree = min(my distance, their distance) - 1
    // - Removed = |my distance - their distance|

    const queue = [{ id: ancestorSiblingId, gen: 0 }];
    const visited = new Set([ancestorSiblingId]);
    const myDistanceToCommonAncestor = ancestorGeneration + 1;

    while (queue.length > 0) {
      const { id, gen } = queue.shift();
      const children = getChildren(id);

      for (const childId of children) {
        if (!visited.has(childId) && !this.relationshipCache.has(childId)) {
          visited.add(childId);
          const newGen = gen + 1;
          const theirDistanceToCommonAncestor = newGen + 1;

          // Calculate cousin degree and removed
          const cousinDegree = Math.min(myDistanceToCommonAncestor, theirDistanceToCommonAncestor) - 1;
          const removed = Math.abs(myDistanceToCommonAncestor - theirDistanceToCommonAncestor);

          let label;
          if (cousinDegree === 1) {
            label = '1st Cousin';
          } else if (cousinDegree === 2) {
            label = '2nd Cousin';
          } else if (cousinDegree === 3) {
            label = '3rd Cousin';
          } else {
            label = `${cousinDegree}th Cousin`;
          }

          if (removed > 0) {
            label += ` ${removed}x removed`;
          }

          // Kinship distance = sum of both paths to common ancestor
          const kinshipDistance = myDistanceToCommonAncestor + theirDistanceToCommonAncestor;

          this.relationshipCache.set(childId, {
            type: 'cousin',
            generation: newGen,
            degree: cousinDegree,
            distance: kinshipDistance,  // Total kinship distance
            label
          });
          queue.push({ id: childId, gen: newGen });
        }
      }
    }
  }

  markNiecesNephews(siblingId, generation, getChildren) {
    // Mark children of siblings as nieces/nephews, and their descendants
    const children = getChildren(siblingId);

    for (const childId of children) {
      if (!this.relationshipCache.has(childId)) {
        const sex = this.data.individuals.get(childId)?.sex;
        let label;
        if (generation === 1) {
          label = sex === 'F' ? 'Niece' : sex === 'M' ? 'Nephew' : 'Niece/Nephew';
        } else {
          const greats = generation - 1;
          const prefix = greats === 1 ? 'Great' : `${greats}x Great`;
          label = sex === 'F' ? `${prefix}-Niece` : sex === 'M' ? `${prefix}-Nephew` : `${prefix}-Niece/Nephew`;
        }

        this.relationshipCache.set(childId, {
          type: 'niece_nephew',
          generation: generation,
          degree: 0,
          distance: 2 + generation,  // Sibling (2) + generations down
          label
        });

        // Recurse for great-nieces/nephews
        this.markNiecesNephews(childId, generation + 1, getChildren);
      }
    }
  }

  getAncestorLabel(generation, sex) {
    const isFemale = sex === 'F';
    const isMale = sex === 'M';

    if (generation === 1) return isFemale ? 'Mother' : isMale ? 'Father' : 'Parent';
    if (generation === 2) return isFemale ? 'Grandmother' : isMale ? 'Grandfather' : 'Grandparent';
    if (generation === 3) return isFemale ? 'Great-Grandmother' : isMale ? 'Great-Grandfather' : 'Great-Grandparent';

    const greats = generation - 2;
    const prefix = greats === 1 ? 'Great' : `${greats}x Great`;
    return isFemale ? `${prefix}-Grandmother` : isMale ? `${prefix}-Grandfather` : `${prefix}-Grandparent`;
  }

  getDescendantLabel(generation) {
    if (generation === 1) return 'Child';
    if (generation === 2) return 'Grandchild';
    if (generation === 3) return 'Great-Grandchild';
    const greats = generation - 2;
    return greats === 1 ? 'Great-Grandchild' : `${greats}x Great-Grandchild`;
  }

  getRelationshipColor(personId) {
    const rel = this.relationshipCache.get(personId);
    if (!rel) return this.relationshipColors.unrelated;
    return this.relationshipColors[rel.type] || this.relationshipColors.unrelated;
  }

  getRelationshipLabel(personId) {
    const rel = this.relationshipCache.get(personId);
    return rel ? rel.label : 'Unrelated';
  }

  getRelationshipType(personId) {
    const rel = this.relationshipCache.get(personId);
    return rel ? rel.type : 'unrelated';
  }

  // Find the relationship path between reference person and target
  findRelationshipPath(targetId) {
    if (!this.referencePerson || !this.data) return null;
    if (targetId === this.referencePerson) return [{ id: targetId, relation: 'self' }];

    // BFS to find shortest path
    const visited = new Set([this.referencePerson]);
    const queue = [[{ id: this.referencePerson, relation: 'self', name: this.data.individuals.get(this.referencePerson)?.name?.full }]];

    // Helper to get all connected people (parents, children, spouses, siblings)
    const getConnections = (personId) => {
      const person = this.data.individuals.get(personId);
      if (!person) return [];
      const connections = [];

      // Parents (through familyChild)
      if (person.familyChild) {
        for (const famId of person.familyChild) {
          const family = this.data.families.get(famId);
          if (family) {
            if (family.husband) connections.push({ id: family.husband, relation: 'parent', type: 'father' });
            if (family.wife) connections.push({ id: family.wife, relation: 'parent', type: 'mother' });
          }
        }
      }

      // Children and spouses (through familySpouse)
      if (person.familySpouse) {
        for (const famId of person.familySpouse) {
          const family = this.data.families.get(famId);
          if (family) {
            if (family.husband && family.husband !== personId) connections.push({ id: family.husband, relation: 'spouse', type: 'husband' });
            if (family.wife && family.wife !== personId) connections.push({ id: family.wife, relation: 'spouse', type: 'wife' });
            if (family.children) {
              for (const childId of family.children) {
                connections.push({ id: childId, relation: 'child', type: 'child' });
              }
            }
          }
        }
      }

      // Siblings (other children of same parents)
      if (person.familyChild) {
        for (const famId of person.familyChild) {
          const family = this.data.families.get(famId);
          if (family && family.children) {
            for (const sibId of family.children) {
              if (sibId !== personId) {
                connections.push({ id: sibId, relation: 'sibling', type: 'sibling' });
              }
            }
          }
        }
      }

      return connections;
    };

    while (queue.length > 0) {
      const path = queue.shift();
      const current = path[path.length - 1];

      const connections = getConnections(current.id);
      for (const conn of connections) {
        if (visited.has(conn.id)) continue;
        visited.add(conn.id);

        const person = this.data.individuals.get(conn.id);
        const newPath = [...path, {
          id: conn.id,
          relation: conn.relation,
          type: conn.type,
          name: person?.name?.full || 'Unknown'
        }];

        if (conn.id === targetId) {
          return newPath;
        }

        queue.push(newPath);
      }
    }

    return null; // No path found
  }

  showRelationshipPath(targetId) {
    const path = this.findRelationshipPath(targetId);
    const targetPerson = this.data.individuals.get(targetId);
    const refPerson = this.data.individuals.get(this.referencePerson);

    // Create modal content with tree-like visualization
    let content = '';
    if (path && path.length > 0) {
      content = `<div class="path-tree">`;

      // Group the path into generations/levels based on relationship direction
      let currentLevel = 0;
      const levels = [{ people: [], connector: null }];

      path.forEach((step, i) => {
        const person = this.data.individuals.get(step.id);
        const isRef = step.id === this.referencePerson;
        const isTarget = step.id === targetId;
        const color = this.getRelationshipColor(step.id);
        const nextStep = path[i + 1];

        // Determine if we're going up (parent), down (child), or sideways (spouse/sibling)
        let direction = 'same';
        if (nextStep) {
          if (nextStep.relation === 'parent') direction = 'up';
          else if (nextStep.relation === 'child') direction = 'down';
          else direction = 'same'; // spouse, sibling
        }

        const personData = {
          id: step.id,
          name: person?.name?.full || 'Unknown',
          givenName: person?.name?.given || 'Unknown',
          year: person?.birth?.date?.year || '',
          sex: person?.sex || 'U',
          color: color,
          isRef: isRef,
          isTarget: isTarget,
          relationToNext: nextStep ? (nextStep.type || nextStep.relation) : null
        };

        levels[currentLevel].people.push(personData);

        // Create new level for parent/child transitions
        if (nextStep && (nextStep.relation === 'parent' || nextStep.relation === 'child')) {
          levels[currentLevel].connector = nextStep.relation === 'parent' ? 'up' : 'down';
          currentLevel++;
          levels.push({ people: [], connector: null });
        }
      });

      // Render the tree structure
      levels.forEach((level, levelIdx) => {
        if (level.people.length === 0) return;

        content += `<div class="path-level">`;
        content += `<div class="path-level-people">`;

        level.people.forEach((p, pIdx) => {
          // Add horizontal connector between people on same level (spouses/siblings)
          if (pIdx > 0) {
            const prevPerson = level.people[pIdx - 1];
            const connLabel = prevPerson.relationToNext || '';
            const isSpouse = connLabel === 'spouse' || connLabel === 'husband' || connLabel === 'wife';
            content += `<div class="path-horiz-connector ${isSpouse ? 'spouse-connector' : ''}">
              <span class="path-horiz-line"></span>
              <span class="path-horiz-label">${connLabel}</span>
            </div>`;
          }

          content += `
            <div class="path-person ${p.isRef ? 'path-ref' : ''} ${p.isTarget ? 'path-target' : ''} ${p.sex === 'M' ? 'male' : 'female'}"
                 style="--node-color: ${p.color};">
              <div class="path-person-circle">
                ${p.isRef ? '★' : p.isTarget ? '◎' : ''}
              </div>
              <div class="path-person-info">
                <div class="path-person-name">${p.givenName}</div>
                ${p.year ? `<div class="path-person-year">${p.year}</div>` : ''}
              </div>
            </div>`;
        });

        content += `</div>`; // end path-level-people

        // Add vertical connector to next level
        if (level.connector && levelIdx < levels.length - 1) {
          const isUp = level.connector === 'up';
          content += `<div class="path-vert-connector ${isUp ? 'going-up' : 'going-down'}">
            <div class="path-vert-line"></div>
            <div class="path-vert-label">${isUp ? '↑ parent' : '↓ child'}</div>
          </div>`;
        }

        content += `</div>`; // end path-level
      });

      content += `</div>`; // end path-tree

      // Add legend
      content += `
        <div class="path-legend">
          <span class="path-legend-item"><span class="path-legend-star">★</span> You (Reference)</span>
          <span class="path-legend-item"><span class="path-legend-target">◎</span> Target Person</span>
        </div>`;

    } else {
      content = `<div class="path-no-connection">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/>
          <path d="M15 9l-6 6M9 9l6 6"/>
        </svg>
        <p>No direct family connection found between<br><strong>${refPerson?.name?.full}</strong> and <strong>${targetPerson?.name?.full}</strong></p>
      </div>`;
    }

    // Show in the modal
    const modal = document.getElementById('person-modal');
    document.getElementById('modal-name').innerHTML = `Connection Path`;
    document.getElementById('modal-dates').textContent = `${refPerson?.name?.full} → ${targetPerson?.name?.full}`;
    document.getElementById('modal-body').innerHTML = content;
    modal.classList.add('active');
  }

  // ==================== FILTERING ====================

  applyFilters() {
    if (!this.data) return [];

    const results = [];

    for (const [id, person] of this.data.individuals) {
      // Relationship type filter
      if (this.referencePerson && this.activeFilters.relationshipTypes.length > 0) {
        const relType = this.getRelationshipType(id);
        if (!this.activeFilters.relationshipTypes.includes(relType) && relType !== 'unrelated') {
          continue;
        }
        const rel = this.relationshipCache.get(id);
        // Check generation limit
        if (rel && rel.generation > this.activeFilters.maxGenerations) {
          continue;
        }
        // Check distance limit (kinship distance filter)
        if (this.activeFilters.maxDistance && rel && rel.distance > this.activeFilters.maxDistance) {
          continue;
        }
      }

      // Surname filter
      if (this.activeFilters.surname && person.name?.surname !== this.activeFilters.surname) {
        continue;
      }

      // Gender filter
      if (this.activeFilters.gender && person.sex !== this.activeFilters.gender) {
        continue;
      }

      // Birth year range filter
      const birthYear = person.birth?.date?.year;
      if (this.activeFilters.birthYearMin && (!birthYear || birthYear < this.activeFilters.birthYearMin)) {
        continue;
      }
      if (this.activeFilters.birthYearMax && (!birthYear || birthYear > this.activeFilters.birthYearMax)) {
        continue;
      }

      // Birth place filter
      if (this.activeFilters.birthPlace) {
        const place = (person.birth?.place || '').toLowerCase();
        if (!place.includes(this.activeFilters.birthPlace.toLowerCase())) {
          continue;
        }
      }

      results.push([id, person]);
    }

    this.filteredResults = results;
    return results;
  }

  getActiveFilterCount() {
    let count = 0;
    if (this.activeFilters.surname) count++;
    if (this.activeFilters.gender) count++;
    if (this.activeFilters.birthYearMin) count++;
    if (this.activeFilters.birthYearMax) count++;
    if (this.activeFilters.birthPlace) count++;
    if (this.activeFilters.maxDistance) count++;
    if (this.referencePerson && this.activeFilters.relationshipTypes.length < 9) count++;
    return count;
  }

  clearAllFilters() {
    // Clear reference person
    this.referencePerson = null;
    this.relationshipCache.clear();
    document.getElementById('reference-person-search').value = '';

    // Reset all filters
    this.activeFilters = {
      surname: '',
      gender: '',
      birthYearMin: null,
      birthYearMax: null,
      birthPlace: '',
      relationshipTypes: ['self', 'ancestor', 'descendant', 'sibling', 'cousin', 'aunt_uncle', 'niece_nephew', 'spouse', 'inlaw'],
      maxGenerations: 10,
      maxDistance: null,  // null = no limit, number = max kinship distance
    };
    this.updateFilterUI();

    // Refresh all views
    this.refreshAllViews();

    // Also update statistics since clearing filters affects all data
    this.updateStatistics();
  }

  updateFilterUI() {
    // Update UI elements to reflect current filter state
    const surnameSelect = document.getElementById('filter-surname');
    const genderSelect = document.getElementById('filter-gender');
    const birthMinInput = document.getElementById('filter-birth-min');
    const birthMaxInput = document.getElementById('filter-birth-max');
    const locationInput = document.getElementById('filter-location');

    if (surnameSelect) surnameSelect.value = this.activeFilters.surname;
    if (genderSelect) genderSelect.value = this.activeFilters.gender;
    if (birthMinInput) birthMinInput.value = this.activeFilters.birthYearMin || '';
    if (birthMaxInput) birthMaxInput.value = this.activeFilters.birthYearMax || '';
    if (locationInput) locationInput.value = this.activeFilters.birthPlace;

    // Update distance filter
    const distanceSelect = document.getElementById('filter-distance');
    if (distanceSelect) distanceSelect.value = this.activeFilters.maxDistance || '';

    // Update relationship toggles
    document.querySelectorAll('.rel-toggle').forEach(btn => {
      const rel = btn.dataset.rel;
      btn.classList.toggle('active', this.activeFilters.relationshipTypes.includes(rel));
    });

    // Update filter count badge
    const countBadge = document.getElementById('filter-count');
    if (countBadge) {
      const count = this.getActiveFilterCount();
      countBadge.textContent = count > 0 ? `${count} filter${count > 1 ? 's' : ''} active` : '';
      countBadge.style.display = count > 0 ? 'inline' : 'none';
    }
  }

  refreshAllViews() {
    // Refresh current tab view with new filters
    const activeTab = document.querySelector('.nav-tab.active')?.dataset.tab;
    if (activeTab === 'search') {
      this.performSearch();
    } else if (activeTab === 'tree' && this.referencePerson) {
      this.renderFamilyTree(this.referencePerson);
    } else if (activeTab === 'statistics') {
      this.updateStatistics();
    } else if (activeTab === 'map') {
      this.initMap();
    }
  }

  setupEventListeners() {
    // File upload
    document.getElementById('gedcom-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        this.loadGedcomFile(file);
      }
    });

    // Tab navigation
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.addEventListener('click', () => this.switchTab(tab.dataset.tab));
    });

    // Search
    document.getElementById('search-btn').addEventListener('click', () => this.performSearch());
    document.getElementById('search-name').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.performSearch();
    });

    // Modal
    document.getElementById('modal-close').addEventListener('click', () => this.closeModal());
    document.getElementById('person-modal').addEventListener('click', (e) => {
      if (e.target.id === 'person-modal') this.closeModal();
    });

    // Tree controls
    document.getElementById('zoom-in').addEventListener('click', () => this.zoomTree(1.2));
    document.getElementById('zoom-out').addEventListener('click', () => this.zoomTree(0.8));

    // Setup filter controls
    this.setupFilterControls();

    // Settings modal
    this.setupSettingsModal();
  }

  setupSettingsModal() {
    const overlay = document.getElementById('settings-modal-overlay');
    const openBtn = document.getElementById('open-settings-btn');
    const closeBtn = document.getElementById('settings-modal-close');
    const fileDrop = document.getElementById('settings-file-drop');

    if (!overlay || !openBtn) return;

    // Open modal
    openBtn.addEventListener('click', () => {
      overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
    });

    // Close modal
    const closeModal = () => {
      overlay.classList.remove('open');
      document.body.style.overflow = '';
    };

    closeBtn?.addEventListener('click', closeModal);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeModal();
    });

    // ESC to close
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && overlay.classList.contains('open')) {
        closeModal();
      }
    });

    // Drag and drop for GEDCOM
    if (fileDrop) {
      fileDrop.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileDrop.classList.add('dragover');
      });

      fileDrop.addEventListener('dragleave', () => {
        fileDrop.classList.remove('dragover');
      });

      fileDrop.addEventListener('drop', (e) => {
        e.preventDefault();
        fileDrop.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && (file.name.endsWith('.ged') || file.name.endsWith('.gedcom'))) {
          this.loadGedcomFile(file);
        }
      });
    }
  }

  loadGedcomFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      this.currentFileName = file.name;
      this.parseAndDisplay(event.target.result);
      // Close settings modal after loading
      const overlay = document.getElementById('settings-modal-overlay');
      if (overlay) {
        overlay.classList.remove('open');
        document.body.style.overflow = '';
      }
    };
    reader.readAsText(file);
  }

  updateSettingsStatus() {
    // Update GEDCOM status
    const gedcomBadge = document.getElementById('gedcom-status-badge');
    const fileLoaded = document.getElementById('settings-file-loaded');
    const fileDrop = document.getElementById('gedcom-drop-zone');
    const headerIndicator = document.getElementById('header-data-indicator');
    const headerCount = document.getElementById('header-data-count');

    if (this.data && this.data.individuals.size > 0) {
      if (gedcomBadge) {
        gedcomBadge.textContent = 'Loaded';
        gedcomBadge.classList.remove('disconnected');
        gedcomBadge.classList.add('connected');
      }
      if (fileLoaded) {
        fileLoaded.style.display = 'flex';
        document.getElementById('loaded-file-name').textContent = this.currentFileName || 'family_tree.ged';
        document.getElementById('loaded-file-stats').textContent =
          `${this.data.individuals.size.toLocaleString()} individuals · ${this.data.families.size.toLocaleString()} families`;
      }
      if (fileDrop) fileDrop.style.display = 'none';
      if (headerIndicator) {
        headerIndicator.classList.add('visible');
        headerCount.textContent = `${this.data.individuals.size.toLocaleString()} people`;
      }
    }

    // Update AI status
    const aiBadge = document.getElementById('ai-status-badge');
    const aiKey = document.getElementById('ai-api-key')?.value;
    if (aiBadge) {
      if (aiKey) {
        aiBadge.textContent = 'Configured';
        aiBadge.classList.remove('disconnected');
        aiBadge.classList.add('connected');
      } else {
        aiBadge.textContent = 'Not configured';
        aiBadge.classList.remove('connected');
        aiBadge.classList.add('disconnected');
      }
    }
  }

  setupFilterControls() {
    const self = this;

    // Reference person autocomplete
    const refInput = document.getElementById('reference-person-search');
    const refDropdown = document.getElementById('reference-autocomplete');

    if (refInput && refDropdown) {
      let highlightedIndex = -1;

      const performRefSearch = () => {
        const query = refInput.value.toLowerCase().trim();
        if (!self.data || !self.data.individuals || query.length < 1) {
          refDropdown.classList.remove('show');
          return;
        }

        const matches = [];
        self.data.individuals.forEach((person, id) => {
          const fullName = (person.name?.full || '').toLowerCase();
          if (fullName.includes(query)) {
            matches.push({ id, person });
          }
        });

        matches.sort((a, b) => (a.person.name?.full || '').localeCompare(b.person.name?.full || ''));
        const limited = matches.slice(0, 15);

        if (limited.length === 0) {
          refDropdown.classList.remove('show');
          return;
        }

        refDropdown.innerHTML = limited.map((m, i) => {
          let birthYear = m.person.birth?.date?.year || '';
          let deathYear = m.person.death?.date?.year || '';
          const dates = birthYear || deathYear ? `(${birthYear || '?'} - ${deathYear || '?'})` : '';
          return `<div class="ref-autocomplete-item${i === highlightedIndex ? ' highlighted' : ''}" data-id="${m.id}">
            <span class="ref-item-name">${m.person.name?.full || 'Unknown'}</span>
            <span class="ref-item-dates">${dates}</span>
          </div>`;
        }).join('');

        refDropdown.classList.add('show');
      };

      refInput.addEventListener('input', performRefSearch);
      refInput.addEventListener('focus', performRefSearch);

      refDropdown.addEventListener('click', (e) => {
        const item = e.target.closest('.ref-autocomplete-item');
        if (item) {
          const personId = item.dataset.id;
          const person = self.data.individuals.get(personId);
          if (person) {
            refInput.value = person.name?.full || '';
            self.setReferencePerson(personId);
          }
          refDropdown.classList.remove('show');
        }
      });

      document.addEventListener('click', (e) => {
        if (!e.target.closest('.reference-person-wrapper')) {
          refDropdown.classList.remove('show');
        }
      });
    }

    // Relationship toggles
    document.querySelectorAll('.rel-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const rel = btn.dataset.rel;
        btn.classList.toggle('active');

        if (btn.classList.contains('active')) {
          if (!self.activeFilters.relationshipTypes.includes(rel)) {
            self.activeFilters.relationshipTypes.push(rel);
          }
        } else {
          self.activeFilters.relationshipTypes = self.activeFilters.relationshipTypes.filter(r => r !== rel);
        }

        self.onFilterChange();
      });
    });

    // Advanced filters toggle
    const toggleAdvanced = document.getElementById('toggle-advanced');
    const advancedPanel = document.getElementById('advanced-filters');
    if (toggleAdvanced && advancedPanel) {
      toggleAdvanced.addEventListener('click', () => {
        toggleAdvanced.classList.toggle('expanded');
        advancedPanel.classList.toggle('show');
      });
    }

    // Clear all filters
    document.getElementById('clear-all-filters')?.addEventListener('click', () => {
      self.clearAllFilters();
    });

    // Attribute filters
    document.getElementById('filter-surname')?.addEventListener('change', (e) => {
      self.activeFilters.surname = e.target.value;
      self.onFilterChange();
    });

    document.getElementById('filter-gender')?.addEventListener('change', (e) => {
      self.activeFilters.gender = e.target.value;
      self.onFilterChange();
    });

    document.getElementById('filter-birth-min')?.addEventListener('change', (e) => {
      self.activeFilters.birthYearMin = e.target.value ? parseInt(e.target.value) : null;
      self.onFilterChange();
    });

    document.getElementById('filter-birth-max')?.addEventListener('change', (e) => {
      self.activeFilters.birthYearMax = e.target.value ? parseInt(e.target.value) : null;
      self.onFilterChange();
    });

    document.getElementById('filter-location')?.addEventListener('input', (e) => {
      self.activeFilters.birthPlace = e.target.value;
      // Debounce location filter
      clearTimeout(self.locationFilterTimeout);
      self.locationFilterTimeout = setTimeout(() => self.onFilterChange(), 300);
    });

    document.getElementById('filter-distance')?.addEventListener('change', (e) => {
      self.activeFilters.maxDistance = e.target.value ? parseInt(e.target.value) : null;
      self.onFilterChange();
    });

    // Select All / Deselect All relationship buttons
    document.getElementById('select-all-rel')?.addEventListener('click', () => {
      self.activeFilters.relationshipTypes = ['self', 'ancestor', 'descendant', 'sibling', 'cousin', 'aunt_uncle', 'niece_nephew', 'spouse', 'inlaw'];
      document.querySelectorAll('.rel-toggle').forEach(btn => btn.classList.add('active'));
      self.onFilterChange();
    });

    document.getElementById('deselect-all-rel')?.addEventListener('click', () => {
      self.activeFilters.relationshipTypes = [];
      document.querySelectorAll('.rel-toggle').forEach(btn => btn.classList.remove('active'));
      self.onFilterChange();
    });

    // Fullscreen buttons
    document.getElementById('fullscreen-tree')?.addEventListener('click', () => {
      const container = document.getElementById('tree-container');
      container.classList.toggle('fullscreen');
      if (container.classList.contains('fullscreen')) {
        document.body.style.overflow = 'hidden';
        // Recalculate tree size
        if (self.referencePerson) {
          setTimeout(() => self.renderFamilyTree(self.referencePerson), 100);
        }
      } else {
        document.body.style.overflow = '';
        if (self.referencePerson) {
          setTimeout(() => self.renderFamilyTree(self.referencePerson), 100);
        }
      }
    });

    document.getElementById('fullscreen-map')?.addEventListener('click', () => {
      const container = document.getElementById('map-container');
      container.classList.toggle('fullscreen');
      if (container.classList.contains('fullscreen')) {
        document.body.style.overflow = 'hidden';
        setTimeout(() => self.map?.invalidateSize(), 100);
      } else {
        document.body.style.overflow = '';
        setTimeout(() => self.map?.invalidateSize(), 100);
      }
    });

    // Download buttons
    document.getElementById('download-tree')?.addEventListener('click', () => self.downloadTreeAsImage());
    document.getElementById('download-map')?.addEventListener('click', () => self.downloadMapAsImage());

    // ESC to exit fullscreen
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        document.querySelectorAll('.fullscreen').forEach(el => {
          el.classList.remove('fullscreen');
        });
        document.body.style.overflow = '';
      }
    });
  }

  downloadTreeAsImage() {
    const svg = document.getElementById('tree-svg');
    if (!svg) return;

    // Get the main content group (with the tree)
    const contentGroup = svg.querySelector('g');
    if (!contentGroup) return;

    // Get actual content bounds
    const bounds = contentGroup.getBBox();
    const padding = 40;
    const contentWidth = bounds.width + padding * 2;
    const contentHeight = bounds.height + padding * 2;

    // Get the current transform applied to the group
    const transform = contentGroup.getAttribute('transform');

    // Higher resolution (3x)
    const scale = 3;
    const width = contentWidth * scale;
    const height = contentHeight * scale;

    // Clone the SVG
    const svgClone = svg.cloneNode(true);
    svgClone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    svgClone.setAttribute('width', width);
    svgClone.setAttribute('height', height);
    svgClone.setAttribute('viewBox', `${bounds.x - padding} ${bounds.y - padding} ${contentWidth} ${contentHeight}`);

    // Remove the zoom transform from the cloned group (viewBox handles positioning)
    const clonedGroup = svgClone.querySelector('g');
    if (clonedGroup) {
      clonedGroup.removeAttribute('transform');
    }

    // Add inline styles for proper rendering
    const styleEl = document.createElementNS('http://www.w3.org/2000/svg', 'style');
    styleEl.textContent = `
      .tree-node circle { filter: drop-shadow(0 2px 4px rgba(0,0,0,0.15)); }
      .tree-node text { font-family: system-ui, sans-serif; fill: #1f2937; }
      .tree-node-given { font-size: 10px; font-weight: 600; }
      .tree-node-surname { font-size: 9px; font-weight: 400; fill: #6b7280; text-transform: uppercase; letter-spacing: 0.03em; }
      .tree-link { fill: none; stroke: #9CA3AF; stroke-width: 2px; stroke-linecap: round; }
      .tree-link.ancestor-link { stroke: #60A5FA; }
      .tree-link.descendant-link { stroke: #34D399; }
      .tree-link.marriage-link { stroke: #EC4899; stroke-width: 2px; stroke-dasharray: 5,3; }
    `;
    svgClone.insertBefore(styleEl, svgClone.firstChild);

    // Add white background
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('x', bounds.x - padding);
    rect.setAttribute('y', bounds.y - padding);
    rect.setAttribute('width', contentWidth);
    rect.setAttribute('height', contentHeight);
    rect.setAttribute('fill', 'white');
    svgClone.insertBefore(rect, svgClone.firstChild);

    // Create canvas for PNG conversion
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');

    // Convert SVG to data URL
    const svgData = new XMLSerializer().serializeToString(svgClone);
    const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);

    // Load SVG into image and draw to canvas
    const img = new Image();
    img.onload = () => {
      ctx.fillStyle = 'white';
      ctx.fillRect(0, 0, width, height);
      ctx.drawImage(img, 0, 0, width, height);

      // Download as PNG
      canvas.toBlob((blob) => {
        const pngUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.download = `family-tree-${new Date().toISOString().split('T')[0]}.png`;
        link.href = pngUrl;
        link.click();
        URL.revokeObjectURL(pngUrl);
        URL.revokeObjectURL(url);
      }, 'image/png', 1.0);
    };
    img.src = url;
  }

  downloadMapAsImage() {
    const mapContainer = document.getElementById('genealogy-map');
    if (!mapContainer || !this.map) {
      alert('Map not available for download');
      return;
    }

    // Use leaflet-image or html2canvas if available
    // For now, just take a screenshot instruction
    alert('To save the map:\n1. Right-click on the map\n2. Select "Save image as..."\n\nOr use your browser\'s screenshot feature.');
  }

  setReferencePerson(personId) {
    this.referencePerson = personId;
    this.calculateRelationships(personId);

    // If on tree tab, render the tree
    const activeTab = document.querySelector('.nav-tab.active')?.dataset.tab;
    if (activeTab === 'tree') {
      this.renderFamilyTree(personId);
    }

    // Update displays
    this.onFilterChange();
  }

  onFilterChange() {
    // Update filter count display
    const count = this.getActiveFilterCount();
    const countEl = document.getElementById('filter-count');
    if (countEl) {
      countEl.textContent = count > 0 ? `${count} filter${count > 1 ? 's' : ''} active` : '';
      countEl.style.display = count > 0 ? 'inline' : 'none';
    }

    // Refresh current view
    this.refreshAllViews();
  }

  populateFilterOptions() {
    if (!this.data) return;

    // Populate surname dropdown
    const surnameSelect = document.getElementById('filter-surname');
    if (surnameSelect) {
      const surnames = new Set();
      this.data.individuals.forEach(person => {
        if (person.name?.surname) surnames.add(person.name.surname);
      });
      const sortedSurnames = Array.from(surnames).sort();
      surnameSelect.innerHTML = '<option value="">All Surnames</option>' +
        sortedSurnames.map(s => `<option value="${s}">${s}</option>`).join('');
    }
  }

  setupTreeAutocomplete() {
    const input = document.getElementById('tree-person-search');
    const dropdown = document.getElementById('tree-autocomplete-dropdown');
    if (!input || !dropdown) return;

    let highlightedIndex = -1;
    const self = this;

    const performSearch = () => {
      const query = input.value.toLowerCase().trim();
      if (!self.data || !self.data.individuals || query.length < 1) {
        dropdown.classList.remove('show');
        return;
      }

      // Search for matching persons
      const matches = [];
      self.data.individuals.forEach((person, id) => {
        const fullName = (person.name?.full || '').toLowerCase();
        const given = (person.name?.given || '').toLowerCase();
        const surname = (person.name?.surname || '').toLowerCase();

        // Score matches - exact starts get priority
        let score = 0;
        if (fullName.startsWith(query) || given.startsWith(query) || surname.startsWith(query)) {
          score = 2;
        } else if (fullName.includes(query) || given.includes(query) || surname.includes(query)) {
          score = 1;
        }

        if (score > 0) {
          matches.push({ id, person, score });
        }
      });

      // Sort by score (better matches first), then by name
      matches.sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        return (a.person.name?.full || '').localeCompare(b.person.name?.full || '');
      });

      // Limit to 25 results
      const limited = matches.slice(0, 25);

      if (limited.length === 0) {
        dropdown.innerHTML = '<div class="autocomplete-empty">No matches found</div>';
      } else {
        dropdown.innerHTML = limited.map((m, i) => {
          // Handle date which might be string or object
          let birthDate = m.person.birth?.date;
          if (typeof birthDate === 'object') birthDate = birthDate?.value || birthDate?.original || '';
          const birthYear = (typeof birthDate === 'string' && birthDate.match(/\d{4}/)?.[0]) || '';

          let deathDate = m.person.death?.date;
          if (typeof deathDate === 'object') deathDate = deathDate?.value || deathDate?.original || '';
          const deathYear = (typeof deathDate === 'string' && deathDate.match(/\d{4}/)?.[0]) || '';

          const dates = birthYear ? `${birthYear}${deathYear ? ' – ' + deathYear : ''}` : '';

          return `
            <div class="autocomplete-item" data-id="${m.id}" data-index="${i}">
              <div class="autocomplete-item-name">${m.person.name?.full || 'Unknown'}</div>
              ${dates ? `<div class="autocomplete-item-dates">${dates}</div>` : ''}
            </div>
          `;
        }).join('');
      }

      dropdown.classList.add('show');
      highlightedIndex = -1;
    };

    // Search on input
    input.addEventListener('input', () => performSearch());

    // Also search on focus if there's already text
    input.addEventListener('focus', () => {
      if (input.value.trim().length >= 1 && self.data) {
        performSearch();
      }
    });

    // Handle keyboard navigation
    input.addEventListener('keydown', (e) => {
      const items = dropdown.querySelectorAll('.autocomplete-item');

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        highlightedIndex = Math.min(highlightedIndex + 1, items.length - 1);
        updateHighlight(items);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        highlightedIndex = Math.max(highlightedIndex - 1, 0);
        updateHighlight(items);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (highlightedIndex >= 0 && items[highlightedIndex]) {
          selectPerson(items[highlightedIndex].dataset.id);
        }
      } else if (e.key === 'Escape') {
        dropdown.classList.remove('show');
      }
    });

    const updateHighlight = (items) => {
      items.forEach((item, i) => {
        item.classList.toggle('highlighted', i === highlightedIndex);
      });
      if (highlightedIndex >= 0 && items[highlightedIndex]) {
        items[highlightedIndex].scrollIntoView({ block: 'nearest' });
      }
    };

    const selectPerson = (id) => {
      const person = self.data.individuals.get(id);
      if (person) {
        input.value = person.name?.full || 'Unknown';
        self.selectedTreePerson = id;
        dropdown.classList.remove('show');
        self.renderFamilyTree(id);
      }
    };

    // Handle click on dropdown items
    dropdown.addEventListener('click', (e) => {
      const item = e.target.closest('.autocomplete-item');
      if (item) {
        selectPerson(item.dataset.id);
      }
    });

    // Close dropdown on outside click
    document.addEventListener('click', (e) => {
      if (!e.target.closest('#tree-autocomplete')) {
        dropdown.classList.remove('show');
      }
    });
  }

  setupThemeToggle() {
    document.querySelectorAll('.theme-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.theme-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.documentElement.dataset.theme = btn.dataset.theme;
        if (this.map) this.updateMapTiles();
      });
    });
  }

  parseAndDisplay(gedcomText) {
    try {
      this.data = this.parser.parse(gedcomText);

      // Build AI indexes
      const summary = this.indexer.buildIndexes(this.data.individuals, this.data.families);
      this.updateAIDataStatus(summary);

      this.populateFilters();
      this.populateFilterOptions();
      this.displayAllIndividuals();
      this.updateStatistics();
      this.renderTimelineChart();
      this.renderSurnameChart();

      // Initialize map on the map tab
      if (document.getElementById('map-tab').classList.contains('active')) {
        this.initMap();
      }

      document.getElementById('search-stats').textContent =
        `${this.data.individuals.size} individuals · ${this.data.families.size} families`;

      // Update settings modal and header status
      this.updateSettingsStatus();

      // Clear any previous reference person when new data is loaded
      this.referencePerson = null;
      this.relationshipCache.clear();
      document.getElementById('reference-person-search').value = '';
    } catch (e) {
      console.error('Error parsing GEDCOM:', e);
      this.showEmptyState();
    }
  }

  // ============================================================================
  // AI QUERY INTERFACE
  // ============================================================================

  setupAIInterface() {
    // Load saved settings
    const settings = this.aiEngine.settings;
    document.getElementById('ai-provider').value = settings.provider;
    document.getElementById('ai-api-key').value = settings.apiKey;
    document.getElementById('ai-model').value = settings.model;

    // Update header status based on saved settings
    this.updateAISettingsStatus();

    // Save settings button
    document.getElementById('save-api-settings').addEventListener('click', () => {
      this.aiEngine.saveSettings({
        provider: document.getElementById('ai-provider').value,
        apiKey: document.getElementById('ai-api-key').value,
        model: document.getElementById('ai-model').value
      });
      this.updateAISettingsStatus();
      this.updateSettingsStatus();
      this.showNotification('Settings saved');
    });

    // Send button
    document.getElementById('ai-send').addEventListener('click', () => this.sendAIQuery());

    // Enter key to send
    document.getElementById('ai-input').addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendAIQuery();
      }
    });

    // Auto-resize textarea
    document.getElementById('ai-input').addEventListener('input', (e) => {
      e.target.style.height = 'auto';
      e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
    });

    // Example buttons
    document.querySelectorAll('.ai-example-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.getElementById('ai-input').value = btn.textContent;
        this.sendAIQuery();
      });
    });
  }

  updateAISettingsStatus() {
    const settings = this.aiEngine.settings;
    const hasKey = settings.apiKey && settings.apiKey.length > 0;

    // Update settings modal AI status badge
    const aiBadge = document.getElementById('ai-status-badge');
    if (aiBadge) {
      if (hasKey) {
        aiBadge.textContent = 'Configured';
        aiBadge.classList.remove('disconnected');
        aiBadge.classList.add('connected');
      } else {
        aiBadge.textContent = 'Not configured';
        aiBadge.classList.remove('connected');
        aiBadge.classList.add('disconnected');
      }
    }
  }

  updateAIDataStatus(summary) {
    const statusEl = document.getElementById('ai-data-status');
    if (!statusEl) return;

    if (summary) {
      statusEl.classList.add('indexed');
      statusEl.innerHTML = `
        <span class="status-dot"></span>
        <span>${summary.totalIndividuals} individuals indexed · ${summary.surnames.length} surnames · ${summary.countries.length} locations</span>
      `;
    } else {
      statusEl.classList.remove('indexed');
      statusEl.innerHTML = `
        <span class="status-dot"></span>
        <span>No data indexed</span>
      `;
    }
  }

  async sendAIQuery() {
    const input = document.getElementById('ai-input');
    const query = input.value.trim();
    if (!query) return;

    if (!this.data) {
      this.addAIMessage('assistant', 'Please load a GEDCOM file first before asking questions.');
      return;
    }

    // Clear input
    input.value = '';
    input.style.height = 'auto';

    // Remove welcome message if present
    const welcome = document.querySelector('.ai-welcome');
    if (welcome) welcome.remove();

    // Add user message
    this.addAIMessage('user', query);

    // Show loading
    const loadingId = this.addAILoading();

    try {
      // Update settings from UI
      this.aiEngine.saveSettings({
        provider: document.getElementById('ai-provider').value,
        apiKey: document.getElementById('ai-api-key').value,
        model: document.getElementById('ai-model').value
      });

      // Pass relationship data for better query context
      const self = this;
      const relationshipContext = {
        referencePerson: this.referencePerson,
        referencePersonName: this.referencePerson ? this.data.individuals.get(this.referencePerson)?.name?.full : null,
        relationshipCache: this.relationshipCache,
        getRelationshipLabel: (id) => this.getRelationshipLabel(id),
        getRelationshipType: (id) => this.getRelationshipType(id),
        // Allow recalculating relationships for a different subject person
        recalculateForPerson: (personId) => {
          // Temporarily set as reference and recalculate
          const originalRef = self.referencePerson;
          self.referencePerson = personId;
          self.calculateRelationships(personId);
          const cache = new Map(self.relationshipCache);

          // Restore original reference
          self.referencePerson = originalRef;
          if (originalRef) {
            self.calculateRelationships(originalRef);
          } else {
            self.relationshipCache.clear();
          }
          return cache;
        }
      };
      const response = await this.aiEngine.query(query, this.data.individuals, this.data.families, relationshipContext);

      // Remove loading
      document.getElementById(loadingId)?.remove();

      // Add response
      this.addAIMessage('assistant', response);
    } catch (error) {
      console.error('AI Query error:', error);
      document.getElementById(loadingId)?.remove();
      this.addAIError(error.message);
    }
  }

  addAIMessage(role, content) {
    const messagesContainer = document.getElementById('ai-messages');

    const messageDiv = document.createElement('div');
    messageDiv.className = `ai-message ${role}`;

    const avatar = document.createElement('div');
    avatar.className = 'ai-message-avatar';
    avatar.innerHTML = role === 'user'
      ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
      : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>';

    const contentDiv = document.createElement('div');
    contentDiv.className = 'ai-message-content';
    contentDiv.innerHTML = this.formatAIResponse(content);

    messageDiv.appendChild(avatar);
    messageDiv.appendChild(contentDiv);
    messagesContainer.appendChild(messageDiv);

    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  formatAIResponse(text) {
    // Convert markdown-like formatting to HTML
    return text
      // Bold
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      // Italic
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      // Code
      .replace(/`(.*?)`/g, '<code>$1</code>')
      // Lists
      .replace(/^- (.*)$/gm, '<li>$1</li>')
      .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
      // Numbered lists
      .replace(/^\d+\. (.*)$/gm, '<li>$1</li>')
      // Paragraphs
      .split('\n\n').map(p => p.trim() ? `<p>${p}</p>` : '').join('')
      // Line breaks
      .replace(/\n/g, '<br>');
  }

  addAILoading() {
    const messagesContainer = document.getElementById('ai-messages');
    const loadingId = 'ai-loading-' + Date.now();

    const loadingDiv = document.createElement('div');
    loadingDiv.id = loadingId;
    loadingDiv.className = 'ai-message assistant';
    loadingDiv.innerHTML = `
      <div class="ai-message-avatar">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
        </svg>
      </div>
      <div class="ai-message-content">
        <div class="ai-loading">
          <div class="ai-loading-dots">
            <span></span><span></span><span></span>
          </div>
          <span>Analyzing genealogy data...</span>
        </div>
      </div>
    `;

    messagesContainer.appendChild(loadingDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    return loadingId;
  }

  addAIError(message) {
    const messagesContainer = document.getElementById('ai-messages');
    const errorDiv = document.createElement('div');
    errorDiv.className = 'ai-error';
    errorDiv.textContent = message;
    messagesContainer.appendChild(errorDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  showNotification(message) {
    // Simple notification - could be enhanced
    const btn = document.getElementById('save-api-settings');
    const originalText = btn.innerHTML;
    btn.innerHTML = '✓ Saved';
    setTimeout(() => { btn.innerHTML = originalText; }, 2000);
  }

  // ============================================================================
  // FAMILYSEARCH INTERFACE
  // ============================================================================

  setupFamilySearchInterface() {
    // Load saved client ID
    const clientIdInput = document.getElementById('fs-client-id');
    if (clientIdInput && this.fsClient.clientId) {
      clientIdInput.value = this.fsClient.clientId;
    }

    // Update UI based on auth state
    this.updateFamilySearchUI();

    // Auth button
    const authBtn = document.getElementById('fs-auth-btn');
    if (authBtn) {
      authBtn.addEventListener('click', async () => {
        const clientId = document.getElementById('fs-client-id')?.value.trim();
        if (!clientId) {
          alert('Please enter your FamilySearch App Key (Client ID)');
          return;
        }

        this.fsClient.setClientId(clientId);

        try {
          await this.fsClient.initiateAuth();
        } catch (e) {
          alert('Authentication error: ' + e.message);
        }
      });
    }

    // Start sync button
    const syncBtn = document.getElementById('fs-start-sync');
    if (syncBtn) {
      syncBtn.addEventListener('click', () => this.startFamilySearchSync());
    }
  }

  async handleFamilySearchCallback() {
    try {
      const wasCallback = await this.fsClient.handleAuthCallback();
      if (wasCallback) {
        this.updateFamilySearchUI();
        // Open settings modal to show connected state
        const overlay = document.getElementById('settings-modal-overlay');
        if (overlay) {
          overlay.classList.add('open');
          document.body.style.overflow = 'hidden';
        }
      }
    } catch (e) {
      console.error('FamilySearch callback error:', e);
    }
  }

  async updateFamilySearchUI() {
    const statusBadge = document.getElementById('fs-status-badge');
    const connectedOptions = document.getElementById('fs-connected-options');
    const authBtn = document.getElementById('fs-auth-btn');

    if (this.fsClient.isAuthenticated()) {
      if (statusBadge) {
        statusBadge.textContent = 'Connected';
        statusBadge.classList.remove('disconnected');
        statusBadge.classList.add('connected');
      }
      if (connectedOptions) connectedOptions.style.display = 'block';
      if (authBtn) authBtn.textContent = 'Reconnect';

      // Pre-fill person ID from user profile
      try {
        const user = await this.fsClient.getCurrentUser();
        if (user?.personId) {
          const personIdsInput = document.getElementById('fs-person-ids');
          if (personIdsInput && !personIdsInput.value) {
            personIdsInput.value = user.personId;
          }
        }
      } catch (e) {
        console.warn('Failed to fetch user info:', e);
      }
    } else {
      if (statusBadge) {
        statusBadge.textContent = 'Not connected';
        statusBadge.classList.remove('connected');
        statusBadge.classList.add('disconnected');
      }
      if (connectedOptions) connectedOptions.style.display = 'none';
      if (authBtn) authBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/>
          <polyline points="10 17 15 12 10 7"/>
          <line x1="15" y1="12" x2="3" y2="12"/>
        </svg>
        Connect`;
    }
  }

  async startFamilySearchSync() {
    const personIdsInput = document.getElementById('fs-person-ids')?.value.trim() || '';
    const ancestorGen = parseInt(document.getElementById('fs-ancestor-gen')?.value || '8');
    const descendantGen = parseInt(document.getElementById('fs-descendant-gen')?.value || '8');

    // Parse person IDs
    let personIds = personIdsInput
      .split(/[,\s]+/)
      .map(id => id.trim())
      .filter(id => id.length > 0);

    if (personIds.length === 0) {
      try {
        const user = await this.fsClient.getCurrentUser();
        if (user?.personId) {
          personIds = [user.personId];
        } else {
          alert('Please enter at least one Person ID or ensure your profile has a linked person.');
          return;
        }
      } catch (e) {
        alert('Failed to get your Person ID. Please enter it manually.');
        return;
      }
    }

    // Close settings modal
    const overlay = document.getElementById('settings-modal-overlay');
    if (overlay) {
      overlay.classList.remove('open');
      document.body.style.overflow = '';
    }

    // Show sync in progress
    alert(`Starting FamilySearch sync for ${personIds.length} person(s)...\nThis may take a few minutes.`);

    try {
      this.fsSyncResult = await this.fsClient.crawlFullTree(personIds, {
        ancestorGenerations: ancestorGen,
        descendantGenerations: descendantGen,
        onProgress: (progress) => {
          console.log('Sync progress:', progress.status, progress.processed, '/', progress.total);
        }
      });

      // Save sync info
      this.fsClient.saveLastSyncInfo(this.fsSyncResult.stats);

      // Auto-load the results
      this.loadFamilySearchResults();

      alert(`Sync complete! ${this.fsSyncResult.stats.totalPersons} persons found and loaded.`);

    } catch (e) {
      console.error('FamilySearch sync error:', e);
      alert('Sync failed: ' + e.message);
    }
  }

  loadFamilySearchResults() {
    if (!this.fsSyncResult) {
      alert('No sync results to load. Please run a sync first.');
      return;
    }

    // Convert FamilySearch data to our internal format
    const individuals = new Map();
    const families = new Map();

    for (const [id, person] of this.fsSyncResult.persons) {
      individuals.set(id, {
        id: id,
        name: person.name,
        gender: person.gender,
        birth: person.birth,
        death: person.death,
        occupation: person.occupation,
        famc: null,
        fams: []
      });
    }

    for (const [id, family] of this.fsSyncResult.families) {
      families.set(id, {
        id: id,
        husband: family.husband,
        wife: family.wife,
        children: family.children
      });

      // Link individuals to families
      if (family.husband && individuals.has(family.husband)) {
        individuals.get(family.husband).fams.push(id);
      }
      if (family.wife && individuals.has(family.wife)) {
        individuals.get(family.wife).fams.push(id);
      }
      for (const childId of family.children) {
        if (individuals.has(childId)) {
          individuals.get(childId).famc = id;
        }
      }
    }

    this.data = { individuals, families };

    // Build indexes
    const summary = this.indexer.buildIndexes(individuals, families);
    this.updateAIDataStatus(summary);

    // Update UI
    this.populateFilters();
    this.renderResults(individuals);
    this.renderStats();

    // Switch to search tab
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelector('[data-tab="search"]').classList.add('active');
    document.getElementById('search-tab').classList.add('active');

    this.showNotification('FamilySearch data loaded!');
  }

  downloadFamilySearchGedcom() {
    if (!this.fsClient.persons.size) {
      alert('No data to download. Please run a sync first.');
      return;
    }

    const gedcom = this.fsClient.toGedcom();
    const blob = new Blob([gedcom], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `familysearch_export_${new Date().toISOString().split('T')[0]}.ged`;
    a.click();

    URL.revokeObjectURL(url);
  }

  populateFilters() {
    const surnames = new Set();
    const years = new Set();

    this.data.individuals.forEach(person => {
      if (person.name?.surname) surnames.add(person.name.surname);
      if (person.birth?.date?.year) years.add(person.birth.date.year);
    });

    const surnameSelect = document.getElementById('search-surname');
    surnameSelect.innerHTML = '<option value="">All Surnames</option>' +
      Array.from(surnames).sort().map(s => `<option value="${s}">${s}</option>`).join('');

    const yearSelect = document.getElementById('search-year');
    yearSelect.innerHTML = '<option value="">All Years</option>' +
      Array.from(years).sort((a, b) => a - b).map(y => `<option value="${y}">${y}</option>`).join('');
  }

  displayAllIndividuals() {
    // Use performSearch which applies filters
    this.performSearch();
  }

  performSearch() {
    const nameQuery = document.getElementById('search-name')?.value.toLowerCase() || '';

    // Start with filtered results based on global filters
    let results = this.applyFilters();

    // Apply local search filters (name search from search box)
    if (nameQuery) {
      results = results.filter(([id, p]) => {
        return (p.name?.full?.toLowerCase() || '').includes(nameQuery);
      });
    }

    // Sort results: reference person first, then by relationship, then by name
    if (this.referencePerson) {
      results.sort((a, b) => {
        const relA = this.relationshipCache.get(a[0]);
        const relB = this.relationshipCache.get(b[0]);

        // Self always first
        if (a[0] === this.referencePerson) return -1;
        if (b[0] === this.referencePerson) return 1;

        // Then by relationship type priority
        const typePriority = {
          self: 0, spouse: 1, ancestor: 2, descendant: 3,
          sibling: 4, niece_nephew: 5, aunt_uncle: 6, cousin: 7, inlaw: 8, unrelated: 9
        };
        const priorityA = relA ? (typePriority[relA.type] ?? 9) : 9;
        const priorityB = relB ? (typePriority[relB.type] ?? 9) : 9;
        if (priorityA !== priorityB) return priorityA - priorityB;

        // Then by generation (closer first)
        const genA = relA?.generation ?? 100;
        const genB = relB?.generation ?? 100;
        if (genA !== genB) return genA - genB;

        // Finally by name
        return (a[1].name?.full || '').localeCompare(b[1].name?.full || '');
      });
    }

    // Limit results for performance
    const totalCount = results.length;
    const limitedResults = results.slice(0, 200);

    this.displayResults(limitedResults, totalCount);
  }

  displayResults(results, totalCount = null) {
    const grid = document.getElementById('results-grid');
    const statsEl = document.getElementById('search-stats');

    // Update stats display
    if (statsEl) {
      const total = this.data?.individuals?.size || 0;
      const showing = results.length;
      const filtered = totalCount ?? showing;

      if (this.referencePerson) {
        const relatedCount = this.relationshipCache.size;
        statsEl.innerHTML = `<strong>${showing}</strong> of <strong>${filtered}</strong> shown · ${relatedCount} related to reference`;
      } else {
        statsEl.innerHTML = `<strong>${showing}</strong> of <strong>${total}</strong> individuals`;
      }
    }

    if (results.length === 0) {
      grid.innerHTML = `
        <div class="empty-state">
          <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="11" cy="11" r="8"/>
            <path d="M21 21l-4.35-4.35"/>
          </svg>
          <h3>No Results Found</h3>
          <p>Try adjusting your search criteria or filters</p>
        </div>
      `;
      return;
    }

    grid.innerHTML = results.map(([id, p]) => this.createPersonCard(id, p)).join('');

    // Use event delegation on the grid for both card clicks and button clicks
    grid.onclick = (e) => {
      // Check if View Path button was clicked
      const viewBtn = e.target.closest('.view-relation-btn');
      if (viewBtn) {
        e.stopPropagation();
        e.preventDefault();
        this.showRelationshipPath(viewBtn.dataset.id);
        return;
      }

      // Check if a person card was clicked
      const card = e.target.closest('.person-card');
      if (card) {
        this.showPersonModal(card.dataset.id);
      }
    };
  }

  createPersonCard(id, person) {
    const name = person.name || { given: 'Unknown', surname: '', full: 'Unknown' };
    const sex = person.sex || 'U';
    const sexClass = sex === 'M' ? 'male' : sex === 'F' ? 'female' : '';

    let dates = '';
    if (person.birth?.date?.year) {
      const birth = person.birth.date.year;
      const death = person.death?.date?.year || (person.death?.occurred ? '?' : '');
      dates = death ? `${birth} – ${death}` : `b. ${birth}`;
    }

    // Get relationship info
    const rel = this.relationshipCache.get(id);
    const relType = rel?.type || 'unrelated';
    const relLabel = this.getRelationshipLabel(id);
    const relColor = this.getRelationshipColor(id);
    const distance = rel?.distance ?? null;

    // Determine if this is a distant relative (distance > 6 = beyond 2nd cousins)
    const isDistant = distance !== null && distance > 6;

    // Build relationship badge and view relation button
    let relBadge = '';
    let viewRelationBtn = '';
    if (this.referencePerson) {
      let badgeClass = relType === 'unrelated' ? 'relationship-badge unrelated' : 'relationship-badge';
      if (isDistant) badgeClass += ' distant';

      // Show distance indicator for distant relatives
      const distanceIndicator = isDistant ? `<span class="distance-indicator" title="Kinship distance: ${distance}">⟷${distance}</span>` : '';

      relBadge = `<span class="${badgeClass}" style="--rel-color: ${relColor}; background: ${relColor};">${relLabel}${distanceIndicator}</span>`;
      if (id !== this.referencePerson) {
        viewRelationBtn = `<button class="view-relation-btn" data-id="${id}" title="View how you're connected">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          View Path
        </button>`;
      }
    }

    // Clean up location - format nicely with Italian province abbreviations
    const cleanLocation = (place) => {
      if (!place) return '';

      // Italian province abbreviations
      const italianProvinces = {
        'Agrigento': 'AG', 'Alessandria': 'AL', 'Ancona': 'AN', 'Aosta': 'AO', 'Arezzo': 'AR',
        'Ascoli Piceno': 'AP', 'Asti': 'AT', 'Avellino': 'AV', 'Bari': 'BA', 'Barletta-Andria-Trani': 'BT',
        'Belluno': 'BL', 'Benevento': 'BN', 'Bergamo': 'BG', 'Biella': 'BI', 'Bologna': 'BO',
        'Bolzano': 'BZ', 'Brescia': 'BS', 'Brindisi': 'BR', 'Cagliari': 'CA', 'Caltanissetta': 'CL',
        'Campobasso': 'CB', 'Caserta': 'CE', 'Catania': 'CT', 'Catanzaro': 'CZ', 'Chieti': 'CH',
        'Como': 'CO', 'Cosenza': 'CS', 'Cremona': 'CR', 'Crotone': 'KR', 'Cuneo': 'CN',
        'Enna': 'EN', 'Fermo': 'FM', 'Ferrara': 'FE', 'Firenze': 'FI', 'Foggia': 'FG',
        'Forlì-Cesena': 'FC', 'Frosinone': 'FR', 'Genova': 'GE', 'Gorizia': 'GO', 'Grosseto': 'GR',
        'Imperia': 'IM', 'Isernia': 'IS', 'La Spezia': 'SP', 'Latina': 'LT', 'Lecce': 'LE',
        'Lecco': 'LC', 'Livorno': 'LI', 'Lodi': 'LO', 'Lucca': 'LU', 'Macerata': 'MC',
        'Mantova': 'MN', 'Massa-Carrara': 'MS', 'Matera': 'MT', 'Messina': 'ME', 'Milano': 'MI',
        'Modena': 'MO', 'Monza e Brianza': 'MB', 'Napoli': 'NA', 'Novara': 'NO', 'Nuoro': 'NU',
        'Oristano': 'OR', 'Padova': 'PD', 'Palermo': 'PA', 'Parma': 'PR', 'Pavia': 'PV',
        'Perugia': 'PG', 'Pesaro e Urbino': 'PU', 'Pescara': 'PE', 'Piacenza': 'PC', 'Pisa': 'PI',
        'Pistoia': 'PT', 'Pordenone': 'PN', 'Potenza': 'PZ', 'Prato': 'PO', 'Ragusa': 'RG',
        'Ravenna': 'RA', 'Reggio Calabria': 'RC', 'Reggio Emilia': 'RE', 'Rieti': 'RI', 'Rimini': 'RN',
        'Roma': 'RM', 'Rovigo': 'RO', 'Salerno': 'SA', 'Sassari': 'SS', 'Savona': 'SV',
        'Siena': 'SI', 'Siracusa': 'SR', 'Sondrio': 'SO', 'Sud Sardegna': 'SU', 'Taranto': 'TA',
        'Teramo': 'TE', 'Terni': 'TR', 'Torino': 'TO', 'Trapani': 'TP', 'Trento': 'TN',
        'Treviso': 'TV', 'Trieste': 'TS', 'Udine': 'UD', 'Varese': 'VA', 'Venezia': 'VE',
        'Verbano-Cusio-Ossola': 'VB', 'Vercelli': 'VC', 'Verona': 'VR', 'Vibo Valentia': 'VV',
        'Vicenza': 'VI', 'Viterbo': 'VT'
      };

      // Clean up the string
      let cleaned = place
        .replace(/,+/g, ',')           // Multiple commas to single
        .replace(/,\s*,/g, ',')        // Remove empty comma sequences
        .replace(/^,+|,+$/g, '')       // Trim commas from ends
        .replace(/,(?!\s)/g, ', ')     // Add space after commas if missing
        .replace(/\s+/g, ' ')          // Multiple spaces to single
        .trim();

      // Check if this is an Italian location and format with province abbreviation
      const parts = cleaned.split(',').map(p => p.trim()).filter(p => p);
      if (parts.length >= 2) {
        const isItaly = parts.some(p => p.toLowerCase() === 'italy' || p.toLowerCase() === 'italia');
        if (isItaly && parts.length >= 3) {
          // Find and replace province name with abbreviation
          const newParts = [];
          let foundProvince = false;
          for (let i = 0; i < parts.length; i++) {
            const part = parts[i];
            if (!foundProvince && italianProvinces[part]) {
              // Replace province name with abbreviation in parentheses
              if (newParts.length > 0) {
                newParts[newParts.length - 1] += ` (${italianProvinces[part]})`;
              }
              foundProvince = true;
              continue;
            }
            // Skip region names but keep Italy
            if (foundProvince) {
              const pLower = part.toLowerCase();
              // Keep Italy at the end
              if (pLower === 'italy' || pLower === 'italia') {
                newParts.push('Italy');
                continue;
              }
              // Skip region names
              if (pLower === 'sicily' || pLower === 'sicilia' ||
                  pLower.includes('friuli') || pLower.includes('veneto') ||
                  pLower.includes('lombardia') || pLower.includes('piemonte') ||
                  pLower.includes('toscana') || pLower.includes('lazio') ||
                  pLower.includes('campania') || pLower.includes('puglia') ||
                  pLower.includes('calabria') || pLower.includes('sardegna') ||
                  pLower.includes('emilia')) {
                continue;
              }
            }
            if (part) newParts.push(part);
          }
          if (foundProvince && newParts.length > 0) {
            return newParts.join(', ');
          }
        }
      }

      return cleaned;
    };
    const birthPlace = cleanLocation(person.birth?.place);

    const distantClass = isDistant ? ' distant-relative' : '';
    return `
      <div class="person-card${distantClass}" data-id="${id}" data-relationship="${relType}" data-distance="${distance ?? ''}" style="--rel-color: ${relColor};">
        <div class="person-card-header">
          <div class="person-name">
            ${name.given} <span class="person-surname">${name.surname}</span>
            ${relBadge}
          </div>
          ${dates ? `<div class="person-dates">${dates}</div>` : ''}
        </div>
        <div class="person-card-body">
          <div class="person-detail">
            <span class="person-badge ${sexClass}">${sex === 'M' ? '♂ Male' : sex === 'F' ? '♀ Female' : '? Unknown'}</span>
          </div>
          ${birthPlace ? `
            <div class="person-detail">
              <svg class="person-detail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
                <circle cx="12" cy="10" r="3"/>
              </svg>
              <span class="person-detail-text">${birthPlace}</span>
            </div>
          ` : ''}
          ${person.occupation ? `
            <div class="person-detail">
              <svg class="person-detail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="2" y="7" width="20" height="14" rx="2" ry="2"/>
                <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>
              </svg>
              <span class="person-detail-text">${person.occupation}</span>
            </div>
          ` : ''}
        </div>
        ${viewRelationBtn ? `<div class="person-card-actions">${viewRelationBtn}</div>` : ''}
      </div>
    `;
  }

  showPersonModal(id) {
    const person = this.data.individuals.get(id);
    if (!person) return;

    const name = person.name || { given: 'Unknown', surname: '', full: 'Unknown' };

    document.getElementById('modal-name').innerHTML =
      `${name.given} <span class="surname">${name.surname}</span>`;

    let dates = '';
    if (person.birth?.date?.original || person.death?.date?.original) {
      const birth = person.birth?.date?.original || '?';
      const death = person.death?.date?.original || '';
      dates = death ? `${birth} – ${death}` : `Born ${birth}`;
    }
    document.getElementById('modal-dates').textContent = dates;

    let bodyHtml = '<div class="modal-section">';
    bodyHtml += '<h4 class="modal-section-title">Personal Details</h4>';
    bodyHtml += `
      <div class="modal-detail">
        <svg class="modal-detail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
          <circle cx="12" cy="7" r="4"/>
        </svg>
        <span>${person.sex === 'M' ? 'Male' : person.sex === 'F' ? 'Female' : 'Unknown'}</span>
      </div>
    `;

    if (person.birth?.place) {
      bodyHtml += `
        <div class="modal-detail">
          <svg class="modal-detail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
            <circle cx="12" cy="10" r="3"/>
          </svg>
          <span>Born in ${person.birth.place}</span>
        </div>
      `;
    }

    if (person.death?.place) {
      bodyHtml += `
        <div class="modal-detail">
          <svg class="modal-detail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
            <circle cx="12" cy="10" r="3"/>
          </svg>
          <span>Died in ${person.death.place}</span>
        </div>
      `;
    }

    if (person.occupation) {
      bodyHtml += `
        <div class="modal-detail">
          <svg class="modal-detail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="2" y="7" width="20" height="14" rx="2" ry="2"/>
            <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>
          </svg>
          <span>${person.occupation}</span>
        </div>
      `;
    }
    bodyHtml += '</div>';

    // Family section
    const familyMembers = this.getFamilyMembers(id);

    bodyHtml += '<div class="modal-section">';
    bodyHtml += '<h4 class="modal-section-title">Family</h4>';

    if (familyMembers.length > 0) {
      bodyHtml += '<div class="modal-family-list">';
      familyMembers.forEach(member => {
        const memberPerson = this.data.individuals.get(member.id);
        if (memberPerson) {
          const memberName = memberPerson.name?.full || 'Unknown';
          const memberDates = memberPerson.birth?.date?.year ? ` (${memberPerson.birth.date.year})` : '';
          bodyHtml += `
            <div class="modal-family-member" data-id="${member.id}">
              <div class="relation">${member.relation}</div>
              <div class="name">${memberName}${memberDates}</div>
            </div>
          `;
        }
      });
      bodyHtml += '</div>';
    } else {
      bodyHtml += '<p style="color: var(--text-muted); font-style: italic;">No family connections found.</p>';
    }
    bodyHtml += '</div>';

    document.getElementById('modal-body').innerHTML = bodyHtml;

    document.querySelectorAll('.modal-family-member').forEach(el => {
      el.addEventListener('click', () => this.showPersonModal(el.dataset.id));
    });

    document.getElementById('person-modal').classList.add('active');
  }

  getFamilyMembers(personId) {
    const members = [];
    const person = this.data.individuals.get(personId);
    if (!person) return members;

    // Parents (from familyChild - FAMC)
    person.familyChild.forEach(famId => {
      const family = this.data.families.get(famId);
      if (family) {
        if (family.husband) members.push({ id: family.husband, relation: 'Father' });
        if (family.wife) members.push({ id: family.wife, relation: 'Mother' });
        // Siblings
        family.children.forEach(sibId => {
          if (sibId !== personId) members.push({ id: sibId, relation: 'Sibling' });
        });
      }
    });

    // Spouse and children (from familySpouse - FAMS)
    person.familySpouse.forEach(famId => {
      const family = this.data.families.get(famId);
      if (family) {
        if (family.husband && family.husband !== personId) {
          members.push({ id: family.husband, relation: 'Spouse' });
        }
        if (family.wife && family.wife !== personId) {
          members.push({ id: family.wife, relation: 'Spouse' });
        }
        family.children.forEach(childId => {
          members.push({ id: childId, relation: 'Child' });
        });
      }
    });

    return members;
  }

  closeModal() {
    document.getElementById('person-modal').classList.remove('active');
  }

  switchTab(tabName) {
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.classList.toggle('active', tab.dataset.tab === tabName);
    });

    document.querySelectorAll('.tab-content').forEach(content => {
      content.classList.toggle('active', content.id === `${tabName}-tab`);
    });

    if (tabName === 'search' && this.data) {
      this.performSearch();
    }

    if (tabName === 'map' && this.data) {
      setTimeout(() => this.initMap(), 100);
    }

    if (tabName === 'tree' && this.data && this.referencePerson) {
      this.renderFamilyTree(this.referencePerson);
    }

    if (tabName === 'statistics' && this.data) {
      this.updateStatistics();
    }
  }

  // Statistics
  updateStatistics() {
    // Use blood relatives only when reference person is set
    const individuals = this.referencePerson
      ? this.getBloodRelatives()
      : this.data.individuals;

    const totalCount = this.data.individuals.size;
    const filteredCount = individuals.size;

    // Show filtered vs total count
    const statIndividuals = document.getElementById('stat-individuals');
    if (this.referencePerson) {
      statIndividuals.innerHTML = `<strong>${filteredCount}</strong> <small style="opacity: 0.6;">blood relatives of ${totalCount} total</small>`;
    } else {
      statIndividuals.textContent = totalCount;
    }

    document.getElementById('stat-families').textContent = this.data.families.size;

    const locations = new Set();
    const years = [];
    individuals.forEach(p => {
      if (p.birth?.place) locations.add(p.birth.place);
      if (p.death?.place) locations.add(p.death.place);
      if (p.birth?.date?.year) years.push(p.birth.date.year);
    });

    document.getElementById('stat-locations').textContent = locations.size;

    if (years.length > 0) {
      const generations = Math.ceil((Math.max(...years) - Math.min(...years)) / 25);
      document.getElementById('stat-generations').textContent = generations;
    }

    // Re-render charts with filtered data
    this.renderTimelineChart();
    this.renderSurnameChart();
  }

  // Check if a relationship type is a blood relative (not spouse or in-law)
  isBloodRelative(relType) {
    const bloodTypes = ['self', 'ancestor', 'descendant', 'sibling', 'cousin', 'aunt_uncle', 'niece_nephew'];
    return bloodTypes.includes(relType);
  }

  // Get only blood relatives from the data (respects distance filter)
  getBloodRelatives() {
    if (!this.referencePerson) {
      return this.data.individuals;
    }

    const bloodRelatives = new Map();
    this.data.individuals.forEach((person, id) => {
      const rel = this.relationshipCache.get(id);
      const relType = rel?.type || 'unrelated';
      if (this.isBloodRelative(relType)) {
        // Check distance filter
        if (this.activeFilters.maxDistance && rel && rel.distance > this.activeFilters.maxDistance) {
          return; // Skip - too distant
        }
        bloodRelatives.set(id, person);
      }
    });
    return bloodRelatives;
  }

  renderTimelineChart() {
    const container = document.getElementById('timeline-chart');
    if (!container) return;

    container.innerHTML = '';

    // Use blood relatives only when reference person is set
    const individuals = this.referencePerson
      ? this.getBloodRelatives()
      : this.data.individuals;

    const yearCounts = {};
    individuals.forEach(p => {
      if (p.birth?.date?.year) {
        const decade = Math.floor(p.birth.date.year / 10) * 10;
        yearCounts[decade] = (yearCounts[decade] || 0) + 1;
      }
    });

    const data = Object.entries(yearCounts)
      .map(([decade, count]) => ({ decade: parseInt(decade), count }))
      .sort((a, b) => a.decade - b.decade);

    if (data.length === 0) {
      container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No birth dates available</div>';
      return;
    }

    const margin = { top: 20, right: 20, bottom: 60, left: 40 };
    // Use a fallback width if container isn't visible
    let containerWidth = container.clientWidth;
    if (containerWidth <= 0) {
      // Container not visible, try to get parent width or use default
      containerWidth = container.parentElement?.clientWidth || 600;
    }
    const width = containerWidth - margin.left - margin.right;
    const height = 280 - margin.top - margin.bottom;

    // Skip rendering if we still have no valid width
    if (width <= 0) return;

    const svgElement = d3.select(container)
      .append('svg')
      .attr('width', width + margin.left + margin.right)
      .attr('height', height + margin.top + margin.bottom);

    // Add gradient definition for timeline bars
    const defs = svgElement.append('defs');
    const gradient = defs.append('linearGradient')
      .attr('id', 'timelineGradient')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');
    gradient.append('stop')
      .attr('offset', '0%')
      .attr('stop-color', 'var(--accent-secondary)');
    gradient.append('stop')
      .attr('offset', '100%')
      .attr('stop-color', 'var(--accent-primary)');

    const svg = svgElement.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const x = d3.scaleBand().domain(data.map(d => d.decade)).range([0, width]).padding(0.25);
    const y = d3.scaleLinear().domain([0, d3.max(data, d => d.count) * 1.1]).range([height, 0]);

    // Calculate how many labels can fit without overlapping
    const labelWidth = 50; // approx width per label
    const maxLabels = Math.floor(width / labelWidth);
    const tickInterval = Math.ceil(data.length / maxLabels) || 1;

    svg.append('g').attr('class', 'axis').attr('transform', `translate(0,${height})`)
      .call(d3.axisBottom(x)
        .tickFormat((d, i) => i % tickInterval === 0 ? d + 's' : '')
        .tickValues(data.map(d => d.decade).filter((d, i) => i % tickInterval === 0))
      )
      .selectAll('text')
      .style('text-anchor', 'end')
      .attr('dx', '-0.5em')
      .attr('dy', '0.3em')
      .attr('transform', 'rotate(-45)');
    svg.append('g').attr('class', 'axis').call(d3.axisLeft(y).ticks(5));

    // Create tooltip div if it doesn't exist
    let tooltip = d3.select('#timeline-tooltip');
    if (tooltip.empty()) {
      tooltip = d3.select('body').append('div')
        .attr('id', 'timeline-tooltip')
        .style('position', 'absolute')
        .style('background', 'var(--bg-card)')
        .style('border', '1px solid var(--border-color)')
        .style('border-radius', '8px')
        .style('padding', '10px 14px')
        .style('font-size', '13px')
        .style('pointer-events', 'none')
        .style('opacity', 0)
        .style('z-index', 1000)
        .style('box-shadow', '0 4px 12px rgba(0,0,0,0.15)');
    }

    const bars = svg.selectAll('.timeline-bar').data(data).enter().append('rect')
      .attr('class', 'timeline-bar')
      .attr('x', d => x(d.decade))
      .attr('width', x.bandwidth())
      .attr('y', height)
      .attr('height', 0)
      .style('cursor', 'pointer');

    // Add hover interactions
    bars.on('mouseover', function(event, d) {
        d3.select(this).style('opacity', 0.8);
        const decadeEnd = d.decade + 9;
        tooltip
          .style('opacity', 1)
          .html(`
            <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">
              ${d.decade}s
            </div>
            <div style="color: var(--text-muted); font-size: 11px; margin-bottom: 6px;">
              ${d.decade} – ${decadeEnd}
            </div>
            <div style="color: var(--accent-primary); font-size: 15px; font-weight: 600;">
              ${d.count} birth${d.count !== 1 ? 's' : ''}
            </div>
          `);
      })
      .on('mousemove', function(event) {
        tooltip
          .style('left', (event.pageX + 15) + 'px')
          .style('top', (event.pageY - 10) + 'px');
      })
      .on('mouseout', function() {
        d3.select(this).style('opacity', 1);
        tooltip.style('opacity', 0);
      });

    // Animate bars
    bars.transition().duration(800).delay((d, i) => i * 50)
      .attr('y', d => y(d.count))
      .attr('height', d => height - y(d.count));
  }

  renderSurnameChart() {
    const container = document.getElementById('surname-list');
    if (!container) return;
    container.innerHTML = '';

    // Use blood relatives only when reference person is set
    const individuals = this.referencePerson
      ? this.getBloodRelatives()
      : this.data.individuals;

    const counts = {};
    individuals.forEach(p => {
      if (p.name?.surname) counts[p.name.surname] = (counts[p.name.surname] || 0) + 1;
    });

    const data = Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    if (data.length === 0) {
      container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 1rem;">No surname data</div>';
      return;
    }

    const max = data[0].count;
    data.forEach((item, i) => {
      const pct = (item.count / max) * 100;
      const div = document.createElement('div');
      div.className = 'surname-item';
      div.innerHTML = `
        <span class="surname-name">${item.name}</span>
        <div class="surname-bar"><div class="surname-bar-fill" style="width: 0%"></div></div>
        <span class="surname-count">${item.count}</span>
      `;
      container.appendChild(div);
      setTimeout(() => div.querySelector('.surname-bar-fill').style.width = `${pct}%`, i * 100);
    });
  }

  // Family Tree
  renderFamilyTree(rootId) {
    const svg = d3.select('#tree-svg');
    svg.selectAll('*').remove();

    const container = document.getElementById('tree-container');
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Set SVG to fill container
    svg.attr('width', width).attr('height', height);

    // Always show both ancestors and descendants together
    this.renderBothTree(rootId, svg, width, height);
  }

  // Render "both" direction tree with ancestors above, descendants below
  renderBothTree(rootId, svg, width, height) {
    const person = this.data.individuals.get(rootId);
    if (!person) return;

    const self = this;
    const g = svg.append('g');
    const centerX = width / 2;
    const centerY = height / 2;

    // Build trees with reasonable depth
    const ancestorTree = this.buildAncestorTree(rootId, 5);
    const descendantTree = this.buildDescendantTree(rootId, 4, 0);

    // Use D3 tree layout for ancestors (flipped)
    if (ancestorTree?.children?.length > 0) {
      const ancestorRoot = d3.hierarchy(ancestorTree);
      const ancestorNodeCount = ancestorRoot.descendants().length;

      // Calculate proper dimensions based on tree size
      const aTreeWidth = Math.max(400, ancestorNodeCount * 50);
      const aTreeHeight = Math.min(300, ancestorRoot.height * 80);

      const ancestorLayout = d3.tree()
        .size([aTreeWidth, aTreeHeight])
        .separation((a, b) => (a.parent === b.parent ? 1 : 1.5));

      ancestorLayout(ancestorRoot);

      // Draw ancestor links (curved)
      g.selectAll('.ancestor-link')
        .data(ancestorRoot.links())
        .enter()
        .append('path')
        .attr('class', 'tree-link ancestor-link')
        .attr('d', d => {
          const sx = centerX + d.source.x - aTreeWidth / 2;
          const sy = centerY - 50 - d.source.y;
          const tx = centerX + d.target.x - aTreeWidth / 2;
          const ty = centerY - 50 - d.target.y;
          return `M${sx},${sy} C${sx},${(sy + ty) / 2} ${tx},${(sy + ty) / 2} ${tx},${ty}`;
        })
        .attr('fill', 'none');

      // Draw ancestor nodes
      ancestorRoot.descendants().forEach(d => {
        if (d.data.id === rootId) return; // Skip root, we draw it separately
        const x = centerX + d.x - aTreeWidth / 2;
        const y = centerY - 50 - d.y;
        this.drawSimpleNode(g, d.data.id, d.data.name, d.data.sex, x, y, false);
      });
    }

    // Use D3 tree layout for descendants
    if (descendantTree?.children?.length > 0) {
      const descendantRoot = d3.hierarchy(descendantTree);
      const dNodeCount = descendantRoot.descendants().length;

      const dTreeWidth = Math.max(400, dNodeCount * 50);
      const dTreeHeight = Math.min(250, descendantRoot.height * 80);

      const descendantLayout = d3.tree()
        .size([dTreeWidth, dTreeHeight])
        .separation((a, b) => (a.parent === b.parent ? 1 : 1.5));

      descendantLayout(descendantRoot);

      // Draw descendant links
      g.selectAll('.descendant-link')
        .data(descendantRoot.links())
        .enter()
        .append('path')
        .attr('class', 'tree-link descendant-link')
        .attr('d', d => {
          const sx = centerX + d.source.x - dTreeWidth / 2;
          const sy = centerY + 50 + d.source.y;
          const tx = centerX + d.target.x - dTreeWidth / 2;
          const ty = centerY + 50 + d.target.y;
          return `M${sx},${sy} C${sx},${(sy + ty) / 2} ${tx},${(sy + ty) / 2} ${tx},${ty}`;
        })
        .attr('fill', 'none');

      // Draw descendant nodes
      descendantRoot.descendants().forEach(d => {
        if (d.data.id === rootId) return;
        const x = centerX + d.x - dTreeWidth / 2;
        const y = centerY + 50 + d.y;
        this.drawSimpleNode(g, d.data.id, d.data.name, d.data.sex, x, y, false);
      });
    }

    // Draw root person in center
    this.drawSimpleNode(g, rootId, person.name?.given || 'Unknown', person.sex, centerX, centerY, true);

    // Draw spouse if exists
    const spouseId = this.getSpouse(rootId);
    if (spouseId) {
      const spouse = this.data.individuals.get(spouseId);
      if (spouse) {
        const spouseX = centerX + 80;
        // Marriage connector
        g.append('line')
          .attr('class', 'tree-link marriage-link')
          .attr('x1', centerX + 22)
          .attr('y1', centerY)
          .attr('x2', spouseX - 22)
          .attr('y2', centerY);
        this.drawSimpleNode(g, spouseId, spouse.name?.given || 'Unknown', spouse.sex, spouseX, centerY, false);
      }
    }

    // Setup zoom
    this.treeZoom = d3.zoom()
      .scaleExtent([0.2, 3])
      .on('zoom', (event) => g.attr('transform', event.transform));

    svg.call(this.treeZoom);

    // Fit to viewport
    const bounds = g.node().getBBox();
    const scale = Math.min(
      0.85 * width / bounds.width,
      0.85 * height / bounds.height,
      1.0
    );
    const translateX = width / 2 - (bounds.x + bounds.width / 2) * scale;
    const translateY = height / 2 - (bounds.y + bounds.height / 2) * scale;

    svg.call(this.treeZoom.transform, d3.zoomIdentity.translate(translateX, translateY).scale(scale));
  }

  getSpouse(personId) {
    const person = this.data.individuals.get(personId);
    if (!person?.familySpouse?.length) return null;
    const family = this.data.families.get(person.familySpouse[0]);
    if (!family) return null;
    if (family.husband === personId) return family.wife;
    if (family.wife === personId) return family.husband;
    return null;
  }

  drawSimpleNode(g, id, name, sex, x, y, isRoot) {
    const self = this;
    const isSelf = id === this.referencePerson;
    const nodeRadius = 20;

    // Get full person data for surname
    const person = this.data.individuals.get(id);
    const givenName = person?.name?.given || name || 'Unknown';
    const surname = person?.name?.surname || '';

    const node = g.append('g')
      .attr('class', `tree-node ${sex === 'M' ? 'male' : 'female'}`)
      .attr('transform', `translate(${x},${y})`)
      .style('cursor', 'pointer')
      .on('click', () => this.showPersonModal(id));

    // Node circle
    let fillColor = sex === 'M' ? '#3B82F6' : '#EC4899';
    if (this.referencePerson) {
      fillColor = this.getRelationshipColor(id);
    }

    node.append('circle')
      .attr('r', nodeRadius)
      .attr('fill', fillColor)
      .attr('stroke', isSelf ? '#FFD700' : (isRoot ? '#10B981' : '#fff'))
      .attr('stroke-width', isSelf ? 3 : (isRoot ? 3 : 2));

    // First name (given name)
    const displayGiven = givenName.length > 10 ? givenName.substring(0, 9) + '…' : givenName;
    const givenText = node.append('text')
      .attr('dy', nodeRadius + 13)
      .attr('text-anchor', 'middle')
      .attr('class', 'tree-node-given')
      .text(displayGiven);
    givenText.append('title').text(givenName);

    // Surname (last name)
    if (surname) {
      const displaySurname = surname.length > 12 ? surname.substring(0, 11) + '…' : surname;
      const surnameText = node.append('text')
        .attr('dy', nodeRadius + 25)
        .attr('text-anchor', 'middle')
        .attr('class', 'tree-node-surname')
        .text(displaySurname);
      surnameText.append('title').text(surname);
    }
  }

  buildAncestorTree(personId, maxDepth, depth = 0) {
    if (depth >= maxDepth) return null;

    const person = this.data.individuals.get(personId);
    if (!person) return null;

    const node = {
      id: personId,
      name: person.name?.given || 'Unknown',
      sex: person.sex,
      children: [] // In ancestor view, "children" are actually parents
    };

    // Find parents through familyChild (FAMC)
    person.familyChild.forEach(famId => {
      const family = this.data.families.get(famId);
      if (family) {
        if (family.husband) {
          const fatherNode = this.buildAncestorTree(family.husband, maxDepth, depth + 1);
          if (fatherNode) node.children.push(fatherNode);
        }
        if (family.wife) {
          const motherNode = this.buildAncestorTree(family.wife, maxDepth, depth + 1);
          if (motherNode) node.children.push(motherNode);
        }
      }
    });

    return node;
  }

  buildDescendantTree(personId, maxDepth, depth = 0) {
    if (depth >= maxDepth) return null;

    const person = this.data.individuals.get(personId);
    if (!person) return null;

    const node = {
      id: personId,
      name: person.name?.given || 'Unknown',
      sex: person.sex,
      children: []
    };

    person.familySpouse.forEach(famId => {
      const family = this.data.families.get(famId);
      if (family?.children) {
        family.children.forEach(childId => {
          const childNode = this.buildDescendantTree(childId, maxDepth, depth + 1);
          if (childNode) node.children.push(childNode);
        });
      }
    });

    return node;
  }

  buildBothTree(personId, ancestorDepth = 4, descendantDepth = 4) {
    const person = this.data.individuals.get(personId);
    if (!person) return null;

    // Get spouses
    const spouses = [];
    if (person.familySpouse) {
      for (const famId of person.familySpouse) {
        const family = this.data.families.get(famId);
        if (family) {
          if (family.husband && family.husband !== personId) {
            const spouse = this.data.individuals.get(family.husband);
            if (spouse) spouses.push({ id: family.husband, name: spouse.name?.given || 'Unknown', sex: spouse.sex });
          }
          if (family.wife && family.wife !== personId) {
            const spouse = this.data.individuals.get(family.wife);
            if (spouse) spouses.push({ id: family.wife, name: spouse.name?.given || 'Unknown', sex: spouse.sex });
          }
        }
      }
    }

    // Build the root node with the person and their spouse as a couple
    const rootNode = {
      id: personId,
      name: person.name?.given || 'Unknown',
      fullName: person.name?.full || 'Unknown',
      sex: person.sex,
      isRoot: true,
      spouse: spouses[0] || null,  // Primary spouse
      children: []
    };

    // Add ancestors as "children" that will be rendered above
    const ancestorSubtree = [];
    if (person.familyChild) {
      for (const famId of person.familyChild) {
        const family = this.data.families.get(famId);
        if (family) {
          if (family.husband) {
            const fatherTree = this.buildAncestorTree(family.husband, ancestorDepth, 0);
            if (fatherTree) {
              fatherTree.isAncestor = true;
              ancestorSubtree.push(fatherTree);
            }
          }
          if (family.wife) {
            const motherTree = this.buildAncestorTree(family.wife, ancestorDepth, 0);
            if (motherTree) {
              motherTree.isAncestor = true;
              ancestorSubtree.push(motherTree);
            }
          }
        }
      }
    }

    // Add descendants
    const descendantSubtree = [];
    if (person.familySpouse) {
      for (const famId of person.familySpouse) {
        const family = this.data.families.get(famId);
        if (family?.children) {
          for (const childId of family.children) {
            const childTree = this.buildDescendantTree(childId, descendantDepth, 0);
            if (childTree) {
              childTree.isDescendant = true;
              descendantSubtree.push(childTree);
            }
          }
        }
      }
    }

    // Structure: ancestors above (as virtual parent), person+spouse in middle, descendants below
    // For D3 tree layout, we create a wrapper structure
    if (ancestorSubtree.length > 0 || descendantSubtree.length > 0) {
      // Create a wrapper that shows ancestors as parents and descendants as children
      rootNode.children = [...descendantSubtree];

      // Add ancestors as a special node above
      if (ancestorSubtree.length > 0) {
        const ancestorWrapper = {
          id: 'ancestors_' + personId,
          name: 'Parents',
          isAncestorWrapper: true,
          children: ancestorSubtree
        };
        // We'll handle this in a special way during rendering
        rootNode.ancestors = ancestorSubtree;
      }
    }

    return rootNode;
  }

  resetTreeView() {
    if (this.treeZoom) {
      d3.select('#tree-svg').transition().duration(500).call(this.treeZoom.transform, d3.zoomIdentity);
    }
  }

  zoomTree(factor) {
    if (this.treeZoom) {
      d3.select('#tree-svg').transition().duration(300).call(this.treeZoom.scaleBy, factor);
    }
  }

  // Map
  initMap() {
    if (!this.data) return;

    const container = document.getElementById('genealogy-map');
    if (!container) return;

    if (this.map) {
      this.map.remove();
      this.map = null;
    }

    // Collect locations - use blood relatives only when reference person is set
    const individuals = this.referencePerson
      ? this.getBloodRelatives()
      : this.data.individuals;

    const locations = new Map();
    const self = this;

    // Clean up location - remove multiple commas and use Italian province abbreviations
    const cleanLocation = (place) => {
      if (!place) return 'Unknown';

      // Italian province abbreviations
      const italianProvinces = {
        'Agrigento': 'AG', 'Alessandria': 'AL', 'Ancona': 'AN', 'Aosta': 'AO', 'Arezzo': 'AR',
        'Ascoli Piceno': 'AP', 'Asti': 'AT', 'Avellino': 'AV', 'Bari': 'BA', 'Barletta-Andria-Trani': 'BT',
        'Belluno': 'BL', 'Benevento': 'BN', 'Bergamo': 'BG', 'Biella': 'BI', 'Bologna': 'BO',
        'Bolzano': 'BZ', 'Brescia': 'BS', 'Brindisi': 'BR', 'Cagliari': 'CA', 'Caltanissetta': 'CL',
        'Campobasso': 'CB', 'Caserta': 'CE', 'Catania': 'CT', 'Catanzaro': 'CZ', 'Chieti': 'CH',
        'Como': 'CO', 'Cosenza': 'CS', 'Cremona': 'CR', 'Crotone': 'KR', 'Cuneo': 'CN',
        'Enna': 'EN', 'Fermo': 'FM', 'Ferrara': 'FE', 'Firenze': 'FI', 'Florence': 'FI',
        'Foggia': 'FG', 'Forlì-Cesena': 'FC', 'Frosinone': 'FR', 'Genova': 'GE', 'Genoa': 'GE',
        'Gorizia': 'GO', 'Grosseto': 'GR', 'Imperia': 'IM', 'Isernia': 'IS', 'L\'Aquila': 'AQ',
        'La Spezia': 'SP', 'Latina': 'LT', 'Lecce': 'LE', 'Lecco': 'LC', 'Livorno': 'LI',
        'Lodi': 'LO', 'Lucca': 'LU', 'Macerata': 'MC', 'Mantova': 'MN', 'Massa-Carrara': 'MS',
        'Matera': 'MT', 'Messina': 'ME', 'Milano': 'MI', 'Milan': 'MI', 'Modena': 'MO',
        'Monza e Brianza': 'MB', 'Napoli': 'NA', 'Naples': 'NA', 'Novara': 'NO', 'Nuoro': 'NU',
        'Oristano': 'OR', 'Padova': 'PD', 'Palermo': 'PA', 'Parma': 'PR', 'Pavia': 'PV',
        'Perugia': 'PG', 'Pesaro e Urbino': 'PU', 'Pescara': 'PE', 'Piacenza': 'PC', 'Pisa': 'PI',
        'Pistoia': 'PT', 'Pordenone': 'PN', 'Potenza': 'PZ', 'Prato': 'PO', 'Ragusa': 'RG',
        'Ravenna': 'RA', 'Reggio Calabria': 'RC', 'Reggio Emilia': 'RE', 'Rieti': 'RI', 'Rimini': 'RN',
        'Roma': 'RM', 'Rome': 'RM', 'Rovigo': 'RO', 'Salerno': 'SA', 'Sassari': 'SS',
        'Savona': 'SV', 'Siena': 'SI', 'Siracusa': 'SR', 'Sondrio': 'SO', 'Sud Sardegna': 'SU',
        'Taranto': 'TA', 'Teramo': 'TE', 'Terni': 'TR', 'Torino': 'TO', 'Turin': 'TO',
        'Trapani': 'TP', 'Trento': 'TN', 'Treviso': 'TV', 'Trieste': 'TS', 'Udine': 'UD',
        'Varese': 'VA', 'Venezia': 'VE', 'Venice': 'VE', 'Verbano-Cusio-Ossola': 'VB',
        'Vercelli': 'VC', 'Verona': 'VR', 'Vibo Valentia': 'VV', 'Vicenza': 'VI', 'Viterbo': 'VT'
      };

      // Italian regions (to remove when province is present)
      const italianRegions = [
        'Abruzzo', 'Basilicata', 'Calabria', 'Campania', 'Emilia-Romagna', 'Emilia Romagna',
        'Friuli-Venezia Giulia', 'Friuli Venezia Giulia', 'Lazio', 'Liguria', 'Lombardia', 'Lombardy',
        'Marche', 'Molise', 'Piemonte', 'Piedmont', 'Puglia', 'Apulia', 'Sardegna', 'Sardinia',
        'Sicilia', 'Sicily', 'Toscana', 'Tuscany', 'Trentino-Alto Adige', 'Trentino Alto Adige',
        'Umbria', 'Valle d\'Aosta', "Val d'Aosta", 'Veneto'
      ];

      // Clean up the location string
      let cleaned = place
        .replace(/,+/g, ',')
        .replace(/,\s*,/g, ',')
        .replace(/^,+|,+$/g, '')
        .replace(/,(?!\s)/g, ', ')  // Add space after commas
        .replace(/\s+/g, ' ')
        .trim();

      if (!cleaned) return 'Unknown';

      // Check if this is an Italian location and substitute province abbreviation
      const parts = cleaned.split(',').map(p => p.trim());
      let provinceFound = null;
      let provinceIndex = -1;

      // Find the province in the parts
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (italianProvinces[part]) {
          provinceFound = italianProvinces[part];
          provinceIndex = i;
          break;
        }
      }

      // If province found, rebuild with abbreviation - keep Italy at the end
      if (provinceFound && provinceIndex > 0) {
        // Keep town name(s) before the province
        const townParts = parts.slice(0, provinceIndex).filter(p => p);
        // Check if Italy is in the remaining parts
        const hasItaly = parts.slice(provinceIndex + 1).some(p =>
          p.toLowerCase() === 'italy' || p.toLowerCase() === 'italia'
        );

        // Build final string: "Town (XX), Italy"
        if (townParts.length > 0) {
          cleaned = townParts.join(', ') + ' (' + provinceFound + ')';
          if (hasItaly) {
            cleaned += ', Italy';
          }
        }
      }

      return cleaned || 'Unknown';
    };

    individuals.forEach((person, id) => {
      const coords = person.birth?.coordinates;
      if (coords?.lat && coords?.lng) {
        const key = `${coords.lat.toFixed(4)},${coords.lng.toFixed(4)}`;
        if (!locations.has(key)) {
          locations.set(key, {
            lat: coords.lat,
            lng: coords.lng,
            place: cleanLocation(person.birth.place),
            people: [],
            relationshipCounts: {}
          });
        }
        const relType = self.getRelationshipType(id);
        const loc = locations.get(key);
        loc.people.push({
          id,
          name: person.name?.full || 'Unknown',
          year: person.birth?.date?.year,
          relationship: relType,
          relColor: self.getRelationshipColor(id)
        });
        loc.relationshipCounts[relType] = (loc.relationshipCounts[relType] || 0) + 1;
      }
    });

    console.log(`Map locations found: ${locations.size}`);

    if (locations.size === 0) {
      container.innerHTML = `
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-muted);">
          <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom: 1rem; opacity: 0.5;">
            <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
            <circle cx="12" cy="10" r="3"/>
          </svg>
          <h3 style="font-family: 'Cormorant Garamond', serif; margin-bottom: 0.5rem;">No Location Data</h3>
          <p>No geographic coordinates found in the GEDCOM file.</p>
        </div>
      `;
      return;
    }

    const locs = Array.from(locations.values());
    const centerLat = locs.reduce((s, l) => s + l.lat, 0) / locs.length;
    const centerLng = locs.reduce((s, l) => s + l.lng, 0) / locs.length;

    this.map = L.map('genealogy-map').setView([centerLat, centerLng], 6);
    this.updateMapTiles();

    // Force map to recalculate size (critical for containers that were hidden)
    setTimeout(() => {
      if (this.map) {
        this.map.invalidateSize();
      }
    }, 100);

    locations.forEach(loc => {
      // Determine marker color based on dominant relationship type
      let markerColor = '#8b2635'; // Default wine color
      if (self.referencePerson && Object.keys(loc.relationshipCounts).length > 0) {
        // Find the most common relationship type at this location
        const dominantType = Object.entries(loc.relationshipCounts)
          .sort((a, b) => b[1] - a[1])[0][0];
        markerColor = self.relationshipColors[dominantType] || markerColor;
      }

      const marker = L.circleMarker([loc.lat, loc.lng], {
        radius: Math.min(8 + loc.people.length * 2, 20),
        fillColor: markerColor,
        color: '#fff',
        weight: 2,
        opacity: 1,
        fillOpacity: 0.8
      });

      let popup = `<div class="popup-title">${loc.place}</div>`;
      popup += `<div class="popup-count">${loc.people.length} ${loc.people.length === 1 ? 'person' : 'people'}</div>`;

      // Show relationship breakdown if reference person is set
      if (self.referencePerson) {
        popup += '<div style="margin-top: 4px; font-size: 0.85em; color: #666;">';
        Object.entries(loc.relationshipCounts).forEach(([type, count]) => {
          const color = self.relationshipColors[type] || '#666';
          popup += `<span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${color}; margin-right: 4px;"></span>${type}: ${count}<br>`;
        });
        popup += '</div>';
      }

      if (loc.people.length <= 5) {
        popup += '<div style="margin-top: 8px; font-size: 0.9em;">';
        loc.people.forEach(p => {
          const relLabel = self.referencePerson ? ` (${p.relationship})` : '';
          popup += `<div>${p.name}${p.year ? ` (${p.year})` : ''}${relLabel}</div>`;
        });
        popup += '</div>';
      }

      marker.bindPopup(popup);
      marker.addTo(this.map);
    });

    this.map.fitBounds(L.latLngBounds(locs.map(l => [l.lat, l.lng])), { padding: [50, 50] });
  }

  updateMapTiles() {
    if (!this.map) return;

    this.map.eachLayer(layer => {
      if (layer instanceof L.TileLayer) this.map.removeLayer(layer);
    });

    const isDark = document.documentElement.dataset.theme === 'dark';
    const url = isDark
      ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
      : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';

    L.tileLayer(url, {
      attribution: '&copy; OpenStreetMap &copy; CARTO',
      subdomains: 'abcd',
      maxZoom: 19
    }).addTo(this.map);
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  window.genealogyApp = new GenealogyApp();
});
