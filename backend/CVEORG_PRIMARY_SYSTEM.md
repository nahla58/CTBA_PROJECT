# CVE.org PRIMARY Source System Implementation

## Overview
The CTBA Platform now uses **CVE.org as the PRIMARY source** for all CVE data, with other sources (NVD, CVEdetails, MSRC, Hackuity) as **SECONDARY sources**.

## System Architecture

### Import Priority
1. **CVE.org (PRIMARY)** - MITRE's official CVE registry
   - Provides authoritative CVE information
   - Definitive publication and update dates
   - CVSS metrics from official sources
   - Source tag: `CVEORG`

2. **NVD (SECONDARY)** - National Vulnerability Database
   - Merged with CVE.org data
   - Used for enhanced vulnerability details
   - CVSS scores compared and max used
   - Added to `sources_secondary`

3. **CVEdetails (SECONDARY)** - CVE Details vulnerability database
   - Additional vulnerability context
   - Risk metrics from independent source
   - Merged with existing data
   - Added to `sources_secondary`

4. **MSRC (SECONDARY)** - Microsoft Security Response Center
   - Microsoft-specific vulnerability data

5. **Hackuity (SECONDARY)** - Hackuity vulnerability intelligence

### Data Merging Rules

When a CVE appears in multiple sources:

```
1. Source Priority: CVE.org is ALWAYS primary
2. CVSS Score: Use MAXIMUM score from all sources
3. Dates: Use dates from CVE.org (authoritative)
4. Tracking: Secondary sources stored in `sources_secondary` JSON field
```

### Database Schema

```sql
-- Primary CVE record
cves:
  - cve_id (PRIMARY KEY)
  - source (CVEORG, NVD, cvedetails, etc.)  -- PRIMARY source
  - cvss_score (MAX from all sources)
  - published_date (from CVE.org)
  - last_updated (from CVE.org)
  - sources_secondary (JSON array of secondary sources)

-- Secondary source tracking
cve_sources:
  - cve_id (FOREIGN KEY)
  - source_name (name of secondary source)
  - added_at (timestamp)
```

## Startup Process

### On Application Start
```
1. Initialize database
2. Launch CVE.org importer (PRIMARY) 🌟
   └─ Fetches from CVE.org API
   └─ Extracts dates and CVSS metrics
   └─ Stores with source='CVEORG'
   
3. Launch secondary importers in PARALLEL ⚙️
   ├─ NVD importer
   ├─ CVEdetails importer
   ├─ MSRC importer
   └─ Hackuity importer
   
4. Secondary importers MERGE with CVE.org data
   └─ Compare CVSS scores → use max
   └─ Keep CVE.org dates
   └─ Track secondary source reference
```

### Scheduled Imports
```
Every 30 minutes:
  1. Run CVE.org importer (PRIMARY) first
  2. Then run secondary importers (NVD, CVEdetails, etc.)
  3. All data merges automatically
```

## Date Handling

### Date Authority: CVE.org
- `published_date` → from CVE.org `datePublished`
- `last_updated` → from CVE.org `dateUpdated`
- Format: ISO 8601 with Z suffix (e.g., `2026-01-27T09:10:42.123456Z`)

### Date Display
Frontend converts to local timezone (UTC+1):
- Database stores: `2026-01-27T01:16:03.050000Z` (UTC)
- Display shows: `27/01/2026 02:16:03` (UTC+1 - Europe/Paris)

## CVSS Score Handling

### Score Selection
1. Check all sources for CVSS scores
2. Extract version with highest priority:
   - CVSS v4.0 (preferred)
   - CVSS v3.1 (alternative)
   - CVSS v3.0 (fallback)
3. **Use MAXIMUM score** if multiple sources have different scores

Example:
```
CVE-2026-1234:
  CVE.org:  8.5 (v3.1)
  NVD:      8.2 (v3.1)
  CVEdetails: 8.7 (v3.1)
  
  → Final score: 8.7 (MAX)
  → Source: CVEORG + secondary sources: [NVD, CVEdetails]
```

## Running the System

### Initial Setup
```bash
# Clean database for fresh start
python setup_cveorg_primary.py

# Start the API with CVE.org PRIMARY source
python main.py
```

### Verify System
```bash
# Test that CVE.org is PRIMARY and merging works
python test_cveorg_primary.py
```

### Update Dates from CVE.org
```bash
# If dates need correction from CVE.org
python fix_cve_dates.py
```

## API Response Format

### CVE List Response
```json
{
  "cve_id": "CVE-2026-24686",
  "source": "CVEORG",
  "sources_secondary": [
    {"name": "NVD", "added_at": "2026-01-27T09:10:41"},
    {"name": "cvedetails", "added_at": "2026-01-27T09:10:45"}
  ],
  "cvss_score": 8.7,
  "cvss_version": "3.1",
  "published_date": "2026-01-27T01:16:03.050000Z",
  "published_date_formatted": "27/01/2026 02:16:03",
  "last_updated": "2026-01-27T09:10:42Z",
  "last_updated_formatted": "27/01/2026 10:10:42"
}
```

### Source Badge Display
```
PRIMARY:    [CVEORG badge]
SECONDARY:  +2 (hover shows: NVD, cvedetails)
```

## Monitoring

### Import Logs
```
🌟 Starting CVE.org import as PRIMARY source...
📡 Fetching recent CVEs from CVE.org...
📊 Found 150 CVEs from CVE.org
✅ CVE.org import completed in 23.45s
📊 Imported 150 CVEs from CVE.org as PRIMARY source

⚙️ Launching secondary sources in parallel...
🚀 Starting NVD import with intelligent product extraction...
🚀 Starting CVE Details import...
```

### Database Queries

Check CVE.org as primary:
```sql
SELECT COUNT(*) FROM cves WHERE source = 'CVEORG';
```

Check multi-source CVEs:
```sql
SELECT cve_id, source, sources_secondary 
FROM cves 
WHERE sources_secondary != '[]';
```

Check CVSS score merging:
```sql
SELECT cve_id, cvss_score, source, sources_secondary 
FROM cves 
WHERE sources_secondary != '[]'
ORDER BY cvss_score DESC;
```

## Troubleshooting

### CVE.org API Issues
If CVE.org API is unavailable:
```
⚠️ CVE.org import skipped (API unreachable)
→ Secondary sources will still import normally
→ Data will be less authoritative but still available
```

### Date Inconsistencies
Run the date fix script:
```bash
python fix_cve_dates.py
# Updates all published_date and last_updated from CVE.org
```

### Force Re-import
```bash
python setup_cveorg_primary.py  # Backs up old DB
python main.py                   # Fresh import from CVE.org
```

## Implementation Details

### Key Functions

**`import_from_cveorg()`** - Primary import function
- Fetches CVEs from `https://cveawg.mitre.org/api/cves/1.1`
- Gets detailed info from `https://cveawg.mitre.org/api/cve/{CVE_ID}`
- Extracts dates, CVSS metrics, descriptions
- Stores with source='CVEORG'

**`merge_cve_from_sources()`** - Merge function
- Called by secondary importers
- Compares and uses max CVSS score
- Updates dates only if from CVE.org
- Tracks secondary sources

**`format_date_for_display()`** - Date formatting
- Converts UTC to local timezone (Europe/Paris)
- Returns multiple formats for display
- Called by API responses

### Import Flow Diagram
```
Application Start
    ↓
Initialize Database
    ↓
┌────────────────────────────────────────────┐
│ 1. CVE.org PRIMARY (wait for completion)   │
│    ├─ Fetch from https://...api/cves/1.1   │
│    ├─ Extract dates, CVSS, descriptions    │
│    └─ Store with source='CVEORG'           │
└────────────────────────────────────────────┘
    ↓
┌─────────────────┬──────────────────┬──────────────────┐
│ NVD SECONDARY   │ CVEdetails SEC.  │ MSRC SECONDARY   │ (PARALLEL)
│ ├─ Fetch CVEs   │ ├─ Fetch CVEs    │ ├─ Fetch CVEs    │
│ ├─ Merge data   │ ├─ Merge data    │ ├─ Merge data    │
│ └─ Add to sec.  │ └─ Add to sec.   │ └─ Add to sec.   │
└─────────────────┴──────────────────┴──────────────────┘
    ↓
Data Merging
    ├─ CVSS: Use MAX score
    ├─ Dates: Keep CVE.org
    └─ Sources: Track all in sources_secondary
    ↓
✅ Import Complete
```

## Configuration

No additional configuration needed. The system automatically:
- Prioritizes CVE.org
- Launches secondary importers in parallel
- Merges data on conflicts
- Uses CVE.org dates as authoritative

Environment variables (optional):
```
CVEDETAILS_API_TOKEN=your_token  # For CVEdetails API
```

## Performance Notes

- CVE.org import: ~20-30 seconds for 500 CVEs
- Secondary imports: Parallel, ~5-15 seconds each
- Total startup: ~30-40 seconds
- Scheduled runs: Every 30 minutes
- Rate limiting: Respectful API usage (0.2s delay per CVE.org request)

## References

- [CVE.org API Documentation](https://www.cve.org/APIDocumentation)
- [NVD API](https://nvd.nist.gov/)
- [CVE Details API](https://www.cvedetails.com/api/)
