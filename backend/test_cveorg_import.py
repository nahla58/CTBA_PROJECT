#!/usr/bin/env python3
"""Test CVE.org importer to see why it's not finding overlaps"""

import sqlite3
import requests
from datetime import datetime, timedelta

# Connect to database
conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 60)
print("Testing CVE.org Import Logic")
print("=" * 60)

# Check current database state
cursor.execute("SELECT COUNT(*) as count FROM cves")
total_cves = cursor.fetchone()['count']
print(f"\n1. Current database state: {total_cves} total CVEs")

cursor.execute("SELECT source_primary, COUNT(*) as count FROM cves GROUP BY source_primary")
for row in cursor.fetchall():
    print(f"   - {row['source_primary']}: {row['count']}")

# Simulate what CVE.org importer does
print("\n2. Fetching recent CVEs from NVD API (like CVE.org importer does)...")
try:
    now = datetime.utcnow()
    start_date = (now - timedelta(days=30)).isoformat()
    end_date = now.isoformat()
    
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date}&pubEndDate={end_date}&resultsPerPage=50"
    print(f"   URL: {nvd_url[:80]}...")
    
    response = requests.get(nvd_url, timeout=15)
    response.raise_for_status()
    nvd_data = response.json()
    
    vulnerabilities = nvd_data.get('vulnerabilities', [])
    print(f"   ✅ Got {len(vulnerabilities)} CVEs from NVD API")
    
    # Check which ones exist in our database
    existing_count = 0
    new_count = 0
    
    for vuln in vulnerabilities[:30]:
        cve_id = vuln.get('cve', {}).get('id')
        if not cve_id:
            continue
        
        cursor.execute('SELECT source_primary FROM cves WHERE cve_id = ?', (cve_id,))
        existing = cursor.fetchone()
        
        if existing:
            existing_count += 1
            print(f"   ✓ {cve_id} EXISTS (primary: {existing['source_primary']})")
        else:
            new_count += 1
            print(f"   ✗ {cve_id} NOT FOUND in DB")
    
    print(f"\n3. Summary:")
    print(f"   - Existing in DB (should enrich): {existing_count}")
    print(f"   - New to DB (should create): {new_count}")
    
except Exception as e:
    print(f"   ❌ Error: {str(e)[:100]}")

print("\n" + "=" * 60)
