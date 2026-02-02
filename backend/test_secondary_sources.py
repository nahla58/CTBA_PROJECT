#!/usr/bin/env python3
"""
Test the add_secondary_source function with our test database
"""

import sqlite3
import json
from datetime import datetime
import pytz
import sys
sys.path.insert(0, '/mnt/c/essai/CTBA_PROJECT/backend')

# Import the function from main.py (simulate it since we can't import main directly)
def add_secondary_source(cursor, cve_id: str, source_name: str, data_enrichment: str = ""):
    """
    Add a source to the sources_secondary JSON array without replacing the primary source.
    """
    try:
        # Get current sources_secondary
        cursor.execute(
            "SELECT sources_secondary FROM cves WHERE cve_id = ?",
            (cve_id,)
        )
        row = cursor.fetchone()
        
        if not row:
            print(f"❌ CVE {cve_id} not found when adding secondary source")
            return False
        
        secondary_sources = []
        try:
            secondary_sources = json.loads(row['sources_secondary'] or '[]')
        except (json.JSONDecodeError, TypeError):
            secondary_sources = []
        
        # Check if source already exists
        if any(s.get('name') == source_name for s in secondary_sources):
            print(f"⚠️ {source_name} already in secondary sources for {cve_id}")
            return False
        
        # Add new secondary source
        now_utc = datetime.now(pytz.UTC).isoformat()
        secondary_sources.append({
            'name': source_name,
            'added_at': now_utc,
            'data_enrichment': data_enrichment
        })
        
        # Update database
        cursor.execute(
            "UPDATE cves SET sources_secondary = ? WHERE cve_id = ?",
            (json.dumps(secondary_sources), cve_id)
        )
        
        print(f"✅ Added {source_name} as secondary source for {cve_id}")
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

# Connect to database
conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 60)
print("Testing add_secondary_source Function")
print("=" * 60)

# Show current state before
print("\n1. Current state BEFORE add_secondary_source:")
cursor.execute("SELECT cve_id, source_primary, sources_secondary FROM cves ORDER BY cve_id")
for row in cursor.fetchall():
    secondary = json.loads(row['sources_secondary'])
    print(f"  {row['cve_id']}: primary={row['source_primary']}, secondary={len(secondary)} sources")

# Test adding secondary sources
print("\n2. Adding secondary sources (simulating what importers do):")

# Simulate CVEdetails finding CVE-2024-1001 which is primary NVD
print("\n  CVEdetails importer finds CVE-2024-1001 (primary: NVD):")
add_secondary_source(cursor, 'CVE-2024-1001', 'cvedetails', 'cvss_score,vendor_product')

# Simulate CVEdetails finding CVE-2024-1002 which is primary NVD
print("\n  CVEdetails importer finds CVE-2024-1002 (primary: NVD):")
add_secondary_source(cursor, 'CVE-2024-1002', 'cvedetails', 'cvss_score,vendor_product')

# Simulate CVE.org finding CVE-2024-1001
print("\n  CVE.org importer finds CVE-2024-1001 (primary: NVD, already has cvedetails):")
add_secondary_source(cursor, 'CVE-2024-1001', 'cveorg', 'vendor,product')

# Commit changes
conn.commit()

# Show state after
print("\n3. Current state AFTER add_secondary_source:")
cursor.execute("SELECT cve_id, source_primary, sources_secondary FROM cves ORDER BY cve_id")
for row in cursor.fetchall():
    secondary = json.loads(row['sources_secondary'])
    secondary_names = [s['name'] for s in secondary] if secondary else []
    print(f"  {row['cve_id']}: primary={row['source_primary']}, secondary={secondary_names}")

# Check for CVEs with multiple sources
print("\n4. CVEs with multiple sources:")
cursor.execute("SELECT cve_id, source_primary, sources_secondary FROM cves WHERE sources_secondary != '[]'")
count = 0
for row in cursor.fetchall():
    secondary = json.loads(row['sources_secondary'])
    if secondary:
        secondary_names = [s['name'] for s in secondary]
        print(f"  {row['cve_id']}: {row['source_primary']} + {secondary_names}")
        count += 1

print(f"\nTotal CVEs with secondary sources: {count}")

conn.close()
print("\n" + "=" * 60)
print("✅ Test completed!")
