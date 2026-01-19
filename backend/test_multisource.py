#!/usr/bin/env python3
"""
Quick test to verify CVE Details importer is working with multi-source support
"""
import sqlite3
import os

# First, let's back up the current database and test with a fresh one
db_path = 'ctba_platform.db'

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check current CVEs by source
print("=" * 70)
print("CVEs by source BEFORE CVE Details fix:")
print("=" * 70)
cursor.execute('''
    SELECT source, COUNT(*) as count FROM cves GROUP BY source
''')
for row in cursor.fetchall():
    print(f"  {row[0]:20} : {row[1]}")

# Now manually test the multi-source feature
print("\n" + "=" * 70)
print("Testing multi-source source field:")
print("=" * 70)

# Simulate what the CVE Details importer will do
test_cve_id = 'CVE-2026-23829'  # This CVE exists in NVD
cursor.execute("SELECT id, source FROM cves WHERE cve_id = ?", (test_cve_id,))
result = cursor.fetchone()

if result:
    cve_id_db, current_source = result
    print(f"\nTest CVE: {test_cve_id}")
    print(f"  Current source: {current_source}")
    
    # Build combined source
    sources = set()
    if current_source:
        sources.update(current_source.split(','))
    sources.add('cvedetails')
    combined_source = ','.join(sorted(sources))
    
    print(f"  After adding cvedetails: {combined_source}")
    print(f"  Would display as multiple badges: {', '.join(sorted(sources))}")
else:
    print(f"\n{test_cve_id} not found in database")

conn.close()
