import sqlite3
import json

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Test what columns are actually returned
cursor.execute("SELECT * FROM cves LIMIT 1")
row = cursor.fetchone()

if row:
    print("=== Columns returned from SELECT * ===")
    for key in row.keys():
        print(f"  - {key}")
    
    print()
    print("=== Sample CVE from cvedetails ===")
    cursor.execute("SELECT * FROM cves WHERE source_primary = 'cvedetails' LIMIT 1")
    sample = cursor.fetchone()
    if sample:
        d = dict(sample)
        print(f"cve_id: {d['cve_id']}")
        print(f"source: {d.get('source')}")
        print(f"source_primary: {d.get('source_primary')}")
        print(f"sources_secondary: {d.get('sources_secondary')}")

conn.close()
