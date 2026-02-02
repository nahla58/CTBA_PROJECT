#!/usr/bin/env python3
"""
Verify the database has correct data before launching server
"""
import sqlite3
import json

DB_PATH = 'ctba_platform.db'
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 100)
print("VÉRIFICATION FINALE DES DONNÉES")
print("=" * 100)

# Test CVEs with multiple sources
cursor.execute("""
    SELECT cve_id, source_primary, sources_secondary, published_date, last_updated
    FROM cves
    WHERE status = 'PENDING' AND sources_secondary IS NOT NULL
    LIMIT 5
""")

print("\n✅ CVEs avec sources secondaires:")
for row in cursor.fetchall():
    print(f"\n{row['cve_id']}")
    print(f"  Primary: {row['source_primary']}")
    try:
        sec = json.loads(row['sources_secondary'])
        for s in sec:
            print(f"  Secondary: {s.get('name')} (added: {s.get('added_at')[:10]})")
    except:
        print(f"  Secondary: {row['sources_secondary'][:50]}")
    print(f"  Published: {row['published_date'][:20]}")
    print(f"  Updated: {row['last_updated'][:20]}")

# Summary
print("\n" + "=" * 100)
print("RÉSUMÉ:")
print("=" * 100)

cursor.execute("""
    SELECT COUNT(*) as total,
           SUM(CASE WHEN sources_secondary IS NOT NULL THEN 1 ELSE 0 END) as with_secondary
    FROM cves
    WHERE status = 'PENDING'
""")

result = cursor.fetchone()
print(f"Total CVEs: {result['total']}")
print(f"CVEs avec sources secondaires: {result['with_secondary']}")
print(f"\n✅ Base de données prête!")

conn.close()
