#!/usr/bin/env python3
"""
Vérifier que last_updated est différent de published_date
"""
import sqlite3

DB_PATH = 'ctba_platform.db'
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 120)
print("VÉRIFICATION: published_date vs last_updated")
print("=" * 120)

# Vérifier si last_updated == published_date (problème)
cursor.execute("""
    SELECT cve_id, source_primary, published_date, last_updated,
           CASE WHEN published_date = last_updated THEN 'IDENTIQUE' 
                ELSE 'DIFFÉRENT' END as date_relation
    FROM cves
    WHERE status = 'PENDING'
    ORDER BY source_primary, cve_id
    LIMIT 20
""")

print(f"\n{'CVE ID':20} | {'Source':12} | {'Published Date':25} | {'Last Updated':25} | Status")
print("-" * 120)

for row in cursor.fetchall():
    pub = row['published_date'][:20] if row['published_date'] else 'NULL'
    upd = row['last_updated'][:20] if row['last_updated'] else 'NULL'
    status = row['date_relation']
    print(f"{row['cve_id']:20} | {row['source_primary']:12} | {pub:25} | {upd:25} | {status}")

# Statistiques
print("\n" + "=" * 120)
print("STATISTIQUES")
print("=" * 120)

cursor.execute("""
    SELECT source_primary,
           COUNT(*) as total,
           SUM(CASE WHEN published_date = last_updated THEN 1 ELSE 0 END) as identiques,
           SUM(CASE WHEN published_date != last_updated THEN 1 ELSE 0 END) as differents
    FROM cves
    WHERE status = 'PENDING'
    GROUP BY source_primary
""")

print(f"\n{'Source':15} | {'Total':5} | {'Identiques':10} | {'Différents':10}")
print("-" * 60)

for row in cursor.fetchall():
    print(f"{row['source_primary']:15} | {row['total']:5} | {row['identiques']:10} | {row['differents']:10}")

# Vérifier les sources_secondary
print("\n" + "=" * 120)
print("SOURCES SECONDAIRES")
print("=" * 120)

cursor.execute("""
    SELECT cve_id, source_primary, sources_secondary, source
    FROM cves
    WHERE status = 'PENDING' AND (sources_secondary IS NOT NULL OR source LIKE '%,%')
    LIMIT 10
""")

for row in cursor.fetchall():
    print(f"\n{row['cve_id']:15}")
    print(f"  source_primary: {row['source_primary']}")
    print(f"  sources_secondary: {row['sources_secondary']}")
    print(f"  source (combined): {row['source']}")

conn.close()
