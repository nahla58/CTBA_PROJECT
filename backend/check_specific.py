import sqlite3

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check specific CVEs from the screenshot
cve_ids = ['CVE-2026-1283', 'CVE-2016-15057', 'CVE-2025-59109']
placeholders = ','.join(['?' * len(cve_ids)])
query = f"SELECT cve_id, published_date, last_updated, source_primary FROM cves WHERE cve_id IN ({','.join(['?' for _ in cve_ids])})"
cursor.execute(query, cve_ids)
rows = cursor.fetchall()

for row in rows:
    print(f"{row['cve_id']}:")
    print(f"  pub: {row['published_date']}")
    print(f"  upd: {row['last_updated']}")
    print(f"  src: {row['source_primary']}")
    print()

conn.close()
