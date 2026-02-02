import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

print("=== CVEs créés par CVE.org ===")
cursor.execute("SELECT cve_id, source_primary FROM cves WHERE source_primary = 'cveorg' LIMIT 10")
rows = cursor.fetchall()
print(f"Nombre de CVEs avec source_primary='cveorg': {len(rows)}")
for row in rows:
    print(row)

print("\n=== Total CVEs dans la base ===")
cursor.execute("SELECT COUNT(*) FROM cves")
print(f"Total: {cursor.fetchone()[0]}")

print("\n=== Distribution par source_primary ===")
cursor.execute("SELECT source_primary, COUNT(*) FROM cves GROUP BY source_primary")
for row in cursor.fetchall():
    print(f"{row[0]}: {row[1]}")

conn.close()
