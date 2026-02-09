import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Compter les CVEs avec source MSRC
cursor.execute("SELECT COUNT(*) FROM cves WHERE source LIKE '%msrc%'")
msrc_count = cursor.fetchone()[0]
print(f"CVEs avec source MSRC: {msrc_count}")

# Total CVEs
cursor.execute("SELECT COUNT(*) FROM cves")
total = cursor.fetchone()[0]
print(f"Total CVEs: {total}")

# Afficher quelques CVEs MSRC si ils existent
if msrc_count > 0:
    cursor.execute("SELECT cve_id, source FROM cves WHERE source LIKE '%msrc%' LIMIT 5")
    print("\nExemples de CVEs MSRC:")
    for row in cursor.fetchall():
        print(f"  - {row[0]}: {row[1]}")

conn.close()
