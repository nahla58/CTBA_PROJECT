"""
Script to fix bulletin #2 by linking the 3 CVEs mentioned by the user
"""
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

bulletin_id = 2
cve_ids = ['CVE-2022-50940', 'CVE-2021-47919', 'CVE-2021-47918']

print(f"Linking CVEs to bulletin #{bulletin_id}...")

for cve_id in cve_ids:
    # Check if CVE exists
    cursor.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,))
    if cursor.fetchone():
        try:
            cursor.execute('''
                INSERT INTO bulletin_cves (bulletin_id, cve_id)
                VALUES (?, ?)
            ''', (bulletin_id, cve_id))
            print(f"  ✅ Linked {cve_id}")
        except sqlite3.IntegrityError:
            print(f"  ℹ️  {cve_id} already linked")
    else:
        print(f"  ❌ {cve_id} not found in database")

conn.commit()

# Verify
cursor.execute('''
    SELECT bc.cve_id, c.severity, c.cvss_score 
    FROM bulletin_cves bc
    JOIN cves c ON bc.cve_id = c.cve_id
    WHERE bc.bulletin_id = ?
''', (bulletin_id,))

results = cursor.fetchall()
print(f"\n✅ Bulletin #{bulletin_id} now has {len(results)} CVE(s):")
for row in results:
    print(f"  - {row[0]} ({row[1]}, CVSS: {row[2]})")

conn.close()
