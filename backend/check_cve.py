import sqlite3

conn = sqlite3.connect('ctba.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check if the specific CVE exists
cursor.execute('SELECT cve_id, status, severity, cvss_score FROM cves WHERE cve_id = ?', ('CVE-2026-1324',))
row = cursor.fetchone()

if row:
    print('CVE trouvé:')
    print(f'  ID: {row["cve_id"]}')
    print(f'  Status: {row["status"]}')
    print(f'  Severity: {row["severity"]}')
    print(f'  CVSS Score: {row["cvss_score"]}')
else:
    print('CVE-2026-1324 n\'existe pas en base de données')
    
print('\nDerniers CVEs importés:')
cursor.execute('SELECT cve_id, status, severity, cvss_score FROM cves ORDER BY published_date DESC LIMIT 10')
for r in cursor.fetchall():
    print(f'  {r["cve_id"]}: status={r["status"]}, severity={r["severity"]}, cvss={r["cvss_score"]}')

print('\n--- Statistiques par Status ---')
cursor.execute('SELECT status, COUNT(*) as count FROM cves GROUP BY status')
for r in cursor.fetchall():
    print(f'  {r["status"]}: {r["count"]} CVEs')

conn.close()
