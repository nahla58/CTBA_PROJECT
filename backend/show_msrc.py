import sqlite3
c = sqlite3.connect('ctba_platform.db')
rows = c.execute('SELECT cve_id, source FROM cves WHERE source LIKE "%msrc%" LIMIT 5').fetchall()
print('\nExemples de CVEs MSRC:')
for r in rows:
    print(f'  {r[0]}: {r[1]}')
c.close()
