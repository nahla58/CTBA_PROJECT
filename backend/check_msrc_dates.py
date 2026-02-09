import sqlite3
from datetime import datetime

c = sqlite3.connect('ctba_platform.db')
rows = c.execute('''
    SELECT cve_id, published_date, imported_at, status, source 
    FROM cves 
    WHERE source LIKE "%msrc%" 
    ORDER BY published_date DESC 
    LIMIT 10
''').fetchall()

print('\n📅 Dates des CVEs MSRC:')
print('-' * 80)
for r in rows:
    pub_date = r[1] if r[1] else 'N/A'
    import_date = r[2] if r[2] else 'N/A'
    print(f'{r[0]}: publié={pub_date}, importé={import_date}, status={r[3]}')

# Compter par statut
statuses = c.execute('SELECT status, COUNT(*) FROM cves WHERE source LIKE "%msrc%" GROUP BY status').fetchall()
print('\n📊 CVEs MSRC par statut:')
for s in statuses:
    print(f'  {s[0]}: {s[1]} CVEs')

c.close()
