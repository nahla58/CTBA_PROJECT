import sqlite3

c = sqlite3.connect('ctba_platform.db')
rows = c.execute('SELECT severity, COUNT(*) FROM cves WHERE source LIKE "%msrc%" GROUP BY severity').fetchall()
print('\nSévérités des CVEs MSRC:')
for r in rows:
    print(f'  {r[0]}: {r[1]} CVEs')

# Total CVEs MSRC HIGH et CRITICAL
high_critical = c.execute('SELECT COUNT(*) FROM cves WHERE source LIKE "%msrc%" AND severity IN ("HIGH", "CRITICAL")').fetchone()
print(f'\n✅ Total HIGH + CRITICAL: {high_critical[0]} CVEs MSRC')
c.close()
