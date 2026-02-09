import sqlite3
c = sqlite3.connect('ctba_platform.db')
r = c.execute('SELECT COUNT(*) FROM cves WHERE source LIKE "%msrc%"').fetchone()
print(f'{r[0]} CVEs MSRC en base')
c.close()
