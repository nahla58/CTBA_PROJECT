import sqlite3
conn = sqlite3.connect('ctba_platform.db')
c = conn.cursor()
c.execute('SELECT severity, COUNT(*), AVG(CAST(cvss_score AS FLOAT)) FROM cves WHERE source_primary="nvd" AND cvss_score > 0 GROUP BY severity')
for row in c.fetchall():
    print(f'{row[0]:10} | Count: {row[1]:3} | Avg CVSS: {row[2]:.2f}')
