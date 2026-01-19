import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Check CVEs by source
cursor.execute('SELECT source, COUNT(*) as count FROM cves GROUP BY source')
print('CVEs by source:')
for row in cursor.fetchall():
    print(f'  {row[0]}: {row[1]}')

# Check total CVEs
cursor.execute('SELECT COUNT(*) FROM cves')
total = cursor.fetchone()[0]
print(f'\nTotal CVEs in database: {total}')

# Check what CVEs from CVE Details look like
print('\nCVEs from CVE Details:')
cursor.execute('SELECT cve_id, source FROM cves WHERE source=? LIMIT 10', ('cvedetails',))
rows = cursor.fetchall()
if rows:
    for row in rows:
        print(f'  {row[0]} ({row[1]})')
else:
    print('  (none found)')

# Show first 5 from NVD
print('\nFirst 5 CVEs from NVD:')
cursor.execute('SELECT cve_id, source FROM cves WHERE source=? LIMIT 5', ('nvd',))
for row in cursor.fetchall():
    print(f'  {row[0]} ({row[1]})')

conn.close()
