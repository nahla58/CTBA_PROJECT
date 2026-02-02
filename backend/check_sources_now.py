import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Count by source
cursor.execute('SELECT source_primary, COUNT(*) FROM cves GROUP BY source_primary ORDER BY COUNT(*) DESC')
print('=== CVE Count by Source ===')
for source, count in cursor.fetchall():
    print(f'{source}: {count}')

# Check if CVE-2026-24636 (from CVEdetails) exists
cursor.execute('SELECT cve_id, source_primary, source FROM cves WHERE cve_id = ?', ('CVE-2026-24636',))
result = cursor.fetchone()
if result:
    print(f'\nCVE-2026-24636 found: primary={result[1]}, source={result[2]}')
else:
    print('\nCVE-2026-24636 NOT found in database')

# List first 5 CVEs
print('\n=== First 5 CVEs ===')
cursor.execute('SELECT cve_id, source_primary FROM cves LIMIT 5')
for row in cursor.fetchall():
    print(f'{row[0]}: {row[1]}')

conn.close()
