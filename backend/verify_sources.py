import sqlite3
import json

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Check source_primary distribution
cursor.execute('SELECT source_primary, COUNT(*) FROM cves GROUP BY source_primary ORDER BY COUNT(*) DESC')
results = cursor.fetchall()
print('=== CVE Distribution by Primary Source ===')
for source, count in results:
    print(f'{source}: {count} CVEs')

print()

# Check a few CVEs from each source
for source_name in ['cvedetails', 'NVD', 'TEST']:
    cursor.execute('SELECT cve_id, source_primary, sources_secondary FROM cves WHERE source_primary = ? LIMIT 3', (source_name,))
    results = cursor.fetchall()
    if results:
        print(f'=== Sample CVEs from {source_name} ===')
        for cve_id, source_primary, sources_secondary in results:
            try:
                secondary = json.loads(sources_secondary) if sources_secondary else []
                print(f'{cve_id}: primary={source_primary}, secondary_count={len(secondary)}')
            except:
                print(f'{cve_id}: primary={source_primary}, secondary={sources_secondary}')
        print()

conn.close()
