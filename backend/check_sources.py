import sqlite3
import json

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check CVEs by source (the actual column name)
cursor.execute('SELECT source, COUNT(*) as count FROM cves GROUP BY source ORDER BY count DESC')
print('CVEs by source:')
for row in cursor.fetchall():
    print(f'  {row["source"]}: {row["count"]}')

# Check total CVEs
cursor.execute('SELECT COUNT(*) FROM cves')
total = cursor.fetchone()[0]
print(f'\nTotal CVEs in database: {total}')

# Check CVEs with secondary sources
cursor.execute('SELECT COUNT(*) FROM cves WHERE sources_secondary != "[]"')
with_secondary = cursor.fetchone()[0]
print(f'CVEs with secondary sources: {with_secondary}')

# Show first 5 with secondary sources
print('\nFirst 5 CVEs with secondary sources:')
cursor.execute('SELECT cve_id, source_primary, sources_secondary FROM cves WHERE sources_secondary != "[]" LIMIT 5')
for row in cursor.fetchall():
    try:
        secondary_list = json.loads(row['sources_secondary'])
        secondary_names = [s.get('name') if isinstance(s, dict) else s for s in secondary_list]
        print(f'  {row["cve_id"]}: primary={row["source_primary"]}, secondary={secondary_names}')
    except:
        print(f'  {row["cve_id"]}: primary={row["source_primary"]}, secondary=[parse error]')

# Show distribution across sources
print('\nCVEs by source and those that could have secondary sources:')
cursor.execute('SELECT source_primary, COUNT(*) as total, SUM(CASE WHEN sources_secondary != "[]" THEN 1 ELSE 0 END) as with_secondary FROM cves GROUP BY source_primary ORDER BY total DESC')
for row in cursor.fetchall():
    print(f'  {row["source_primary"]}: {row["total"]} total, {row["with_secondary"] or 0} with secondary')

conn.close()
