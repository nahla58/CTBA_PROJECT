import sqlite3

conn = sqlite3.connect('cves.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get sample CVEs with their dates
cursor.execute('''SELECT cve_id, published_date, last_updated FROM cves LIMIT 10''')
rows = cursor.fetchall()

for row in rows:
    print(f"{row['cve_id']}:")
    print(f"  published_date: {row['published_date']}")
    print(f"  last_updated: {row['last_updated']}")
    print()

conn.close()
