import sqlite3
conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check users
cursor.execute('SELECT * FROM users LIMIT 3')
users = cursor.fetchall()
print("=== USERS ===")
for u in users:
    print(f"  {u['username']} - {u['role']}")

# Check CVEs
cursor.execute('SELECT COUNT(*) as count FROM cves')
cve_count = cursor.fetchone()
print(f"\n=== CVEs ===")
print(f"  Total CVEs: {cve_count['count']}")

cursor.execute('SELECT cve_id, severity, status FROM cves LIMIT 3')
cves = cursor.fetchall()
print("  First 3 CVEs:")
for c in cves:
    print(f"    {c['cve_id']} - {c['severity']} - {c['status']}")

conn.close()
