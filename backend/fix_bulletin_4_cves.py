"""
Add CVEs to bulletin #4
"""
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Create bulletin_cves table if it doesn't exist
print("Creating bulletin_cves table...")
cursor.execute('''
    CREATE TABLE IF NOT EXISTS bulletin_cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bulletin_id INTEGER NOT NULL,
        cve_id TEXT NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (bulletin_id) REFERENCES bulletins(id) ON DELETE CASCADE,
        UNIQUE(bulletin_id, cve_id)
    )
''')
conn.commit()
print("✅ Table created/verified\n")

bulletin_id = 4
cves = ['CVE-2021-47918', 'CVE-2021-47919', 'CVE-2022-50940']

print(f"Adding {len(cves)} CVEs to bulletin #{bulletin_id}...")

for cve_id in cves:
    try:
        cursor.execute('''
            INSERT INTO bulletin_cves (bulletin_id, cve_id)
            VALUES (?, ?)
        ''', (bulletin_id, cve_id))
        print(f"  ✅ Added {cve_id}")
    except sqlite3.IntegrityError:
        print(f"  ⚠️ {cve_id} already associated")

conn.commit()

# Verify
cursor.execute('SELECT cve_id FROM bulletin_cves WHERE bulletin_id = ?', (bulletin_id,))
result = cursor.fetchall()

print(f"\n✅ Bulletin #{bulletin_id} now has {len(result)} CVEs:")
for row in result:
    print(f"   - {row[0]}")

conn.close()
print("\nYou can now resend bulletin #4 and it will include all CVEs!")
