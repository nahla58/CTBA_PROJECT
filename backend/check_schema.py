import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Get table schema
cursor.execute("PRAGMA table_info(cves)")
columns = cursor.fetchall()

print("📋 Structure de la table 'cves':\n")
for col in columns:
    print(f"  {col[1]} ({col[2]})")

conn.close()
