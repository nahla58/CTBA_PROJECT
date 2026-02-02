import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Check tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('regions', 'region_mailing_lists', 'bulletins')")
tables = [r[0] for r in cursor.fetchall()]
print(f"📋 Tables trouvées: {tables}")

# Check regions
cursor.execute('SELECT COUNT(*) FROM regions')
regions_count = cursor.fetchone()[0]
print(f"🌍 Régions: {regions_count}")

if regions_count > 0:
    cursor.execute('SELECT id, name, description FROM regions LIMIT 3')
    for row in cursor.fetchall():
        print(f"  - {row[1]} (ID: {row[0]})")

# Check mailing lists
cursor.execute('SELECT COUNT(*) FROM region_mailing_lists')
mailing_count = cursor.fetchone()[0]
print(f"📧 Mailing lists: {mailing_count}")

if mailing_count > 0:
    cursor.execute('SELECT region_id, region_name, to_recipients FROM region_mailing_lists LIMIT 3')
    for row in cursor.fetchall():
        print(f"  - {row[1]}: {row[2][:50]}...")

# Check bulletins
cursor.execute('SELECT COUNT(*) FROM bulletins')
bulletins_count = cursor.fetchone()[0]
print(f"📄 Bulletins: {bulletins_count}")

conn.close()
print("\n✅ Vérification terminée")
