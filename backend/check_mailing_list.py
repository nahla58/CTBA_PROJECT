import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Vérifier la mailing list EUROPE
cursor.execute("SELECT id, region_name, email, full_name, role FROM mailing_lists WHERE region_name='EUROPE'")
results = cursor.fetchall()

print('=== Mailing list EUROPE ===')
for r in results:
    print(f'ID {r[0]}: {r[2]} | {r[3]} | {r[4]}')

print(f'\nTotal: {len(results)} emails')

# Vérifier la table regions
cursor.execute("SELECT name, recipients FROM regions WHERE name='EUROPE'")
region = cursor.fetchone()
print(f'\n=== Table regions ===')
print(f'EUROPE: {region[1]}')

conn.close()
