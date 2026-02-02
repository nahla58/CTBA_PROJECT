import sqlite3
from datetime import datetime, timedelta

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Total CVEs
cursor.execute('SELECT COUNT(*) FROM cves')
print(f'✅ Total CVEs dans la base: {cursor.fetchone()[0]}')

# Par sévérité
cursor.execute('SELECT severity, COUNT(*) FROM cves GROUP BY severity')
print('\n📊 Par sévérité:')
for row in cursor.fetchall():
    print(f'  {row[0]}: {row[1]}')

# Par status
cursor.execute('SELECT status, COUNT(*) FROM cves GROUP BY status')
print('\n📋 Par status:')
for row in cursor.fetchall():
    print(f'  {row[0]}: {row[1]}')

# Dates de publication
cursor.execute('SELECT published_date FROM cves ORDER BY published_date DESC LIMIT 5')
print('\n📅 5 dernières dates de publication:')
for row in cursor.fetchall():
    print(f'  {row[0]}')

# Test filtre actuel (7 jours + MEDIUM/HIGH + PENDING)
now_utc = datetime.utcnow()
days_7_ago = now_utc - timedelta(days=7)
cutoff_date = days_7_ago.strftime('%Y-%m-%dT%H:%M:%S')

cursor.execute("""
    SELECT COUNT(*) FROM cves 
    WHERE published_date >= ? 
    AND status = 'PENDING' 
    AND severity IN ('MEDIUM', 'HIGH')
""", (cutoff_date,))

print(f'\n🔍 CVEs avec filtres actuels (7 jours + MEDIUM/HIGH + PENDING): {cursor.fetchone()[0]}')

# Sans filtre de date
cursor.execute("""
    SELECT COUNT(*) FROM cves 
    WHERE status = 'PENDING' 
    AND severity IN ('MEDIUM', 'HIGH')
""")
print(f'🔍 CVEs MEDIUM/HIGH + PENDING (sans filtre date): {cursor.fetchone()[0]}')

conn.close()
