import sqlite3
from datetime import datetime, timedelta

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Check published_date for CVE-2026-25069
cursor.execute('SELECT cve_id, published_date, status, severity FROM cves WHERE cve_id = ?', ('CVE-2026-25069',))
result = cursor.fetchone()

print("CVE-2026-25069 Info:")
print(f"  CVE: {result[0]}")
print(f"  Published Date: {result[1]}")
print(f"  Status: {result[2]}")
print(f"  Severity: {result[3]}")

# Check if it passes the 7-day filter
now_utc = datetime.utcnow()
days_7_ago = now_utc - timedelta(days=7)
cutoff_date = days_7_ago.strftime('%Y-%m-%dT%H:%M:%S')

print(f"\nCurrent UTC time: {now_utc}")
print(f"7 days ago: {cutoff_date}")
print(f"CVE published: {result[1]}")

# Parse published date
try:
    published = datetime.strptime(result[1], '%Y-%m-%d %H:%M:%S')
    is_recent = published >= days_7_ago
    print(f"Is within 7 days? {is_recent}")
except:
    print(f"Could not parse date")

# Test the exact query the API uses
print("\n" + "="*80)
print("Testing API query logic:")
print("="*80)

query = """
SELECT cve_id, published_date, status, severity 
FROM cves 
WHERE 1=1 
  AND published_date >= ?
  AND status = 'PENDING'
  AND severity IN ('CRITICAL', 'HIGH')
  AND cve_id = 'CVE-2026-25069'
"""

cursor.execute(query, (cutoff_date,))
result = cursor.fetchone()

if result:
    print(f"✅ CVE-2026-25069 PASSES ALL FILTERS")
    print(f"   {result}")
else:
    print(f"❌ CVE-2026-25069 FAILS FILTERS")
    
    # Test each filter individually
    print("\nTesting filters individually:")
    
    cursor.execute("SELECT cve_id FROM cves WHERE cve_id = 'CVE-2026-25069'")
    print(f"  Base query: {cursor.fetchone() is not None}")
    
    cursor.execute("SELECT cve_id FROM cves WHERE cve_id = 'CVE-2026-25069' AND published_date >= ?", (cutoff_date,))
    print(f"  Date filter (>= {cutoff_date}): {cursor.fetchone() is not None}")
    
    cursor.execute("SELECT cve_id FROM cves WHERE cve_id = 'CVE-2026-25069' AND status = 'PENDING'")
    print(f"  Status filter (PENDING): {cursor.fetchone() is not None}")
    
    cursor.execute("SELECT cve_id FROM cves WHERE cve_id = 'CVE-2026-25069' AND severity IN ('CRITICAL', 'HIGH')")
    print(f"  Severity filter (CRITICAL, HIGH): {cursor.fetchone() is not None}")

conn.close()

print("\n" + "="*80)
print("SOLUTION:")
print("="*80)
print("Le backend doit être REDÉMARRÉ pour prendre en compte les changements!")
print("1. Arrêter le backend (Ctrl+C dans le terminal python)")
print("2. Redémarrer: python main.py")
print("3. Retester l'API")
