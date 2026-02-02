import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Check total PENDING CVEs
cursor.execute('SELECT COUNT(*) FROM cves WHERE status = ?', ('PENDING',))
count = cursor.fetchone()[0]
print(f'Total PENDING CVEs: {count}')

# Find CVE-2026-25069
cursor.execute('SELECT * FROM cves WHERE cve_id = ?', ('CVE-2026-25069',))
cve = cursor.fetchone()

if cve:
    print(f'\n✅ CVE-2026-25069 FOUND in database:')
    print(f'   ID: {cve[0]}')
    print(f'   CVE: {cve[1]}')
    print(f'   Severity: {cve[3]}')
    print(f'   CVSS: {cve[4]}')
    print(f'   Status: {cve[7]}')
    print(f'   Source: {cve[13]}')
    print(f'   Imported at: {cve[11]}')
else:
    print('\n❌ CVE-2026-25069 NOT FOUND')

# Show last 5 PENDING CVEs
print('\n📋 Last 5 PENDING CVEs in database:')
cursor.execute('SELECT cve_id, severity, cvss_score, imported_at FROM cves WHERE status = ? ORDER BY id DESC LIMIT 5', ('PENDING',))
for row in cursor.fetchall():
    marker = '👉' if row[0] == 'CVE-2026-25069' else '  '
    print(f'{marker} {row[0]} - {row[1]} (CVSS: {row[2]}) - imported: {row[3]}')

conn.close()

print('\n💡 If CVE is in database with PENDING status but not showing in dashboard:')
print('   1. Check frontend filters (severity, search)')
print('   2. Refresh the frontend page (hard refresh: Ctrl+F5)')
print('   3. Check browser console for API errors')
print('   4. Verify API endpoint: GET http://localhost:8000/api/cves?decision=PENDING')
