"""
Check CVE-2026-25202 in database
"""
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# List all tables
print("📊 Tables dans la base de données:")
tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
for table in tables:
    print(f"  - {table[0]}")

print("\n🔍 Recherche de CVE-2026-25202...")

# Try to find the CVE
try:
    result = cursor.execute("""
        SELECT cve_id, severity, cvss_score, status, source, 
               substr(description, 1, 150) as desc_short
        FROM cves 
        WHERE cve_id = 'CVE-2026-25202'
    """).fetchone()
    
    if result:
        print("\n✅ CVE trouvé dans la base de données:")
        print(f"  ID: {result[0]}")
        print(f"  Severity: {result[1]}")
        print(f"  Score CVSS: {result[2]}")
        print(f"  Status: {result[3]}")
        print(f"  Source: {result[4]}")
        print(f"  Description: {result[5]}...")
    else:
        print("\n❌ CVE-2026-25202 n'existe PAS dans la base de données")
        
        # Check how many CVEs we have total
        count = cursor.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        print(f"\n📊 Total CVEs dans la base: {count}")
        
        # Show some recent CVEs
        print("\n📋 Derniers CVEs dans la base:")
        recent = cursor.execute("""
            SELECT cve_id, severity, cvss_score 
            FROM cves 
            ORDER BY id DESC 
            LIMIT 10
        """).fetchall()
        for cve in recent:
            print(f"  - {cve[0]} | {cve[1]} | Score: {cve[2]}")

except sqlite3.OperationalError as e:
    print(f"\n❌ Erreur: {e}")
    print("\nℹ️ La table 'cves' n'existe probablement pas dans cette base de données")

conn.close()
