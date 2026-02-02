#!/usr/bin/env python3
"""
FIX CVSS SCORES properly - assign based on severity from NVD averages
"""
import sqlite3

DB_PATH = 'ctba_platform.db'
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 80)
print("FIXING CVSS SCORES FOR CVEdetails")
print("=" * 80)

# Get average CVSS per severity from sources that have CVSS
cursor.execute("""
    SELECT severity, AVG(CAST(cvss_score AS FLOAT)) as avg_cvss, COUNT(*) as count
    FROM cves
    WHERE cvss_score > 0 AND status = 'PENDING'
    GROUP BY severity
    ORDER BY severity
""")

severity_avgs = {}
print("\nAverage CVSS by Severity (from all sources with CVSS > 0):")
for row in cursor.fetchall():
    severity = row['severity']
    avg = row['avg_cvss']
    count = row['count']
    severity_avgs[severity] = avg
    print(f"  {severity:10} | Avg: {avg:5.2f} | Count: {count}")

if not severity_avgs:
    print("❌ No CVSS averages found. Using default mapping.")
    severity_avgs = {
        'CRITICAL': 9.0,
        'HIGH': 7.5,
        'MEDIUM': 5.0,
        'LOW': 2.5
    }

# Update CVEs with CVSS = 0 using severity average
cursor.execute("""
    SELECT id, cve_id, severity FROM cves
    WHERE cvss_score = 0.0 AND status = 'PENDING'
""")

zeros = cursor.fetchall()
print(f"\nUpdating {len(zeros)} CVEs with CVSS = 0...")

updated = 0
for row in zeros:
    cve_id = row['cve_id']
    severity = row['severity']
    avg_cvss = severity_avgs.get(severity, 5.0)
    
    cursor.execute(
        "UPDATE cves SET cvss_score = ? WHERE id = ?",
        (avg_cvss, row['id'])
    )
    updated += 1
    if updated <= 10:
        print(f"  {cve_id}: {severity} = {avg_cvss}")

conn.commit()
print(f"\n✅ Updated {updated} CVEs")

# Verify
cursor.execute("""
    SELECT source_primary, COUNT(*) as total, AVG(CAST(cvss_score AS FLOAT)) as avg_cvss
    FROM cves
    WHERE status = 'PENDING'
    GROUP BY source_primary
""")

print("\n" + "=" * 80)
print("VERIFICATION AFTER FIX")
print("=" * 80)
for row in cursor.fetchall():
    print(f"{row['source_primary']:12} | Count: {row['total']:3} | Avg CVSS: {row['avg_cvss']:6.2f}")

conn.close()
print("\n✅ Done!")
