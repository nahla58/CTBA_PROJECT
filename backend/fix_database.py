#!/usr/bin/env python3
"""
Fix dates and CVSS scores in database for consistent display
"""
import sqlite3
from datetime import datetime
import pytz

DB_PATH = 'ctba_platform.db'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 80)
print("FIXING DATES AND CVSS SCORES")
print("=" * 80)

# 1. Normalize all dates to ISO format with timezone
print("\n1. Normalizing dates...")

cursor.execute("SELECT id, cve_id, published_date FROM cves WHERE published_date IS NOT NULL")
rows = cursor.fetchall()

updated = 0
for row in rows:
    cve_id = row['cve_id']
    pub_date = row['published_date']
    
    # Skip if already in proper ISO format
    if '+' in pub_date or 'Z' in pub_date:
        continue
    
    # Dates like '2026-01-23 14:29:05' need timezone info
    if ' ' in pub_date and '+' not in pub_date and 'Z' not in pub_date:
        # This is a naive datetime, treat it as UTC
        pub_date_normalized = pub_date + '+00:00'
        cursor.execute("UPDATE cves SET published_date = ? WHERE id = ?", (pub_date_normalized, row['id']))
        updated += 1

conn.commit()
print(f"Updated {updated} published_date entries with timezone info")

# 2. Fix CVSS scores for CVEdetails (set them to average based on source avg or severity)
print("\n2. Assigning CVSS scores to CVEdetails CVEs...")

# Get average CVSS per severity from NVD
cursor.execute("""
    SELECT severity, AVG(CAST(cvss_score AS FLOAT)) as avg_cvss
    FROM cves
    WHERE source_primary = 'nvd' AND cvss_score > 0
    GROUP BY severity
""")

severity_avgs = {}
for row in cursor.fetchall():
    severity_avgs[row['severity']] = row['avg_cvss']

print(f"Average CVSS by severity (from NVD):")
for severity, avg in severity_avgs.items():
    print(f"  {severity}: {avg:.2f}")

# Update CVEdetails CVEs with 0 CVSS using average based on severity
cursor.execute("""
    SELECT id, cve_id, severity FROM cves
    WHERE source_primary = 'cvedetails' AND cvss_score = 0.0
""")

cvedetails_rows = cursor.fetchall()
for row in cvedetails_rows:
    severity = row['severity']
    avg_cvss = severity_avgs.get(severity, 5.0)  # Default to 5.0 if not found
    cursor.execute("UPDATE cves SET cvss_score = ? WHERE id = ?", (round(avg_cvss, 1), row['id']))
    print(f"  {row['cve_id']} ({severity}): {round(avg_cvss, 1)}")

conn.commit()
print(f"Updated {len(cvedetails_rows)} CVEdetails entries with estimated CVSS scores")

# 3. Ensure last_updated is set for all CVEs
print("\n3. Ensuring last_updated is set for all CVEs...")

cursor.execute("""
    UPDATE cves 
    SET last_updated = published_date 
    WHERE last_updated IS NULL AND published_date IS NOT NULL
""")

conn.commit()
rows_affected = cursor.rowcount
print(f"Updated {rows_affected} CVEs with published_date as last_updated")

# Verify the changes
print("\n" + "=" * 80)
print("VERIFICATION")
print("=" * 80)

cursor.execute("""
    SELECT source_primary, COUNT(*) as count, 
           AVG(CAST(cvss_score AS FLOAT)) as avg_cvss,
           COUNT(CASE WHEN cvss_score = 0 THEN 1 END) as zero_cvss
    FROM cves
    WHERE status = 'PENDING'
    GROUP BY source_primary
""")

for row in cursor.fetchall():
    print(f"{row['source_primary']:15} | Count: {row['count']:3} | Avg CVSS: {row['avg_cvss']:6.2f} | Zero CVSS: {row['zero_cvss']}")

# Show sample of dates
print("\nSample dates after fixes:")
cursor.execute("""
    SELECT cve_id, source_primary, published_date, last_updated FROM cves
    WHERE status = 'PENDING'
    ORDER BY source_primary, cve_id
    LIMIT 10
""")

for row in cursor.fetchall():
    print(f"{row['cve_id']:15} | {row['source_primary']:12} | Pub: {row['published_date'][:20]}")

conn.close()
print("\n✅ Database fixes completed!")
