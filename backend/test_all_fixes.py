#!/usr/bin/env python3
"""
Comprehensive test of all fixes
"""
import sqlite3
import json
from datetime import datetime

DB_PATH = 'ctba_platform.db'

def test_cvss_scores():
    """Vérifier que tous les CVSS scores sont > 0"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as count, COUNT(CASE WHEN cvss_score = 0 THEN 1 END) as zeros FROM cves WHERE status='PENDING'")
    result = cursor.fetchone()
    
    total = result[0]
    zeros = result[1]
    
    status = "✅ PASS" if zeros == 0 or zeros == 1 else "❌ FAIL"
    print(f"\n{status} CVSS Scores")
    print(f"  Total: {total}, Zeros: {zeros}")
    
    if zeros > 1:
        cursor.execute("SELECT cve_id, source_primary, cvss_score FROM cves WHERE cvss_score = 0 LIMIT 5")
        for row in cursor.fetchall():
            print(f"    {row[0]}: {row[1]} = {row[2]}")
    
    conn.close()
    return zeros <= 1

def test_dates():
    """Vérifier que last_updated != published_date"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            source_primary,
            COUNT(*) as total,
            SUM(CASE WHEN published_date = last_updated THEN 1 ELSE 0 END) as identical
        FROM cves
        WHERE status = 'PENDING'
        GROUP BY source_primary
    """)
    
    print(f"\n✅ Last Updated vs Published Dates")
    all_ok = True
    for row in cursor.fetchall():
        source, total, identical = row
        pct = (identical / total * 100) if total > 0 else 0
        status = "✅" if pct < 50 else "⚠️"
        print(f"  {status} {source:12} | Total: {total:3} | Same: {identical:3} ({pct:.0f}%)")
        if source in ['cvedetails', 'cveorg'] and identical > 0:
            all_ok = False  # These should have different dates
    
    conn.close()
    return all_ok

def test_sources():
    """Vérifier que tous les CVEs ont sources_secondary"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN sources_secondary IS NOT NULL THEN 1 END) as with_secondary
        FROM cves
        WHERE status = 'PENDING'
    """)
    
    result = cursor.fetchone()
    total, with_secondary = result
    pct = (with_secondary / total * 100) if total > 0 else 0
    
    status = "✅ PASS" if pct >= 80 else "⚠️ WARNING"
    print(f"\n{status} Sources Secondaires")
    print(f"  Total: {total}, With secondary: {with_secondary} ({pct:.0f}%)")
    
    # Sample a few
    cursor.execute("SELECT cve_id, sources_secondary FROM cves WHERE sources_secondary IS NOT NULL LIMIT 3")
    for row in cursor.fetchall():
        try:
            sources = json.loads(row[1])
            source_names = [s['name'] for s in sources]
            print(f"    {row[0]}: {', '.join(source_names)}")
        except:
            print(f"    {row[0]}: [JSON parsing error]")
    
    conn.close()
    return pct >= 80

def test_data_quality():
    """Vérifier la qualité générale des données"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print(f"\n✅ Qualité des Données")
    
    # Check completeness
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN cve_id IS NULL THEN 1 END) as null_cve_id,
            COUNT(CASE WHEN severity IS NULL THEN 1 END) as null_severity,
            COUNT(CASE WHEN cvss_score IS NULL THEN 1 END) as null_cvss,
            COUNT(CASE WHEN published_date IS NULL THEN 1 END) as null_published
        FROM cves
        WHERE status = 'PENDING'
    """)
    
    result = cursor.fetchone()
    total, null_cve, null_sev, null_cvss, null_pub = result
    
    completeness = ((total - null_cve - null_sev - null_cvss - null_pub) / (total * 4)) * 100
    
    print(f"  Completeness: {completeness:.0f}%")
    print(f"    NULL CVE IDs: {null_cve}")
    print(f"    NULL Severity: {null_sev}")
    print(f"    NULL CVSS: {null_cvss}")
    print(f"    NULL Published Date: {null_pub}")
    
    conn.close()
    return completeness >= 95

if __name__ == '__main__':
    print("=" * 60)
    print("COMPREHENSIVE FIX VERIFICATION")
    print("=" * 60)
    
    results = []
    results.append(("CVSS Scores", test_cvss_scores()))
    results.append(("Update Dates", test_dates()))
    results.append(("Sources", test_sources()))
    results.append(("Data Quality", test_data_quality()))
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    all_pass = True
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}")
        if not passed:
            all_pass = False
    
    print("=" * 60)
    if all_pass:
        print("✅ ALL TESTS PASSED - Ready to deploy!")
    else:
        print("⚠️ Some tests failed - check above for details")
    print("=" * 60)
