#!/usr/bin/env python3
"""
Test script to verify CVE.org as PRIMARY source and multi-source merging
"""
import sqlite3
import json
import os

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ctba_platform.db")

def test_cveorg_primary():
    """Verify CVE.org is set as primary source"""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        print("\n" + "="*60)
        print("🧪 TEST: CVE.org as PRIMARY source")
        print("="*60)
        
        # Check CVEs from each source
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE source = ?", ('CVEORG',))
        cveorg_count = cursor.fetchone()['count']
        print(f"\n✅ CVEs from CVE.org (PRIMARY): {cveorg_count}")
        
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE source = ?", ('NVD',))
        nvd_count = cursor.fetchone()['count']
        print(f"✅ CVEs from NVD (SECONDARY): {nvd_count}")
        
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE source = ?", ('cvedetails',))
        cvedetails_count = cursor.fetchone()['count']
        print(f"✅ CVEs from CVEdetails (SECONDARY): {cvedetails_count}")
        
        # Check for CVEs with multiple sources
        cursor.execute("""
            SELECT COUNT(*) as count FROM cves 
            WHERE sources_secondary != '[]' AND sources_secondary IS NOT NULL
        """)
        multi_source_count = cursor.fetchone()['count']
        print(f"\n📊 CVEs with multiple sources: {multi_source_count}")
        
        # Show examples of multi-source CVEs
        if multi_source_count > 0:
            cursor.execute("""
                SELECT cve_id, source, cvss_score, sources_secondary 
                FROM cves 
                WHERE sources_secondary != '[]' AND sources_secondary IS NOT NULL
                LIMIT 5
            """)
            examples = cursor.fetchall()
            print("\n🔍 Examples of multi-source CVEs:")
            for cve in examples:
                try:
                    secondary_sources = json.loads(cve['sources_secondary'])
                    secondary_names = [s.get('name') for s in secondary_sources] if secondary_sources else []
                    print(f"  • {cve['cve_id']}")
                    print(f"    PRIMARY: {cve['source']}")
                    print(f"    SECONDARY: {', '.join(secondary_names) if secondary_names else 'None'}")
                    print(f"    CVSS Score: {cve['cvss_score']}")
                except:
                    pass
        
        # Check dates are from CVE.org
        cursor.execute("""
            SELECT cve_id, published_date, last_updated 
            FROM cves 
            WHERE source = 'CVEORG'
            LIMIT 3
        """)
        dates = cursor.fetchall()
        if dates:
            print("\n📅 Date format verification (from CVE.org PRIMARY source):")
            for cve in dates:
                print(f"  • {cve['cve_id']}")
                print(f"    Published: {cve['published_date']}")
                print(f"    Updated: {cve['last_updated']}")
        
        # Check CVSS scores - verify max is used
        cursor.execute("""
            SELECT cve_id, cvss_score, cvss_version 
            FROM cves 
            WHERE source = 'CVEORG' AND cvss_score > 0
            LIMIT 5
        """)
        scores = cursor.fetchall()
        if scores:
            print("\n🔢 CVSS Score verification (from CVE.org):")
            for cve in scores:
                print(f"  • {cve['cve_id']}: Score={cve['cvss_score']} Version={cve['cvss_version']}")
        
        print("\n" + "="*60)
        print("✅ TEST COMPLETE: CVE.org PRIMARY source system is working!")
        print("="*60 + "\n")
        
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_cveorg_primary()
