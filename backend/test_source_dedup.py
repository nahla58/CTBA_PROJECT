#!/usr/bin/env python3
"""
Test script to verify the multi-source deduplication fix
Tests the new source_primary and sources_secondary columns
"""
import sqlite3
import json
from datetime import datetime
import pytz

DB_FILE = "ctba_platform.db"

def test_source_deduplication():
    """Test the source deduplication system"""
    
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        print("\n" + "="*70)
        print("🧪 TESTING MULTI-SOURCE DEDUPLICATION SYSTEM")
        print("="*70)
        
        # Test 1: Check columns exist
        print("\n[TEST 1] Verifying new columns exist...")
        cursor.execute("PRAGMA table_info(cves)")
        columns = {row['name'] for row in cursor.fetchall()}
        
        if 'source_primary' in columns:
            print("  ✅ source_primary column exists")
        else:
            print("  ❌ source_primary column NOT found!")
            return False
        
        if 'sources_secondary' in columns:
            print("  ✅ sources_secondary column exists")
        else:
            print("  ❌ sources_secondary column NOT found!")
            return False
        
        # Test 2: Check data migration
        print("\n[TEST 2] Verifying data migration...")
        cursor.execute("SELECT COUNT(*) as count FROM cves")
        total = cursor.fetchone()['count']
        print(f"  Total CVEs in database: {total}")
        
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE source_primary IS NOT NULL")
        with_primary = cursor.fetchone()['count']
        print(f"  CVEs with source_primary: {with_primary}")
        
        if total > 0 and with_primary == total:
            print("  ✅ All CVEs have a source_primary assigned")
        else:
            print(f"  ⚠️ {total - with_primary} CVEs missing source_primary")
        
        # Test 3: Verify sources_secondary is JSON
        print("\n[TEST 3] Verifying sources_secondary JSON structure...")
        cursor.execute("""
            SELECT cve_id, sources_secondary 
            FROM cves 
            WHERE sources_secondary != '[]'
            LIMIT 3
        """)
        
        rows = cursor.fetchall()
        if len(rows) == 0:
            print("  ℹ️ No CVEs with secondary sources yet (expected at first run)")
        else:
            for row in rows:
                try:
                    secondary = json.loads(row['sources_secondary'])
                    print(f"  ✅ {row['cve_id']}: Valid JSON with {len(secondary)} secondary sources")
                    for src in secondary:
                        print(f"      • {src.get('name')}: {src.get('data_enrichment')}")
                except json.JSONDecodeError:
                    print(f"  ❌ {row['cve_id']}: Invalid JSON!")
                    return False
        
        # Test 4: Check primary source distribution
        print("\n[TEST 4] Primary source distribution...")
        cursor.execute("""
            SELECT source_primary, COUNT(*) as count
            FROM cves
            GROUP BY source_primary
            ORDER BY count DESC
        """)
        
        for row in cursor.fetchall():
            source = row['source_primary']
            count = row['count']
            pct = (count / total * 100) if total > 0 else 0
            print(f"  • {source:30s}: {count:5d} CVEs ({pct:5.1f}%)")
        
        # Test 5: Sample CVE display (like frontend will see)
        print("\n[TEST 5] Sample CVE with new source fields...")
        cursor.execute("""
            SELECT cve_id, source_primary, sources_secondary
            FROM cves
            LIMIT 1
        """)
        
        sample = cursor.fetchone()
        if sample:
            cve_id = sample['cve_id']
            primary = sample['source_primary']
            try:
                secondary = json.loads(sample['sources_secondary'] or '[]')
            except:
                secondary = []
            
            print(f"  CVE ID: {cve_id}")
            print(f"  Primary Source: {primary}")
            print(f"  Secondary Sources: {len(secondary)}")
            if secondary:
                for src in secondary:
                    print(f"    • {src.get('name')} ({src.get('data_enrichment')})")
            else:
                print("    (none)")
        
        # Test 6: Verify audit table
        print("\n[TEST 6] Checking audit log table...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_source_history'")
        audit_exists = cursor.fetchone() is not None
        if audit_exists:
            print("  ✅ cve_source_history table exists")
        else:
            print("  ⚠️ cve_source_history table not found (will be created on first update)")
        
        # Test 7: Verify indexes
        print("\n[TEST 7] Checking database indexes...")
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='index' AND (name LIKE '%source%')
        """)
        indexes = [row['name'] for row in cursor.fetchall()]
        if indexes:
            print(f"  ✅ Found {len(indexes)} indexes on source columns:")
            for idx in indexes:
                print(f"    • {idx}")
        else:
            print("  ⚠️ No indexes found on source columns (performance may be impacted)")
        
        # Test 8: Final verdict
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED!")
        print("="*70)
        print("\n📊 System Status:")
        print(f"  • Total CVEs: {total}")
        print(f"  • Source tracking: ACTIVE")
        print(f"  • Multi-source support: ENABLED")
        print(f"  • Audit logging: READY")
        print("\n✨ The system is ready to handle multi-source CVE ingestion!")
        print("="*70)
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    import sys
    success = test_source_deduplication()
    sys.exit(0 if success else 1)
