#!/usr/bin/env python3
"""
Apply the multi-source deduplication migration
Run this script once to upgrade the database schema
"""
import sqlite3
import sys
import os

DB_FILE = "ctba_platform.db"

def apply_migration():
    """Apply the migration from fix_multi_source.sql"""
    
    if not os.path.exists(DB_FILE):
        print(f"❌ Database file not found: {DB_FILE}")
        return False
    
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        print("\n" + "="*70)
        print("🚀 APPLYING MULTI-SOURCE DEDUPLICATION MIGRATION")
        print("="*70)
        
        # Step 1: Add new columns
        print("\n[1/8] Adding new columns (source_primary, sources_secondary, last_updated)...")
        try:
            cursor.execute("ALTER TABLE cves ADD COLUMN source_primary TEXT DEFAULT 'NVD'")
            print("  ✅ Added source_primary column")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e):
                print("  ⚠️ Column source_primary already exists")
            else:
                raise
        
        try:
            cursor.execute("ALTER TABLE cves ADD COLUMN sources_secondary JSON DEFAULT '[]'")
            print("  ✅ Added sources_secondary column")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e):
                print("  ⚠️ Column sources_secondary already exists")
            else:
                raise
        
        try:
            cursor.execute("ALTER TABLE cves ADD COLUMN last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            print("  ✅ Added last_updated column")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e):
                print("  ⚠️ Column last_updated already exists")
            else:
                raise
        
        conn.commit()
        
        # Step 2: Migrate existing data from 'source' column
        print("\n[2/8] Migrating existing data from 'source' column...")
        cursor.execute("""
            UPDATE cves 
            SET source_primary = CASE 
              WHEN source LIKE '%nvd%' THEN 'NVD'
              WHEN source LIKE '%cvedetails%' THEN 'cvedetails'
              WHEN source LIKE '%cveorg%' THEN 'cveorg'
              WHEN source LIKE '%msrc%' THEN 'msrc'
              WHEN source LIKE '%hackuity%' THEN 'hackuity'
              WHEN source LIKE '%manual%' THEN 'manual'
              WHEN source IS NOT NULL AND source != '' THEN source
              ELSE 'NVD'
            END
            WHERE source_primary = 'NVD'
        """)
        updated = cursor.rowcount
        print(f"  ✅ Updated {updated} CVEs with extracted primary source")
        conn.commit()
        
        # Step 3: Create indexes
        print("\n[3/8] Creating indexes for performance...")
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_source_primary ON cves(source_primary)")
            print("  ✅ Created index on source_primary")
        except:
            print("  ⚠️ Index on source_primary already exists")
        
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_sources_secondary ON cves(sources_secondary)")
            print("  ✅ Created index on sources_secondary")
        except:
            print("  ⚠️ Index on sources_secondary already exists")
        
        conn.commit()
        
        # Step 4: Create audit log table
        print("\n[4/8] Creating audit log table...")
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_source_history (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  cve_id TEXT NOT NULL,
                  old_source_primary TEXT,
                  new_source_primary TEXT,
                  secondary_source_added TEXT,
                  changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  reason TEXT,
                  FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
                )
            """)
            print("  ✅ Created cve_source_history table")
        except:
            print("  ⚠️ cve_source_history table already exists")
        
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_source_history_cve_id ON cve_source_history(cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_source_history_changed_at ON cve_source_history(changed_at DESC)")
            print("  ✅ Created indexes on cve_source_history")
        except:
            print("  ⚠️ Indexes on cve_source_history already exist")
        
        conn.commit()
        
        # Step 5: Show statistics
        print("\n[5/8] Analyzing migrated data...")
        cursor.execute("""
            SELECT 
              COUNT(*) as total_cves,
              COUNT(DISTINCT source_primary) as unique_primary_sources
            FROM cves
        """)
        row = cursor.fetchone()
        total = row['total_cves']
        unique = row['unique_primary_sources']
        print(f"  ✅ Total CVEs: {total}")
        print(f"  ✅ Unique primary sources: {unique}")
        
        # Show breakdown by primary source
        print("\n[6/8] Breakdown by primary source:")
        cursor.execute("""
            SELECT 
              source_primary,
              COUNT(*) as count
            FROM cves
            GROUP BY source_primary
            ORDER BY count DESC
        """)
        for row in cursor.fetchall():
            source = row['source_primary']
            count = row['count']
            print(f"  • {source:30s}: {count:5d} CVEs")
        
        # Step 6: Check for mixed sources needing secondary source processing
        print("\n[7/8] Checking for CVEs needing secondary source setup...")
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM cves
            WHERE sources_secondary = '[]' AND source LIKE '%,%'
        """)
        row = cursor.fetchone()
        needs_processing = row['count']
        if needs_processing > 0:
            print(f"  ⚠️ {needs_processing} CVEs have multiple sources that need secondary source setup")
            print("     These will be processed during the next import cycle")
        else:
            print(f"  ✅ All CVEs properly configured")
        
        # Step 7: Migration complete
        print("\n[8/8] Migration complete!")
        print("\n" + "="*70)
        print("✅ MIGRATION SUCCESSFUL")
        print("="*70)
        print("\n📝 What changed:")
        print("  • CVEs now use source_primary to indicate their original source")
        print("  • Multiple sources are tracked in sources_secondary JSON array")
        print("  • Each CVE has a clear primary source, no more confusion!")
        print("\n📊 Benefits:")
        print("  ✓ Clear source attribution")
        print("  ✓ Traceable enrichments")
        print("  ✓ No data loss")
        print("  ✓ Flexible multi-source support")
        print("\n🔄 Next steps:")
        print("  1. Restart the backend API (python main.py)")
        print("  2. Run a fresh import to see the new source tracking in action")
        print("  3. Check the 'Source' column in the CVE table to see primary + secondary sources")
        print("\n" + "="*70)
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = apply_migration()
    sys.exit(0 if success else 1)
