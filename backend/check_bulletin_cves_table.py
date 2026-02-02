import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Check if bulletin_cves table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='bulletin_cves'")
result = cursor.fetchone()

if result:
    print("✅ bulletin_cves table EXISTS")
    
    # Show schema
    cursor.execute("PRAGMA table_info(bulletin_cves)")
    columns = cursor.fetchall()
    print("\nTable schema:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    # Count records
    cursor.execute("SELECT COUNT(*) FROM bulletin_cves")
    count = cursor.fetchone()[0]
    print(f"\nTotal records: {count}")
    
    if count > 0:
        cursor.execute("SELECT * FROM bulletin_cves LIMIT 5")
        print("\nSample records:")
        for row in cursor.fetchall():
            print(f"  {row}")
else:
    print("❌ bulletin_cves table DOES NOT EXIST")
    print("\nCreating bulletin_cves table...")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bulletin_cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bulletin_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (bulletin_id) REFERENCES bulletins(id) ON DELETE CASCADE,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
            UNIQUE(bulletin_id, cve_id)
        )
    ''')
    
    conn.commit()
    print("✅ bulletin_cves table created successfully")

conn.close()
