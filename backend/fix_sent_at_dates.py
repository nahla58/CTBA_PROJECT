"""
Fix sent_at dates for existing SENT bulletins
"""
import sqlite3
from datetime import datetime, timedelta

def fix_sent_dates():
    print("🔧 Fixing sent_at dates for existing bulletins...\n")
    
    conn = sqlite3.connect('ctba_platform.db')
    cursor = conn.cursor()
    
    # Get all SENT bulletins without sent_at dates
    cursor.execute("""
        SELECT id, created_at FROM bulletins 
        WHERE status = 'SENT' AND sent_at IS NULL
        ORDER BY id
    """)
    
    bulletins = cursor.fetchall()
    
    if not bulletins:
        print("✅ No bulletins to fix")
        conn.close()
        return
    
    print(f"📊 Found {len(bulletins)} bulletins with status SENT but no sent_at date\n")
    
    # Update each bulletin with a sent_at date
    # Use created_at + a few minutes as the sent date
    for bulletin_id, created_at in bulletins:
        # Parse created_at if it exists, otherwise use now
        if created_at:
            sent_date = datetime.fromisoformat(created_at.replace('Z', '+00:00')) + timedelta(minutes=2)
        else:
            sent_date = datetime.now()
        
        sent_at_str = sent_date.isoformat()
        
        cursor.execute("""
            UPDATE bulletins 
            SET sent_at = ?
            WHERE id = ?
        """, (sent_at_str, bulletin_id))
        
        print(f"✅ Updated bulletin #{bulletin_id}: sent_at = {sent_at_str}")
    
    conn.commit()
    
    # Verify the fix
    print("\n📊 Verification:")
    cursor.execute("""
        SELECT id, status, created_at, sent_at 
        FROM bulletins 
        WHERE status = 'SENT'
        ORDER BY id
    """)
    
    for row in cursor.fetchall():
        bulletin_id, status, created_at, sent_at = row
        print(f"  Bulletin #{bulletin_id}: {status} | Sent: {sent_at}")
    
    conn.close()
    print("\n✅ All sent_at dates fixed!")

if __name__ == "__main__":
    fix_sent_dates()
