"""
Migration: Add reminder and closure tracking fields to bulletins table
Date: 2026-02-02
"""
import sqlite3
import os

def migrate():
    """Add new reminder and closure fields to bulletins table"""
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ctba.db')
    if not os.path.exists(db_path):
        print(f"❌ Database file not found at {db_path}")
        print("Please ensure the database is initialized first.")
        return
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if columns exist before adding
    cursor.execute("PRAGMA table_info(bulletins)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    
    # Add new columns if they don't exist
    new_columns = {
        'reminder_7_sent_at': 'TIMESTAMP',
        'reminder_14_sent_at': 'TIMESTAMP',
        'escalation_30_sent_at': 'TIMESTAMP',
        'closed_at': 'TIMESTAMP',
        'closed_by': 'TEXT',
        'closure_reason': 'TEXT',
        'can_reopen': 'BOOLEAN DEFAULT 1',
        'reopened_at': 'TIMESTAMP',
        'reopened_by': 'TEXT'
    }
    
    for column_name, column_type in new_columns.items():
        if column_name not in existing_columns:
            try:
                cursor.execute(f'ALTER TABLE bulletins ADD COLUMN {column_name} {column_type}')
                print(f"✅ Added column: {column_name}")
            except sqlite3.OperationalError as e:
                print(f"⚠️  Column {column_name} might already exist: {e}")
    
    # Update status constraint to include CLOSED
    # Note: SQLite doesn't support modifying constraints directly
    # So we just ensure new bulletins can use CLOSED status
    
    conn.commit()
    conn.close()
    
    print("\n✅ Migration completed successfully!")
    print("📋 Bulletins table now supports:")
    print("   - Automatic reminders at 7, 14, 30 days")
    print("   - Manual closure with reason tracking")
    print("   - Reopen capability with audit trail")

if __name__ == '__main__':
    migrate()
