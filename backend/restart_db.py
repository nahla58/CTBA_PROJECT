import os
import time
import sqlite3

db_path = 'ctba_platform.db'

# Try to remove the database file multiple times
for attempt in range(5):
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"✅ Database file removed successfully")
            break
    except Exception as e:
        print(f"⏳ Attempt {attempt + 1}: Cannot delete database - {e}")
        time.sleep(2)
else:
    print("⚠️ Could not delete database file, will proceed with reinitialization")

# Now run init_db.py
print("\n" + "="*50)
print("Reinitializing database...")
print("="*50 + "\n")

# Execute init_db.py
exec(open('init_db.py').read())
