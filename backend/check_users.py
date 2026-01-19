import sqlite3
conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print("Tables:", [t[0] for t in tables])

if 'users' in [t[0] for t in tables]:
    cursor.execute('SELECT username, role FROM users')
    users = cursor.fetchall()
    print("Users:")
    for u in users:
        print(f"  {u[0]} - {u[1]}")
else:
    print("Users table not found!")

conn.close()
