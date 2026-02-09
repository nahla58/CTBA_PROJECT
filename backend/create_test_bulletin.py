"""
Créer un bulletin de test envoyé il y a 8 jours pour tester les reminders
"""
import sqlite3
from datetime import datetime, timedelta

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Date d'envoi: il y a 8 jours
sent_date = datetime.utcnow() - timedelta(days=8)

# Créer un bulletin de test
cursor.execute('''
    INSERT INTO bulletins (
        title, description, severity, regions, 
        status, sent_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
''', (
    '[TEST] Bulletin pour reminder test',
    'Ce bulletin a été créé pour tester le système de reminder',
    'MEDIUM',
    '["EUROPE"]',
    'SENT',
    sent_date.strftime('%Y-%m-%d %H:%M:%S'),
    datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
    datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
))

bulletin_id = cursor.lastrowid
conn.commit()
conn.close()

print(f"✅ Bulletin de test créé (ID: {bulletin_id})")
print(f"   Envoyé: {sent_date.strftime('%Y-%m-%d %H:%M:%S')}")
print(f"   Il y a: 8 jours")
print(f"   Devrait recevoir: Reminder 7 jours\n")
print("Maintenant exécutez: python test_reminder.py")
