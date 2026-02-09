"""
Test manuel du service de reminder
"""
import logging
import sqlite3
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_reminder_service():
    """Test le service de reminder"""
    
    print("\n=== Test du Service de Reminder ===\n")
    
    # 1. Vérifier la structure de la DB
    print("1. Vérification de la structure DB...")
    conn = sqlite3.connect('ctba_platform.db')
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA table_info(bulletins)")
    columns = {col[1]: col[2] for col in cursor.fetchall()}
    
    reminder_fields = ['reminder_7_sent_at', 'reminder_14_sent_at', 'escalation_30_sent_at']
    for field in reminder_fields:
        if field in columns:
            print(f"   ✓ {field}: {columns[field]}")
        else:
            print(f"   ✗ {field}: MANQUANT")
    
    # 2. Lister les bulletins envoyés
    print("\n2. Bulletins envoyés (non cloturés)...")
    cursor.execute('''
        SELECT id, title, status, sent_at, 
               reminder_7_sent_at, reminder_14_sent_at, 
               escalation_30_sent_at, closed_at
        FROM bulletins
        WHERE status = 'SENT' AND sent_at IS NOT NULL
        ORDER BY sent_at DESC
    ''')
    
    bulletins = cursor.fetchall()
    
    if not bulletins:
        print("   ⚠️ Aucun bulletin envoyé trouvé")
    else:
        print(f"   Trouvé {len(bulletins)} bulletin(s) envoyé(s):\n")
        
        now = datetime.utcnow()
        for b in bulletins:
            bid, title, status, sent_at, r7, r14, esc, closed = b
            
            # Parser la date
            try:
                sent_date = datetime.strptime(sent_at, '%Y-%m-%d %H:%M:%S')
            except:
                try:
                    sent_date = datetime.fromisoformat(sent_at.replace('Z', '+00:00'))
                except:
                    sent_date = None
            
            days_ago = (now - sent_date).days if sent_date else -1
            
            print(f"   📄 Bulletin #{bid}: {title[:50]}")
            print(f"      Status: {status}")
            print(f"      Envoyé: {sent_at} ({days_ago} jours)")
            print(f"      Reminder 7j: {'✓' if r7 else '✗'} {r7 or ''}")
            print(f"      Reminder 14j: {'✓' if r14 else '✗'} {r14 or ''}")
            print(f"      Escalation 30j: {'✓' if esc else '✗'} {esc or ''}")
            print(f"      Cloturé: {'Oui' if closed else 'Non'}")
            
            # Déterminer quel reminder devrait être envoyé
            if days_ago >= 30 and not esc:
                print(f"      ⚠️  DEVRAIT RECEVOIR: Escalation 30j")
            elif days_ago >= 14 and not r14:
                print(f"      ⚠️  DEVRAIT RECEVOIR: Reminder 14j")
            elif days_ago >= 7 and not r7:
                print(f"      ⚠️  DEVRAIT RECEVOIR: Reminder 7j")
            else:
                print(f"      ✓ Aucun reminder nécessaire pour le moment")
            
            print()
    
    # 3. Tester manuellement le check
    print("\n3. Test manuel du check de reminders...")
    
    try:
        from services.bulletin_reminder_service import BulletinReminderService
        
        reminder_service = BulletinReminderService()
        print("   Service de reminder initialisé")
        
        print("   Exécution du check...")
        reminder_service.check_and_send_reminders()
        print("   ✓ Check terminé")
        
    except Exception as e:
        print(f"   ✗ Erreur: {e}")
    
    conn.close()
    
    print("\n=== Test terminé ===\n")


if __name__ == "__main__":
    test_reminder_service()
