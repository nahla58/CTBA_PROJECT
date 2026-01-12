# check_db.py
import sqlite3
import os

def check_database():
    print("🔍 VÉRIFICATION DE LA BASE DE DONNÉES")
    print("="*40)
    
    # 1. Le fichier existe-t-il ?
    if not os.path.exists("ctba.db"):
        print("❌ Fichier ctba.db NON TROUVÉ")
        print("   → Lance d'abord 'python main.py'")
        return False
    
    file_size = os.path.getsize("ctba.db")
    print(f"✅ Fichier ctba.db existe ({file_size} octets)")
    
    # 2. Connexion et vérification des tables
    try:
        conn = sqlite3.connect("ctba.db")
        cursor = conn.cursor()
        
        # Liste des tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        if tables:
            print("📋 TABLES TROUVÉES :")
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table[0]};")
                count = cursor.fetchone()[0]
                print(f"  • {table[0]} : {count} lignes")
        else:
            print("⚠️  AUCUNE TABLE TROUVÉE")
            print("   → Lance 'python main.py' pour créer les tables")
        
        # 3. Vérifier spécifiquement blacklisted_products
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blacklisted_products';")
        if cursor.fetchone():
            print("✅ Table 'blacklisted_products' existe")
        else:
            print("❌ Table 'blacklisted_products' MANQUANTE")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ ERREUR : {e}")
        return False

if __name__ == "__main__":
    check_database()
    input("\n👆 Appuie sur ENTRÉE pour quitter...")