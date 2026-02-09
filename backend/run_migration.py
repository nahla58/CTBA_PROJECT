#!/usr/bin/env python3
"""Script pour exécuter les migrations SQL"""
import sqlite3
import sys
import time

def run_migration():
    db_path = 'ctba_platform.db'
    migration_file = 'migration_bulletin_cves_sqlite.sql'  # Version SQLite corrigée
    
    print(f"🔄 Connexion à la base de données: {db_path}")
    
    # Attendre que la DB soit déverrouillée
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            conn = sqlite3.connect(db_path, timeout=10.0)
            break
        except sqlite3.OperationalError as e:
            if attempt < max_attempts - 1:
                print(f"⏳ Tentative {attempt + 1}/{max_attempts} - DB verrouillée, attente...")
                time.sleep(2)
            else:
                print(f"❌ Erreur: Database toujours verrouillée après {max_attempts} tentatives")
                print("   → Arrêtez le backend (Ctrl+C dans le terminal python) et relancez ce script")
                sys.exit(1)
    
    try:
        print(f"📖 Lecture du script de migration: {migration_file}")
        with open(migration_file, 'r', encoding='utf-8') as f:
            migration_sql = f.read()
        
        print("⚙️  Exécution de la migration...")
        conn.executescript(migration_sql)
        conn.commit()
        
        # Vérifier que la table existe
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='bulletin_cves'")
        result = cursor.fetchone()
        
        if result:
            print("✅ Migration réussie! Table bulletin_cves créée")
            
            # Afficher le schéma
            cursor.execute("PRAGMA table_info(bulletin_cves)")
            columns = cursor.fetchall()
            print("\n📋 Colonnes de bulletin_cves:")
            for col in columns:
                print(f"   - {col[1]} ({col[2]})")
        else:
            print("⚠️  Avertissement: Table bulletin_cves non trouvée après migration")
        
        conn.close()
        print("\n✓ Migration terminée avec succès!")
        
    except Exception as e:
        print(f"❌ Erreur lors de la migration: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_migration()
