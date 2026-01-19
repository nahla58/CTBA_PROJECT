#!/usr/bin/env python3
"""
Test de connexion à PostgreSQL
Vérifie que la migration est réussie
"""

import psycopg2
from psycopg2 import sql
import os
from dotenv import load_dotenv

load_dotenv()

# Configuration de la connexion
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'ctba_platform')
DB_USER = os.getenv('DB_USER', 'ctba_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'ctba_password123')

def test_postgres_connection():
    """Test la connexion à PostgreSQL"""
    
    print("\n" + "="*70)
    print("TEST DE CONNEXION PostgreSQL")
    print("="*70)
    
    print(f"\nConfiguration:")
    print(f"  Host: {DB_HOST}")
    print(f"  Port: {DB_PORT}")
    print(f"  Database: {DB_NAME}")
    print(f"  User: {DB_USER}")
    
    try:
        # Connexion
        print("\n🔗 Connexion en cours...", end=" ")
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        print("✅")
        
        cursor = conn.cursor()
        
        # Test 1: Vérifier les tables
        print("\n📋 Vérifier les tables:", end=" ")
        cursor.execute("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        tables = cursor.fetchall()
        print(f"✅ {len(tables)} tables trouvées")
        
        for table in tables:
            table_name = table[0]
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            print(f"   - {table_name}: {count} rows")
        
        # Test 2: Version PostgreSQL
        print("\n🔧 Version PostgreSQL:", end=" ")
        cursor.execute("SELECT version()")
        version = cursor.fetchone()[0]
        print(f"✅\n   {version[:70]}...")
        
        # Test 3: Vérifier les données CVEs
        print("\n🛡️ CVEs importés:", end=" ")
        cursor.execute("SELECT COUNT(*) FROM cves")
        cve_count = cursor.fetchone()[0]
        print(f"✅ {cve_count} CVEs")
        
        # Test 4: Vérifier les produits affectés
        print("📦 Produits affectés:", end=" ")
        cursor.execute("SELECT COUNT(*) FROM affected_products")
        product_count = cursor.fetchone()[0]
        print(f"✅ {product_count} produits")
        
        # Test 5: Vérifier les utilisateurs
        print("👥 Utilisateurs:", end=" ")
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"✅ {user_count} utilisateurs")
        
        # Test 6: Vérifier les technologies
        print("💻 Technologies:", end=" ")
        cursor.execute("SELECT COUNT(*) FROM technologies")
        tech_count = cursor.fetchone()[0]
        print(f"✅ {tech_count} technologies")
        
        # Test 7: Exemple de CVE
        print("\n📌 Exemple de CVE:")
        cursor.execute("""
            SELECT cve_id, description, severity, cvss_score
            FROM cves
            LIMIT 1
        """)
        cve = cursor.fetchone()
        if cve:
            cve_id, desc, severity, score = cve
            print(f"   ID: {cve_id}")
            print(f"   Sévérité: {severity}")
            print(f"   CVSS: {score}")
            print(f"   Description: {desc[:100] if desc else 'N/A'}...")
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*70)
        print("✅ MIGRATION REUSSIE!")
        print("="*70)
        print("\n✨ PostgreSQL est prêt pour l'utilisation!")
        
        return True
        
    except psycopg2.Error as e:
        print(f"\n❌ ERREUR PostgreSQL:")
        print(f"   {e}")
        print("\n💡 Solutions possibles:")
        print("   1. PostgreSQL n'est pas installé/lancé")
        print("   2. Vérifier les credentials dans .env")
        print("   3. Vérifier que la base de données existe")
        print("   4. Exécuter: psql -U postgres -c 'CREATE DATABASE ctba_platform'")
        return False
    
    except Exception as e:
        print(f"\n❌ ERREUR:")
        print(f"   {e}")
        print("\n💡 Assurez-vous que psycopg2 est installé:")
        print("   pip install psycopg2-binary")
        return False

if __name__ == "__main__":
    success = test_postgres_connection()
    exit(0 if success else 1)
