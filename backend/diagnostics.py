# diagnostics.py - Exécutez-le et copiez la sortie
import sqlite3
import json

def diagnose():
    print("🔍 DIAGNOSTIC COMPLET DU PROBLÈME PRODUITS")
    print("="*70)
    
    try:
        conn = sqlite3.connect("ctba.db")
        cursor = conn.cursor()
        
        # 1. Structure de la base
        print("\n1. 📋 STRUCTURE DES TABLES:")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        for table in tables:
            print(f"\n   Table: {table[0]}")
            cursor.execute(f"PRAGMA table_info({table[0]})")
            columns = cursor.fetchall()
            for col in columns:
                print(f"     - {col[1]} ({col[2]})")
        
        # 2. Données CVE
        print("\n2. 📊 DONNÉES CVE:")
        cursor.execute("SELECT COUNT(*) as total, COUNT(DISTINCT cve_id) as unique_cves FROM cves")
        cve_stats = cursor.fetchone()
        print(f"   Total lignes: {cve_stats[0]}, CVE uniques: {cve_stats[1]}")
        
        cursor.execute("SELECT cve_id, description, severity FROM cves LIMIT 3")
        sample_cves = cursor.fetchall()
        for cve in sample_cves:
            print(f"   • {cve[0]} - {cve[2]} - {cve[1][:50]}...")
        
        # 3. Données produits affectés
        print("\n3. 📦 DONNÉES PRODUITS AFFECTÉS:")
        cursor.execute("SELECT COUNT(*) as total_products FROM affected_products")
        total_products = cursor.fetchone()[0]
        print(f"   Total produits: {total_products}")
        
        if total_products > 0:
            cursor.execute("SELECT cve_id, vendor, product FROM affected_products LIMIT 10")
            products = cursor.fetchall()
            print("   Exemples:")
            for prod in products:
                print(f"     • {prod[0]} - {prod[1]}/{prod[2]}")
            
            # Compter les CVE avec produits
            cursor.execute("SELECT COUNT(DISTINCT cve_id) FROM affected_products")
            cves_with_products = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(DISTINCT cve_id) FROM cves")
            total_cves = cursor.fetchone()[0]
            print(f"   CVE avec produits: {cves_with_products}/{total_cves} ({cves_with_products/total_cves*100:.1f}%)")
        else:
            print("   ⚠️  AUCUN PRODUIT DANS LA BASE!")
        
        # 4. Test d'une route API
        print("\n4. 🔌 TEST STRUCTURE API:")
        cursor.execute("""
            SELECT c.cve_id, c.severity, 
                   GROUP_CONCAT(ap.vendor || '/' || ap.product) as products
            FROM cves c
            LEFT JOIN affected_products ap ON c.cve_id = ap.cve_id
            GROUP BY c.cve_id
            LIMIT 3
        """)
        api_test = cursor.fetchall()
        print("   Structure API attendue:")
        for cve in api_test:
            print(f"     • {cve[0]}: produits = '{cve[2] if cve[2] else 'AUCUN'}'")
        
        # 5. Vérifier les données de test
        print("\n5. 🧪 DONNÉES DE TEST:")
        cursor.execute("SELECT * FROM cves WHERE cve_id = 'CVE-2024-99999'")
        test_cve = cursor.fetchone()
        if test_cve:
            print(f"   ✅ CVE de test trouvée: CVE-2024-99999")
            cursor.execute("SELECT vendor, product FROM affected_products WHERE cve_id = 'CVE-2024-99999'")
            test_products = cursor.fetchall()
            if test_products:
                print(f"   ✅ Produits de test: {test_products}")
            else:
                print("   ❌ PAS DE PRODUITS pour la CVE de test!")
        else:
            print("   ⚠️  CVE de test non trouvée")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ ERREUR: {e}")
    
    print("\n" + "="*70)
    print("🎯 RECOMMANDATIONS:")
    if total_products == 0:
        print("1. Exécuter: python fix_products.py")
        print("2. Vérifier la fonction extract_affected_products dans main.py")
        print("3. Vérifier que affected_products est bien lié à cves")
    else:
        print("1. Vérifier la route /cves dans main.py")
        print("2. Vérifier le frontend (CVEList.js)")
        print("3. Tester l'API: curl http://localhost:8000/cves")

def fix_products():
    """Solution rapide pour ajouter des produits"""
    print("\n⚡ CORRECTION RAPIDE")
    print("="*70)
    
    try:
        conn = sqlite3.connect("ctba.db")
        cursor = conn.cursor()
        
        # Liste de produits de test
        test_products = [
            ("Apache", "HTTP Server"),
            ("Linux", "Kernel"),
            ("Microsoft", "Windows 10"),
            ("OpenSSL", "OpenSSL"),
            ("WordPress", "WordPress"),
            ("MySQL", "MySQL"),
            ("Python", "Python"),
            ("Node.js", "Node.js"),
            ("Docker", "Docker"),
            ("Kubernetes", "Kubernetes")
        ]
        
        # Récupérer toutes les CVE
        cursor.execute("SELECT cve_id FROM cves")
        all_cves = cursor.fetchall()
        
        added = 0
        for cve_id, in all_cves:
            # Vérifier si cette CVE a déjà des produits
            cursor.execute("SELECT COUNT(*) FROM affected_products WHERE cve_id = ?", (cve_id,))
            if cursor.fetchone()[0] == 0:
                # Ajouter 1-3 produits aléatoires
                import random
                num = random.randint(1, 3)
                selected = random.sample(test_products, num)
                
                for vendor, product in selected:
                    cursor.execute('''
                        INSERT INTO affected_products (cve_id, vendor, product, version)
                        VALUES (?, ?, ?, ?)
                    ''', (cve_id, vendor, product, "1.0"))
                    added += 1
        
        conn.commit()
        conn.close()
        
        print(f"✅ {added} produits ajoutés à {len(all_cves)} CVE")
        
    except Exception as e:
        print(f"❌ ERREUR: {e}")

if __name__ == "__main__":
    diagnose()
    print("\n")
    input("Appuyez sur Entrée pour appliquer la correction rapide...")
    fix_products()