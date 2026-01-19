# init_learning.py
import logging
import sqlite3
from learning_system import ProductLearningSystem  # Import de la classe, pas de l'instance

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_missing_columns():
    """Ajouter les colonnes manquantes à la base de données"""
    try:
        conn = sqlite3.connect("ctba_platform.db")
        cursor = conn.cursor()
        
        # 1. Ajouter la colonne 'source' si elle n'existe pas
        cursor.execute("PRAGMA table_info(affected_products)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'source' not in columns:
            logger.info("Adding 'source' column to affected_products...")
            cursor.execute('ALTER TABLE affected_products ADD COLUMN source TEXT DEFAULT "unknown"')
            
            # Mettre à jour les données existantes
            cursor.execute("""
                UPDATE affected_products 
                SET source = 'cpe' 
                WHERE confidence > 0.8
            """)
            cursor.execute("""
                UPDATE affected_products 
                SET source = 'description' 
                WHERE confidence <= 0.8 AND confidence > 0.3
            """)
            cursor.execute("""
                UPDATE affected_products 
                SET source = 'fallback' 
                WHERE confidence <= 0.3
            """)
        
        # 2. Ajouter la colonne 'extraction_method' si elle n'existe pas
        if 'extraction_method' not in columns:
            logger.info("Adding 'extraction_method' column to affected_products...")
            cursor.execute('ALTER TABLE affected_products ADD COLUMN extraction_method TEXT DEFAULT "unknown"')
        
        # 3. Vérifier la table cves
        cursor.execute("PRAGMA table_info(cves)")
        cves_columns = [row[1] for row in cursor.fetchall()]
        
        if 'cvss_version' not in cves_columns:
            logger.info("Adding 'cvss_version' column to cves...")
            cursor.execute('ALTER TABLE cves ADD COLUMN cvss_version TEXT DEFAULT "N/A"')
        
        conn.commit()
        conn.close()
        logger.info("✅ Database schema updated successfully")
        
    except Exception as e:
        logger.error(f"❌ Error updating database schema: {e}")

def cleanup_incorrect_products():
    """Nettoyer les produits incorrects dans la base"""
    try:
        conn = sqlite3.connect("ctba_platform.db")
        cursor = conn.cursor()
        
        # Liste des produits incorrects à supprimer
        invalid_products = [
            'en', 'hpesc', 'vulnbycola', 'support.hpe', 'helpdesk.paessler',
            '0 fool', 'bluvoyix', 'blusparkglobal', 'gitlab', 'fool', 
            'paessler', 'bluvoyix', 'wireshark', 'vulnbycola'
        ]
        
        # Supprimer les entrées avec des noms de produits incorrects
        placeholders = ','.join('?' for _ in invalid_products)
        cursor.execute(f"""
            DELETE FROM affected_products 
            WHERE LOWER(product) IN ({placeholders})
            OR LOWER(vendor) IN ({placeholders})
        """, invalid_products * 2)
        
        # Compter les suppressions
        deleted = cursor.rowcount
        
        # Mettre à jour les produits 'Unknown' avec une confiance plus basse
        cursor.execute("""
            UPDATE affected_products 
            SET confidence = 0.3 
            WHERE vendor = 'Unknown' OR product = 'Multiple Products'
        """)
        
        updated = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Cleanup completed: {deleted} incorrect products deleted, {updated} products updated")
        
    except Exception as e:
        logger.error(f"❌ Error during cleanup: {e}")

def main():
    """Initialiser et tester le système d'apprentissage"""
    logger.info("Initializing learning system...")
    
    # 1. Corriger la base de données
    fix_missing_columns()
    
    # 2. Nettoyer les données incorrectes
    cleanup_incorrect_products()
    
    # 3. Initialiser le système d'apprentissage avec une nouvelle instance
    learner = ProductLearningSystem()
    learner.initialize()
    
    # 4. Afficher les stats
    stats = learner.get_stats()
    
    print("\n" + "="*60)
    print("🤖 SYSTÈME D'APPRENTISSAGE INITIALISÉ")
    print("="*60)
    
    if 'error' in stats:
        print(f"❌ Erreur: {stats['error']}")
    else:
        print(f"✅ Vendeurs connus: {stats.get('known_vendors', 0)}")
        print(f"✅ Produits connus: {stats.get('known_products', 0)}")
        print(f"✅ Paires vendeur-produit: {stats.get('vendor_product_pairs', 0)}")
        print(f"✅ Patterns appris: {stats.get('learned_patterns', 0)}")
        
        print("\n📊 Top 10 paires fréquentes:")
        top_pairs = stats.get('top_pairs', [])
        if top_pairs:
            for (vendor, product), count in top_pairs[:10]:
                print(f"  ▪ {vendor:20} → {product:30} : {count:3d}x")
        else:
            print("  Aucune paire fréquente trouvée")
        
        print("\n🎯 Top 10 vendeurs:")
        top_vendors = stats.get('top_vendors', [])
        for vendor in top_vendors[:10]:
            print(f"  ▪ {vendor}")
    
    print("\n" + "="*60)
    print("📋 Prochaines étapes:")
    print("1. Lancez l'API avec: python main.py")
    print("2. Importez de nouveaux CVEs: POST /api/import/test-now")
    print("3. Vérifiez les stats: GET /api/learning/stats")
    print("4. Testez l'amélioration: POST /api/learning/improve/CVE-XXXX")
    print("="*60)

if __name__ == "__main__":
    main()