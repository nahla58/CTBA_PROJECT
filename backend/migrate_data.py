# migrate_data.py
import sqlite3
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_existing_data():
    """Migrer les données existantes vers le nouveau schéma"""
    try:
        conn = sqlite3.connect("ctba_platform.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        logger.info("Starting data migration...")
        
        # 1. Vérifier et ajouter la colonne 'source'
        cursor.execute("PRAGMA table_info(affected_products)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'source' not in columns:
            cursor.execute('ALTER TABLE affected_products ADD COLUMN source TEXT DEFAULT "unknown"')
            logger.info("Added 'source' column")
        
        # 2. Déterminer la source basée sur la confiance et les valeurs
        cursor.execute("""
            SELECT id, vendor, product, confidence 
            FROM affected_products 
            WHERE source = 'unknown' OR source IS NULL
        """)
        
        updates = []
        for row in cursor.fetchall():
            source = determine_source(row['vendor'], row['product'], row['confidence'])
            updates.append((source, row['id']))
        
        # 3. Appliquer les mises à jour
        cursor.executemany("""
            UPDATE affected_products 
            SET source = ? 
            WHERE id = ?
        """, updates)
        
        logger.info(f"Updated source for {len(updates)} records")
        
        # 4. Nettoyer les données incorrectes
        cursor.execute("""
            DELETE FROM affected_products 
            WHERE LOWER(product) IN (
                'en', 'hpesc', 'vulnbycola', 'support.hpe', 'helpdesk.paessler',
                '0 fool', 'bluvoyix', 'blusparkglobal', 'gitlab', 'fool', 'paessler'
            ) OR LOWER(vendor) IN ('0 fool', 'gitlab', 'blusparkglobal')
            OR product LIKE '%Fool%' OR product LIKE '%Paessler%'
            OR product LIKE '%Bluvoyix%' OR product LIKE '%Wireshark%'
        """)
        
        deleted = cursor.rowcount
        logger.info(f"Deleted {deleted} incorrect records")
        
        # 5. Mettre à jour les CVSS versions si manquantes
        cursor.execute("""
            UPDATE cves 
            SET cvss_version = 'N/A' 
            WHERE cvss_version IS NULL OR cvss_version = ''
        """)
        
        conn.commit()
        conn.close()
        
        logger.info("✅ Data migration completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Error during migration: {e}")

def determine_source(vendor: str, product: str, confidence: float) -> str:
    """Déterminer la source basée sur les données"""
    if confidence > 0.8:
        return "cpe"
    elif confidence > 0.4:
        return "description"
    elif vendor == 'Unknown' or product == 'Multiple Products':
        return "fallback"
    else:
        return "unknown"

if __name__ == "__main__":
    migrate_existing_data()