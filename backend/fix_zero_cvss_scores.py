"""
Script pour mettre à jour les scores CVSS à 0 dans la base de données
Récupère les vrais scores depuis NVD et met à jour la DB
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sqlite3
from services.cve_fetcher_service import CVEFetcherService
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

DB_FILE = "ctba_platform.db"

def update_cvss_scores():
    """Met à jour les scores CVSS à 0 dans la base de données"""
    
    print("\n" + "="*80)
    print("🔧 MISE À JOUR DES SCORES CVSS DEPUIS NVD")
    print("="*80)
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Trouver tous les CVEs avec score à 0
    cursor.execute("""
        SELECT cve_id, cvss_score, cvss_version
        FROM cves
        WHERE cvss_score = 0 OR cvss_score IS NULL
        ORDER BY published_date DESC
        LIMIT 100
    """)
    
    cves_with_zero_score = cursor.fetchall()
    
    print(f"\n📊 {len(cves_with_zero_score)} CVEs avec score CVSS à 0 trouvés")
    
    if len(cves_with_zero_score) == 0:
        print("✅ Aucun CVE à mettre à jour!")
        conn.close()
        return
    
    print("\n🔄 Récupération des scores depuis NVD...")
    
    updated = 0
    not_found = 0
    still_zero = 0
    
    for row in cves_with_zero_score[:50]:  # Limiter à 50 pour éviter rate limit
        cve_id = row['cve_id']
        
        try:
            # Récupérer les infos depuis NVD via l'API de recherche
            cves = CVEFetcherService.search_cves_by_keyword(cve_id, limit=1)
            
            if not cves or len(cves) == 0:
                logger.warning(f"⚠️ {cve_id}: Non trouvé dans NVD")
                not_found += 1
                continue
            
            cve_data = cves[0]
            new_score = cve_data.get('cvss_score', 0)
            new_version = cve_data.get('cvss_version', 'N/A')
            new_severity = cve_data.get('severity', 'UNKNOWN')
            
            if new_score > 0:
                # Mettre à jour le score
                cursor.execute("""
                    UPDATE cves
                    SET cvss_score = ?, cvss_version = ?, severity = ?
                    WHERE cve_id = ?
                """, (new_score, new_version, new_severity, cve_id))
                
                conn.commit()
                
                print(f"✅ {cve_id}: {new_score} ({new_version}) - {new_severity}")
                updated += 1
            else:
                logger.info(f"ℹ️ {cve_id}: Score toujours à 0 (pas encore analysé par NVD)")
                still_zero += 1
            
            # Pause pour éviter le rate limiting NVD (5 requêtes/30 secondes)
            time.sleep(6)
            
        except Exception as e:
            logger.error(f"❌ Erreur pour {cve_id}: {str(e)}")
            continue
    
    conn.close()
    
    print("\n" + "="*80)
    print("📊 RÉSUMÉ")
    print("="*80)
    print(f"✅ Mis à jour: {updated}")
    print(f"⚠️ Non trouvés: {not_found}")
    print(f"ℹ️ Score toujours à 0: {still_zero}")
    print(f"📊 Total traité: {updated + not_found + still_zero}")

if __name__ == "__main__":
    try:
        update_cvss_scores()
        print("\n🎉 MISE À JOUR TERMINÉE!")
    except Exception as e:
        logger.error(f"❌ Erreur fatale: {str(e)}")
        import traceback
        traceback.print_exc()
