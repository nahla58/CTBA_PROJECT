"""
Script pour corriger les scores CVSS des CVEs en les récupérant depuis CVE.org
Les scores CVSS peuvent être publiés par les CNA (CVE Numbering Authorities) sur CVE.org
"""
import sqlite3
import requests
import time
import logging
from datetime import datetime
import pytz

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DB_FILE = "ctba_platform.db"
CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve"

def extract_cvss_from_cveorg(cve_id: str):
    """
    Extrait le score CVSS depuis CVE.org
    
    Returns:
        Tuple (cvss_score, severity, cvss_version, cvss_vector) ou None
    """
    try:
        url = f"{CVEORG_BASE_URL}/{cve_id}"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            logger.debug(f"❌ {cve_id}: Non trouvé sur CVE.org")
            return None
        
        data = response.json()
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        metrics = cna.get("metrics", [])
        
        if not metrics or len(metrics) == 0:
            logger.debug(f"⚠️ {cve_id}: Pas de metrics CVSS sur CVE.org")
            return None
        
        # Prendre le premier metric
        metric = metrics[0]
        
        cvss_score = 0.0
        cvss_vector = "N/A"
        cvss_version = "N/A"
        severity = "UNKNOWN"
        
        # 🆕 CVSS v4.0 (le plus récent)
        if "cvssV4_0" in metric:
            cvss_data = metric["cvssV4_0"]
            cvss_score = float(cvss_data.get("baseScore", 0))
            cvss_vector = cvss_data.get("vectorString", "N/A")
            cvss_version = "4.0"
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        # CVSS v3.1
        elif "cvssV3_1" in metric:
            cvss_data = metric["cvssV3_1"]
            cvss_score = float(cvss_data.get("baseScore", 0))
            cvss_vector = cvss_data.get("vectorString", "N/A")
            cvss_version = "3.1"
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        # CVSS v3.0
        elif "cvssV3_0" in metric:
            cvss_data = metric["cvssV3_0"]
            cvss_score = float(cvss_data.get("baseScore", 0))
            cvss_vector = cvss_data.get("vectorString", "N/A")
            cvss_version = "3.0"
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        # CVSS v2.0
        elif "cvssV2_0" in metric:
            cvss_data = metric["cvssV2_0"]
            cvss_score = float(cvss_data.get("baseScore", 0))
            cvss_vector = cvss_data.get("vectorString", "N/A")
            cvss_version = "2.0"
            if cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        
        if cvss_score > 0:
            return (cvss_score, severity, cvss_version, cvss_vector)
        
        return None
        
    except Exception as e:
        logger.error(f"❌ {cve_id}: Erreur extraction - {str(e)}")
        return None

def fix_cvss_scores():
    """
    Corrige les scores CVSS des CVEs qui ont un score 0
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Trouver les CVEs avec score 0
    cursor.execute("""
        SELECT cve_id FROM cves 
        WHERE (cvss_score IS NULL OR cvss_score = 0 OR cvss_score = 0.0)
        AND status = 'PENDING'
        ORDER BY imported_at DESC
    """)
    
    cves_without_score = [row[0] for row in cursor.fetchall()]
    
    if not cves_without_score:
        logger.info("✅ Aucun CVE sans score trouvé")
        conn.close()
        return
    
    logger.info(f"📊 {len(cves_without_score)} CVEs sans score CVSS trouvés")
    logger.info("🔄 Vérification des scores sur CVE.org...")
    
    fixed_count = 0
    not_available = 0
    
    for i, cve_id in enumerate(cves_without_score, 1):
        try:
            logger.info(f"[{i}/{len(cves_without_score)}] Vérification {cve_id}...")
            
            # Extraire depuis CVE.org
            result = extract_cvss_from_cveorg(cve_id)
            
            if result:
                cvss_score, severity, cvss_version, cvss_vector = result
                
                # Mettre à jour la base de données
                cursor.execute("""
                    UPDATE cves 
                    SET cvss_score = ?, severity = ?, cvss_version = ?, last_updated = ?
                    WHERE cve_id = ?
                """, (
                    cvss_score,
                    severity,
                    cvss_version,
                    datetime.now(pytz.UTC).isoformat(),
                    cve_id
                ))
                conn.commit()
                fixed_count += 1
                logger.info(f"   ✅ {cve_id}: Score mis à jour → {cvss_score} ({severity})")
            else:
                not_available += 1
                logger.debug(f"   ⏳ {cve_id}: Score pas encore publié sur CVE.org")
            
            # Rate limiting
            time.sleep(0.6)
            
        except Exception as e:
            logger.error(f"   ❌ {cve_id}: Erreur - {str(e)}")
            continue
    
    conn.close()
    
    logger.info("=" * 80)
    logger.info(f"✅ Correction terminée:")
    logger.info(f"   - Total vérifié: {len(cves_without_score)}")
    logger.info(f"   - Scores corrigés: {fixed_count}")
    logger.info(f"   - Pas encore publié: {not_available}")
    logger.info("=" * 80)

if __name__ == "__main__":
    logger.info("🚀 Démarrage de la correction des scores CVSS depuis CVE.org...")
    fix_cvss_scores()
