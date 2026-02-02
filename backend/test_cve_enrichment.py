"""
Script de test pour l'enrichissement CVE.org
Teste les fonctionnalités du service d'enrichissement
"""
import sys
import os

# Ajouter le chemin du backend
backend_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, backend_path)

from services.cve_enrichment_service import CVEEnrichmentService
import sqlite3
import logging

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_fetch_single_cve():
    """Test de récupération d'un CVE depuis CVE.org"""
    print("\n" + "="*60)
    print("TEST 1: Récupération d'un CVE depuis CVE.org")
    print("="*60)
    
    cve_id = "CVE-2024-21413"  # CVE connu avec produits affectés
    
    logger.info(f"Récupération de {cve_id}...")
    data = CVEEnrichmentService.fetch_cve_from_cveorg(cve_id)
    
    if data:
        print(f"✅ CVE {cve_id} récupéré avec succès")
        
        # Extraire les produits
        products = CVEEnrichmentService.extract_affected_products(data)
        print(f"📦 Produits affectés: {len(products)}")
        for vendor, product in products[:5]:
            print(f"   - {vendor}: {product}")
        
        # Extraire les dates
        date_pub, date_upd = CVEEnrichmentService.extract_dates(data)
        print(f"📅 Date publication: {date_pub}")
        print(f"📅 Date mise à jour: {date_upd}")
    else:
        print(f"❌ Impossible de récupérer {cve_id}")
    
    return data is not None


def test_enrich_specific_cves():
    """Test d'enrichissement de CVEs spécifiques"""
    print("\n" + "="*60)
    print("TEST 2: Enrichissement de CVEs spécifiques")
    print("="*60)
    
    # Liste de CVEs connus
    cve_list = [
        "CVE-2024-21413",  # Microsoft Outlook
        "CVE-2024-21351",  # Windows
    ]
    
    logger.info(f"Enrichissement de {len(cve_list)} CVEs...")
    stats = CVEEnrichmentService.enrich_specific_cves(cve_list)
    
    print(f"\n📊 Statistiques d'enrichissement:")
    print(f"   ✅ CVEs traités: {stats['total_processed']}")
    print(f"   📦 Produits ajoutés: {stats['total_products_added']}")
    print(f"   ⏭️  Produits skippés: {stats['total_products_skipped']}")
    print(f"   📅 Dates mises à jour: {stats['total_dates_updated']}")
    print(f"   ❌ Erreurs: {stats['total_errors']}")
    print(f"   ⏱️  Durée: {stats['duration']}s")
    
    return stats['total_processed'] > 0


def test_database_integration():
    """Test de l'intégration avec la base de données"""
    print("\n" + "="*60)
    print("TEST 3: Vérification base de données")
    print("="*60)
    
    db_path = os.path.join(backend_path, "ctba_platform.db")
    
    if not os.path.exists(db_path):
        print(f"❌ Base de données non trouvée: {db_path}")
        return False
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Vérifier les CVEs enrichis avec CVE.org
    cursor.execute("""
        SELECT cve_id, source, published_date, last_updated
        FROM cves
        WHERE source LIKE '%cveorg%'
        LIMIT 5
    """)
    
    rows = cursor.fetchall()
    print(f"\n✅ {len(rows)} CVEs enrichis avec CVE.org trouvés")
    
    for row in rows:
        print(f"\n   📋 {row['cve_id']}")
        print(f"      Source: {row['source']}")
        print(f"      Publié: {row['published_date']}")
        print(f"      MAJ: {row['last_updated']}")
        
        # Vérifier les produits
        cursor.execute("""
            SELECT vendor, product, confidence
            FROM affected_products
            WHERE cve_id = ?
            LIMIT 3
        """, (row['cve_id'],))
        
        products = cursor.fetchall()
        if products:
            print(f"      Produits ({len(products)}):")
            for prod in products:
                print(f"         - {prod['vendor']}: {prod['product']} (conf: {prod['confidence']})")
    
    conn.close()
    return len(rows) > 0


def test_rate_limiting():
    """Test du rate limiting"""
    print("\n" + "="*60)
    print("TEST 4: Rate Limiting")
    print("="*60)
    
    import time
    
    cve_ids = ["CVE-2024-21413", "CVE-2024-21351", "CVE-2024-0001"]
    
    start_time = time.time()
    
    for cve_id in cve_ids:
        logger.info(f"Récupération {cve_id}...")
        data = CVEEnrichmentService.fetch_cve_from_cveorg(cve_id)
        if data:
            print(f"   ✅ {cve_id} récupéré")
        else:
            print(f"   ⏭️  {cve_id} non disponible")
    
    duration = time.time() - start_time
    expected_min = len(cve_ids) * CVEEnrichmentService.RATE_LIMIT_DELAY
    
    print(f"\n⏱️  Durée totale: {duration:.2f}s")
    print(f"⏱️  Minimum attendu: {expected_min:.2f}s (rate limit)")
    
    if duration >= expected_min:
        print("✅ Rate limiting fonctionne correctement")
        return True
    else:
        print("⚠️ Rate limiting pourrait être trop rapide")
        return False


def main():
    """Exécuter tous les tests"""
    print("\n" + "="*60)
    print("🧪 TESTS D'ENRICHISSEMENT CVE.ORG")
    print("="*60)
    
    results = []
    
    # Test 1: Fetch single CVE
    try:
        results.append(("Fetch single CVE", test_fetch_single_cve()))
    except Exception as e:
        print(f"❌ Erreur Test 1: {e}")
        results.append(("Fetch single CVE", False))
    
    # Test 2: Enrich specific CVEs
    try:
        results.append(("Enrich specific CVEs", test_enrich_specific_cves()))
    except Exception as e:
        print(f"❌ Erreur Test 2: {e}")
        results.append(("Enrich specific CVEs", False))
    
    # Test 3: Database integration
    try:
        results.append(("Database integration", test_database_integration()))
    except Exception as e:
        print(f"❌ Erreur Test 3: {e}")
        results.append(("Database integration", False))
    
    # Test 4: Rate limiting
    try:
        results.append(("Rate limiting", test_rate_limiting()))
    except Exception as e:
        print(f"❌ Erreur Test 4: {e}")
        results.append(("Rate limiting", False))
    
    # Résumé
    print("\n" + "="*60)
    print("📊 RÉSUMÉ DES TESTS")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\n🎯 Résultat global: {passed}/{total} tests réussis")
    
    if passed == total:
        print("✅ Tous les tests sont passés avec succès!")
        return 0
    else:
        print("⚠️ Certains tests ont échoué")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
