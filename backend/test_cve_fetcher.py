"""
Test du service de récupération des CVEs depuis NVD
Vérifie que les scores CVSS sont correctement extraits
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.cve_fetcher_service import CVEFetcherService
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def test_fetch_recent_cves():
    """Test de récupération des CVEs récents"""
    print("\n" + "="*80)
    print("🧪 TEST: Récupération des CVEs des 7 derniers jours")
    print("="*80)
    
    cves = CVEFetcherService.fetch_recent_cves_from_nvd(days=7, limit=10)
    
    if not cves:
        print("⚠️ Aucun CVE récupéré (possible si aucun CVE publié récemment)")
        return False
    
    print(f"\n✅ {len(cves)} CVEs récupérés\n")
    
    # Vérifier que les scores ne sont pas tous à 0
    scores = [c.get('cvss_score', 0) for c in cves]
    non_zero_scores = [s for s in scores if s > 0]
    
    print("📊 Analyse des scores CVSS:")
    print(f"   - CVEs avec score > 0: {len(non_zero_scores)}/{len(cves)}")
    print(f"   - Score min: {min(scores)}")
    print(f"   - Score max: {max(scores)}")
    print(f"   - Score moyen: {sum(scores)/len(scores):.1f}")
    
    # Afficher quelques exemples
    print("\n📋 Exemples de CVEs récupérés:\n")
    for i, cve in enumerate(cves[:5], 1):
        print(f"{i}. {cve['cve_id']}")
        print(f"   Score CVSS: {cve['cvss_score']} ({cve['cvss_version']})")
        print(f"   Sévérité: {cve['severity']}")
        print(f"   Description: {cve['description'][:100]}...")
        print(f"   Produits: {cve['affected_products'][:2]}")
        print()
    
    # Vérification
    if len(non_zero_scores) == 0:
        print("❌ ÉCHEC: Tous les scores sont à 0!")
        return False
    
    print("✅ SUCCÈS: Les scores CVSS sont correctement extraits!")
    return True

def test_search_cves():
    """Test de recherche par mot-clé"""
    print("\n" + "="*80)
    print("🧪 TEST: Recherche de CVEs (mot-clé: 'Windows')")
    print("="*80)
    
    cves = CVEFetcherService.search_cves_by_keyword("Windows", limit=5)
    
    if not cves:
        print("⚠️ Aucun CVE trouvé pour 'Windows'")
        return False
    
    print(f"\n✅ {len(cves)} CVEs trouvés\n")
    
    for i, cve in enumerate(cves, 1):
        print(f"{i}. {cve['cve_id']} - Score: {cve['cvss_score']} - {cve['severity']}")
    
    return True

def test_cve_from_cveorg():
    """Test de récupération depuis CVE.org"""
    print("\n" + "="*80)
    print("🧪 TEST: Récupération depuis CVE.org (CVE-2024-21413)")
    print("="*80)
    
    cve = CVEFetcherService.fetch_cve_from_cveorg("CVE-2024-21413")
    
    if not cve:
        print("⚠️ CVE non trouvé dans CVE.org")
        return False
    
    print(f"\n✅ CVE récupéré depuis CVE.org")
    print(f"   ID: {cve['cve_id']}")
    print(f"   Description: {cve['description'][:150]}...")
    print(f"   Produits affectés: {len(cve['affected_products'])}")
    print(f"   Publié: {cve['published_date']}")
    
    return True

if __name__ == "__main__":
    print("\n" + "🚀 DÉMARRAGE DES TESTS DU SERVICE CVE FETCHER" + "\n")
    
    results = []
    
    try:
        results.append(("Récupération CVEs récents", test_fetch_recent_cves()))
    except Exception as e:
        print(f"\n❌ Erreur test CVEs récents: {e}")
        results.append(("Récupération CVEs récents", False))
    
    try:
        results.append(("Recherche par mot-clé", test_search_cves()))
    except Exception as e:
        print(f"\n❌ Erreur test recherche: {e}")
        results.append(("Recherche par mot-clé", False))
    
    try:
        results.append(("Récupération CVE.org", test_cve_from_cveorg()))
    except Exception as e:
        print(f"\n❌ Erreur test CVE.org: {e}")
        results.append(("Récupération CVE.org", False))
    
    # Résumé
    print("\n" + "="*80)
    print("📊 RÉSUMÉ DES TESTS")
    print("="*80)
    
    for test_name, success in results:
        status = "✅ SUCCÈS" if success else "❌ ÉCHEC"
        print(f"{status}: {test_name}")
    
    total = len(results)
    passed = sum(1 for _, s in results if s)
    
    print(f"\nRésultat final: {passed}/{total} tests réussis")
    
    if passed == total:
        print("\n🎉 TOUS LES TESTS SONT PASSÉS!")
    else:
        print("\n⚠️ Certains tests ont échoué")
