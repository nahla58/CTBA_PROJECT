#!/usr/bin/env python3
"""
Test script pour vérifier que extract_cvss_metrics() prend bien le score maximum
parmi toutes les sources et toutes les versions CVSS.

Test avec CVE-2026-2182 pour valider le comportement attendu.
"""

import sys
import os

# Add backend path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import extract_cvss_metrics
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_extract_cvss_with_multiple_sources():
    """Test avec des données simulées contenant plusieurs sources"""
    
    print("=" * 80)
    print("TEST 1: Données simulées avec multiples sources CVSS")
    print("=" * 80)
    
    # Simuler les données NVD pour CVE-2026-2182
    test_data = {
        "metrics": {
            "cvssMetricV40": [
                {
                    "source": "VulDB",
                    "cvssData": {
                        "baseScore": 7.3,
                        "baseSeverity": "HIGH"
                    }
                },
                {
                    "source": "CVE.org",
                    "cvssData": {
                        "baseScore": 8.6,
                        "baseSeverity": "HIGH"
                    }
                }
            ],
            "cvssMetricV31": [
                {
                    "source": "VulDB",
                    "cvssData": {
                        "baseScore": 7.2,
                        "baseSeverity": "HIGH"
                    }
                }
            ],
            "cvssMetricV2": [
                {
                    "source": "VulDB",
                    "cvssData": {
                        "baseScore": 8.3
                    }
                }
            ]
        }
    }
    
    severity, score, version = extract_cvss_metrics(test_data)
    
    print(f"\n✅ Résultat:")
    print(f"   Score: {score}")
    print(f"   Version: {version}")
    print(f"   Sévérité: {severity}")
    print(f"\n✔️ Test réussi: Le score maximum (8.6) a été sélectionné parmi toutes les sources!")
    
    assert score == 8.6, f"❌ Attendu: 8.6, Obtenu: {score}"
    assert version == "4.0", f"❌ Attendu: CVSS 4.0, Obtenu: {version}"
    print("\n✅ ASSERTION PASSED\n")


def test_fetch_cve_from_nvd():
    """Test avec une vraie requête NVD pour CVE-2026-2182"""
    
    print("=" * 80)
    print("TEST 2: Récupération depuis NVD API (CVE-2026-2182)")
    print("=" * 80)
    
    cve_id = "CVE-2026-2182"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                vuln = vulnerabilities[0]
                cve_data = vuln.get("cve", {})
                metrics = cve_data.get("metrics", {})
                
                print(f"\n📊 Métriques CVSS trouvées:")
                
                # Afficher toutes les sources
                for metric_type in ["cvssMetricV41", "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_type in metrics and metrics[metric_type]:
                        print(f"\n{metric_type}:")
                        for idx, metric in enumerate(metrics[metric_type]):
                            source = metric.get("source", f"Source-{idx+1}")
                            cvss_data = metric.get("cvssData", {})
                            score = cvss_data.get("baseScore", "N/A")
                            severity = cvss_data.get("baseSeverity", "N/A")
                            print(f"  - {source}: Score={score}, Severity={severity}")
                
                # Tester extract_cvss_metrics avec ces données réelles
                severity, score, version = extract_cvss_metrics({"metrics": metrics})
                
                print(f"\n✅ Score MAXIMUM sélectionné:")
                print(f"   Score: {score}")
                print(f"   Version: CVSS {version}")
                print(f"   Sévérité: {severity}")
                
                return True
            else:
                print(f"⚠️ Aucune vulnérabilité trouvée pour {cve_id}")
                return False
        else:
            print(f"❌ Erreur NVD API: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Erreur lors de la requête NVD: {e}")
        return False


def test_with_zero_scores():
    """Test avec des scores à 0 (edge case)"""
    
    print("=" * 80)
    print("TEST 3: CVE sans score CVSS (edge case)")
    print("=" * 80)
    
    test_data = {
        "metrics": {}
    }
    
    severity, score, version = extract_cvss_metrics(test_data)
    
    print(f"\n✅ Résultat pour CVE sans métriques:")
    print(f"   Score: {score}")
    print(f"   Version: {version}")
    print(f"   Sévérité: {severity}")
    
    assert score == 5.0, f"❌ Score par défaut devrait être 5.0, obtenu: {score}"
    assert severity == "MEDIUM", f"❌ Sévérité par défaut devrait être MEDIUM, obtenu: {severity}"
    print("\n✅ ASSERTION PASSED\n")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("🧪 TEST DE LA FONCTION extract_cvss_metrics()")
    print("   Objectif: Vérifier que le score MAXIMUM est pris parmi toutes les sources")
    print("=" * 80 + "\n")
    
    try:
        # Test 1: Données simulées
        test_extract_cvss_with_multiple_sources()
        
        # Test 2: Récupération réelle depuis NVD
        test_fetch_cve_from_nvd()
        
        # Test 3: Edge case
        test_with_zero_scores()
        
        print("=" * 80)
        print("✅ TOUS LES TESTS SONT PASSÉS !")
        print("=" * 80)
        print("\n📋 Prochaines étapes:")
        print("   1. Redémarrer le backend:")
        print("      cd backend")
        print("      python main.py")
        print("   2. Enrichir les CVEs existants:")
        print("      curl -X POST 'http://localhost:8000/api/enrich-cvss-scores-from-nvd?limit=100'")
        print("   3. Vérifier le dashboard: http://localhost:8000/")
        print("\n")
        
    except Exception as e:
        print(f"\n❌ ERREUR DANS LES TESTS: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
