#!/usr/bin/env python3
"""
Test l'API CVE.org pour comprendre sa structure
"""
import requests
import json

def test_cveorg_api():
    """Test CVE.org API"""
    
    # CVE.org API endpoint - rechercher CVEs récentes
    url = "https://cveawg.mitre.org/api/cve"
    
    # Test 1: Récupérer un seul CVE pour voir la structure
    cve_id = "CVE-2026-1149"
    print(f"\n=== TEST 1: Récupérer {cve_id} ===")
    
    try:
        response = requests.get(f"{url}/{cve_id}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Status: {response.status_code}")
            print(f"Clés principales: {list(data.keys())}")
            
            # Afficher la structure complète
            print("\n📋 Structure complète:")
            print(json.dumps(data, indent=2)[:2000])
        else:
            print(f"❌ Status: {response.status_code}")
            print(f"Response: {response.text[:500]}")
    except Exception as e:
        print(f"❌ Erreur: {e}")
    
    # Test 2: Chercher via l'API de recherche
    print(f"\n=== TEST 2: Rechercher CVEs récentes ===")
    
    search_url = "https://cveawg.mitre.org/api/cves"
    params = {
        "limit": 5,
        "year": 2026
    }
    
    try:
        response = requests.get(search_url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Status: {response.status_code}")
            print(f"Clés principales: {list(data.keys())}")
            
            if 'cves' in data:
                print(f"Nombre de CVEs: {len(data['cves'])}")
                if data['cves']:
                    first_cve = data['cves'][0]
                    print(f"\n📋 Premier CVE:")
                    print(json.dumps(first_cve, indent=2)[:2000])
        else:
            print(f"❌ Status: {response.status_code}")
            print(f"Response: {response.text[:500]}")
    except Exception as e:
        print(f"❌ Erreur: {e}")

    # Test 3: Vérifier la structure des affectations
    print(f"\n=== TEST 3: Analyser les affectations (affected) ===")
    
    try:
        response = requests.get(f"{url}/{cve_id}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            # CVE.org structure:
            # {
            #   "cveMetadata": {...},
            #   "containers": {
            #     "cna": {
            #       "affected": [
            #         {
            #           "vendor": "...",
            #           "product": "...",
            #           "versions": [...]
            #         }
            #       ]
            #     }
            #   }
            # }
            
            containers = data.get('containers', {})
            cna = containers.get('cna', {})
            affected = cna.get('affected', [])
            
            print(f"Nombre de produits affectés: {len(affected)}")
            
            for i, product_info in enumerate(affected[:3]):
                print(f"\n📦 Produit {i+1}:")
                print(f"  Vendor: {product_info.get('vendor', 'N/A')}")
                print(f"  Product: {product_info.get('product', 'N/A')}")
                versions = product_info.get('versions', [])
                print(f"  Versions affectées: {len(versions)}")
                if versions:
                    print(f"    Exemples: {[v.get('version', 'N/A') for v in versions[:3]]}")
        else:
            print(f"❌ Status: {response.status_code}")
    except Exception as e:
        print(f"❌ Erreur: {e}")

if __name__ == "__main__":
    test_cveorg_api()
