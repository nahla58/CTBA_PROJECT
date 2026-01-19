#!/usr/bin/env python3
"""Test le endpoint /api/cves avec force_refresh=true"""
import requests
import json

print("\n" + "="*70)
print("TEST: GET /api/cves?limit=50&force_refresh=true")
print("="*70)

try:
    url = "http://localhost:8000/api/cves?limit=50&force_refresh=true"
    print(f"\nEnvoie une requête à: {url}\n")
    
    response = requests.get(url, timeout=60)
    
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"\nClés de réponse: {list(data.keys())}")
        print(f"Nombre de CVEs retournés: {len(data.get('cves', []))}")
        
        if data.get('cves'):
            first_cve = data['cves'][0]
            print(f"\nPremier CVE exemple:")
            print(f"  - CVE ID: {first_cve.get('cve_id')}")
            print(f"  - Source: {first_cve.get('source')}")
            print(f"  - Severity: {first_cve.get('severity')}")
            print(f"  - Status: {first_cve.get('status')}")
            
            if first_cve.get('affected_products'):
                print(f"  - Produits affectés: {first_cve['affected_products'][:2]}")
        
        print("\n✅ Endpoint fonctionne correctement!")
    else:
        print(f"\n❌ Erreur: {response.text}")

except requests.exceptions.ConnectionError:
    print("❌ Erreur: Impossible de se connecter au backend (http://localhost:8000)")
    print("   Assurez-vous que le backend est en cours d'exécution")
except Exception as e:
    print(f"❌ Erreur: {e}")

print("="*70)
