# fichier : test_nvd_corrige.py
import requests
import json
from datetime import datetime, timezone, timedelta

def test_nvd_api_correct():
    print("🧪 Test NVD avec filtre PUBLICATION...")
    
    # Filtrer par DATE DE PUBLICATION (pas modification)
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=1)  # CVE publiées hier
    
    start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S")
    end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S")
    
    print(f"📅 Publications entre : {start_str} → {end_str}")
    
    # API NVD avec filtre PUBLICATION
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_str,    # ⚠️ CHANGÉ ICI !
        "pubEndDate": end_str,        # ⚠️ CHANGÉ ICI !
        "resultsPerPage": 10
    }
    
    print(f"🌐 Appel avec paramètres : {params}")
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        print(f"\n✅ SUCCÈS ! Code HTTP : {response.status_code}")
        print(f"📦 CVE PUBLIÉES dans les 24h : {data.get('totalResults', 0)}")
        
        # Afficher les CVE
        vulnerabilities = data.get('vulnerabilities', [])
        for i, vuln in enumerate(vulnerabilities[:5], 1):
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', 'N/A')
            published = cve.get('published', 'N/A')
            
            # Description
            desc = cve.get('descriptions', [{}])[0].get('value', 'Pas de description')
            
            # Sévérité
            metrics = cve.get('metrics', {})
            severity = 'NON CLASSÉ'
            score = 'N/A'
            
            if 'cvssMetricV31' in metrics:
                severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            elif 'cvssMetricV30' in metrics:
                severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
                score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics:
                score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                # Convertir score V2 en sévérité
                if score >= 7.0: severity = 'HIGH'
                elif score >= 4.0: severity = 'MEDIUM'
                else: severity = 'LOW'
            
            print(f"\n{'='*60}")
            print(f"CVE #{i}: {cve_id}")
            print(f"Publiée le : {published}")
            print(f"Sévérité : {severity} (Score: {score})")
            print(f"Description : {desc[:150]}...")
        
        if data.get('totalResults', 0) == 0:
            print("\n⚠️ Aucune CVE publiée dans les dernières 24h.")
            print("   Essaie avec 2-3 jours :")
            print("   start_date = end_date - timedelta(days=3)")
            
    except Exception as e:
        print(f"\n❌ ERREUR : {type(e).__name__}: {e}")

if __name__ == "__main__":
    test_nvd_api_correct()
    input("\n👆 Appuie sur ENTRÉE pour quitter...")