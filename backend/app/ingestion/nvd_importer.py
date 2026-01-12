# backend/app/ingestion/nvd_importer.py
import sqlite3
import requests
from datetime import datetime, timezone, timedelta
import time

def import_recent_cves():
    """Importe les CVE récentes depuis NVD dans la base"""
    print("🔄 Importation des CVE depuis NVD...")
    
    # Date : dernières 24h
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(hours=24)
    
    # Appel API NVD
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S"),
        "resultsPerPage": 50
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        data = response.json()
        
        cves_count = data.get('totalResults', 0)
        print(f"📦 {cves_count} CVE trouvées sur NVD")
        
        # Connexion base
        conn = sqlite3.connect("ctba.db")
        cursor = conn.cursor()
        
        added = 0
        for vuln in data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            # Vérifier si existe déjà
            cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
            if cursor.fetchone():
                continue  # Déjà dans la base
            
            # Extraire description
            description = "Pas de description"
            for desc in cve_data.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extraire sévérité et score
            severity = "LOW"
            score = 0.0
            metrics = cve_data.get('metrics', {})
            
            if 'cvssMetricV31' in metrics:
                severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            elif 'cvssMetricV30' in metrics:
                severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
                score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics:
                score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                if score >= 9.0: severity = "CRITICAL"
                elif score >= 7.0: severity = "HIGH"
                elif score >= 4.0: severity = "MEDIUM"
                else: severity = "LOW"
            
            # Filtrer : seulement HIGH et CRITICAL
            if severity in ["HIGH", "CRITICAL"]:
                try:
                    cursor.execute('''
                        INSERT INTO cves (cve_id, description, severity, cvss_score, published_date)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        description[:500],  # Limiter la longueur
                        severity,
                        float(score) if score else 0.0,
                        cve_data.get('published', '')
                    ))
                    added += 1
                    print(f"  ➕ {cve_id} - {severity}")
                except Exception as e:
                    print(f"  ⚠️ Erreur avec {cve_id}: {e}")
        
        conn.commit()
        conn.close()
        
        print(f"✅ {added} nouvelles CVE ajoutées à la base")
        return added
        
    except Exception as e:
        print(f"❌ Erreur lors de l'import: {e}")
        return 0

if __name__ == "__main__":
    import_recent_cves()
    input("\n👆 Appuie sur ENTRÉE pour quitter...")