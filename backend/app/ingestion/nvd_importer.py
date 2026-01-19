# backend/app/ingestion/nvd_importer.py
import sqlite3
import requests
from datetime import datetime, timezone, timedelta
import time
from main import format_date_for_display
import pytz
import re

def sort_cves_by_cvss(cves: list) -> list:
    """
    Sort CVEs by CVSS score in descending order, prioritizing CVSS 4.0 over 3.1.
    """
    def get_cvss_score(item):
        # item can be either the vuln wrapper or the inner cve dict
        metrics = {}
        if isinstance(item, dict):
            if 'metrics' in item:
                metrics = item.get('metrics', {})
            else:
                cve = item.get('cve', {})
                metrics = cve.get('metrics', {})

        cvss_v4 = metrics.get('cvssMetricV4', [{}])
        cvss_v3 = metrics.get('cvssMetricV31', [{}])

        if cvss_v4 and len(cvss_v4) > 0:
            return cvss_v4[0].get('cvssData', {}).get('baseScore', 0)
        elif cvss_v3 and len(cvss_v3) > 0:
            return cvss_v3[0].get('cvssData', {}).get('baseScore', 0)
        return 0

    return sorted(cves, key=get_cvss_score, reverse=True)

def get_cvss_score(cve):
    """Extract CVSS score from CVE data or vuln wrapper.

    Accepts either the vuln wrapper (with 'cve') or the inner cve dict.
    """
    metrics = {}
    if isinstance(cve, dict):
        if 'metrics' in cve:
            metrics = cve.get('metrics', {})
        else:
            inner = cve.get('cve', {})
            metrics = inner.get('metrics', {})

    cvss_v4 = metrics.get('cvssMetricV4', [{}])
    cvss_v3 = metrics.get('cvssMetricV31', [{}])

    if cvss_v4 and len(cvss_v4) > 0:
        return cvss_v4[0].get('cvssData', {}).get('baseScore', 0)
    elif cvss_v3 and len(cvss_v3) > 0:
        return cvss_v3[0].get('cvssData', {}).get('baseScore', 0)
    return 0


def parse_cpe_uri(cpe_uri: str) -> tuple:
    """Parse a CPE URI and return (vendor, product).

    Supports CPE 2.3 (cpe:2.3:part:vendor:product:...) and
    legacy CPE 2.2 (cpe:/part:vendor:product:...). Returns (vendor, product)
    or (None, None) if parsing fails.
    """
    if not cpe_uri or not isinstance(cpe_uri, str):
        return (None, None)

    try:
        # CPE 2.3 -> cpe:2.3:part:vendor:product:version:...
        if cpe_uri.startswith('cpe:2.3:'):
            parts = cpe_uri.split(':')
            # parts: ['cpe', '2.3', part, vendor, product, ...]
            if len(parts) >= 5:
                vendor = parts[3].strip() or None
                product = parts[4].strip() or None
                return (vendor, product)

        # CPE 2.2 -> cpe:/part:vendor:product:version
        if cpe_uri.startswith('cpe:/'):
            # normalize and split after 'cpe:/'
            tail = cpe_uri[5:]
            parts = tail.split(':')
            # parts: [part, vendor, product, ...]
            if len(parts) >= 3:
                vendor = parts[1].strip() or None
                product = parts[2].strip() or None
                return (vendor, product)

        # Fallback: try to find vendor/product with regex (vendor:product)
        m = re.search(r'[:/](?P<vendor>[^:/]+)[:/](?P<product>[^:/]+)', cpe_uri)
        if m:
            return (m.group('vendor').strip(), m.group('product').strip())
    except Exception:
        pass

    return (None, None)


def extract_cpe_uris(vuln: dict) -> list:
    """Walk the vuln dict to collect any cpe23Uri or cpe_uri occurrences."""
    found = set()

    def recurse(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ('cpe23Uri', 'cpe_uri', 'cpe23uri') and isinstance(v, str):
                    found.add(v)
                else:
                    recurse(v)
        elif isinstance(obj, list):
            for item in obj:
                recurse(item)

    recurse(vuln)
    return list(found)

def format_date_for_storage(date_str: str) -> str:
    """
    Format a date for storage in database.
    Returns ISO 8601 format: YYYY-MM-DD HH:MM:SS
    """
    if not date_str:
        return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        # NVD format: "2024-01-18T15:30:00.000Z"
        date_str = date_str.strip()
        if date_str.endswith('Z'):
            date_str = date_str[:-1] + '+00:00'
        
        # Parse the date
        dt = datetime.fromisoformat(date_str)
        
        # Ensure it's UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        
        # Format for database storage
        return dt.strftime('%Y-%m-%d %H:%M:%S')
        
    except Exception as e:
        print(f"Error formatting date {date_str}: {e}")
        return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

def import_recent_cves():
    """Importe les CVE récentes depuis NVD dans la base"""
    print("🔄 Importation des CVE depuis NVD...")
    
    # Date : dernières 24h
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(hours=24)
    
    # Appel API NVD
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S") + ".000",
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S") + ".000",
        "resultsPerPage": 50
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        data = response.json()
        
        cves_count = data.get('totalResults', 0)
        print(f"📦 {cves_count} CVE trouvées sur NVD")
        
        # Trier les CVEs par CVSS
        sorted_cves = sort_cves_by_cvss(data.get('vulnerabilities', []))
        
        # Connexion base
        conn = sqlite3.connect("ctba.db")
        cursor = conn.cursor()
        
        added = 0
        for vuln in sorted_cves:
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

            # Extraire et formater la date de publication POUR LE STOCKAGE
            published_date_raw = cve_data.get('published', '')
            
            # Utiliser la nouvelle fonction pour formater pour le stockage
            published_date = format_date_for_storage(published_date_raw)
            
            # Score CVSS
            cvss_score = get_cvss_score(vuln)
            
            # Ajouter à la base
            cursor.execute(
                "INSERT INTO cves (cve_id, description, cvss_score, published_date) VALUES (?, ?, ?, ?)",
                (cve_id, description, cvss_score, published_date)
            )
            added += 1

            # Extraire les CPE URIs depuis la vuln et insérer les produits affectés
            try:
                cpe_uris = extract_cpe_uris(vuln)
                for uri in cpe_uris:
                    vendor, product = parse_cpe_uri(uri)
                    if not vendor or not product:
                        continue

                    # Vérifier doublon (vendor + product)
                    cursor.execute(
                        "SELECT 1 FROM affected_products WHERE cve_id = ? AND vendor = ? AND product = ?",
                        (cve_id, vendor, product)
                    )
                    if cursor.fetchone():
                        continue

                    cursor.execute(
                        "INSERT INTO affected_products (cve_id, vendor, product) VALUES (?, ?, ?)",
                        (cve_id, vendor, product)
                    )
            except Exception as e:
                print(f"Warning: failed to extract/insert affected products for {cve_id}: {e}")

        conn.commit()
        conn.close()
        print(f"✅ {added} CVE ajoutées à la base")
        
        # Tester que les dates sont bien formatées
        print("\n=== Vérification des dates ajoutées ===")
        test_imported_dates()
        
    except Exception as e:
        print(f"❌ Erreur lors de l'importation des CVE : {e}")

def test_imported_dates():
    """Tester les dates importées"""
    conn = sqlite3.connect("ctba.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT cve_id, published_date FROM cves ORDER BY id DESC LIMIT 5")
    rows = cursor.fetchall()
    
    for row in rows:
        print(f"\nCVE: {row[0]}")
        print(f"Date en base: {row[1]}")
        
        # Tester avec format_date_for_display
        formatted = format_date_for_display(row[1])
        print(f"Formattée pour affichage: {formatted.get('formatted', 'N/A')}")
    
    conn.close()

if __name__ == "__main__":
    import_recent_cves()
    input("\n👆 Appuie sur ENTRÉE pour quitter...")