import sqlite3
import requests

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cves = ['CVE-2026-24825', 'CVE-2026-24824', 'CVE-2026-24823', 'CVE-2026-24822', 'CVE-2026-24821']

print("=" * 80)
print("DATABASE STATE")
print("=" * 80)

for cve_id in cves:
    cursor.execute('SELECT cve_id, cvss_score, cvss_version, source FROM cves WHERE cve_id = ?', (cve_id,))
    row = cursor.fetchone()
    if row:
        print(f'{row["cve_id"]}: Score={row["cvss_score"]}, Version={row["cvss_version"]}, Source={row["source"]}')
    else:
        print(f'{cve_id}: NOT FOUND IN DB')

print("\n" + "=" * 80)
print("CVE.ORG API CHECK")
print("=" * 80)

for cve_id in cves:
    try:
        url = f'https://cveawg.mitre.org/api/cve/{cve_id}'
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cvss_info = data.get('containers', {}).get('cna', {})
            metrics = cvss_info.get('metrics', [])
            
            score = None
            version = None
            if metrics:
                # Try to extract CVSS score from metrics
                for metric in metrics:
                    if 'cvssV4_0' in metric:
                        score = metric['cvssV4_0'].get('baseScore')
                        version = '4.0'
                        break
                    elif 'cvssV3_1' in metric:
                        score = metric['cvssV3_1'].get('baseScore')
                        version = '3.1'
                        break
            
            print(f'{cve_id}: Score={score}, Version={version}')
        else:
            print(f'{cve_id}: API returned {response.status_code}')
    except Exception as e:
        print(f'{cve_id}: ERROR - {str(e)}')

print("\n" + "=" * 80)
print("NVD API CHECK")
print("=" * 80)

for cve_id in cves:
    try:
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            
            if vulns:
                vuln = vulns[0]['cve']
                metrics = vuln.get('metrics', {})
                score = None
                version = None
                
                # Check CVSS versions in priority order
                if 'cvssMetricV41' in metrics and metrics['cvssMetricV41']:
                    score = metrics['cvssMetricV41'][0]['cvssData'].get('baseScore')
                    version = '4.1'
                elif 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore')
                    version = '3.1'
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    score = metrics['cvssMetricV30'][0]['cvssData'].get('baseScore')
                    version = '3.0'
                
                print(f'{cve_id}: Score={score}, Version={version}')
            else:
                print(f'{cve_id}: NOT IN NVD')
        else:
            print(f'{cve_id}: API returned {response.status_code}')
    except Exception as e:
        print(f'{cve_id}: ERROR - {str(e)}')

conn.close()
