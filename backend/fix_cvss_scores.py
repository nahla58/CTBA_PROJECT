#!/usr/bin/env python3
"""
Fix CVSS scores for CVEdetails CVEs by calling the detailed endpoint
"""
import sqlite3
import requests
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DB_PATH = 'ctba_platform.db'
API_TOKEN = os.environ.get('CVEDETAILS_API_TOKEN')

if not API_TOKEN:
    logger.error("CVEDETAILS_API_TOKEN not set")
    exit(1)

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get all CVEdetails with CVSS = 0
cursor.execute("""
    SELECT cve_id FROM cves 
    WHERE source_primary = 'cvedetails' AND cvss_score = 0.0
    LIMIT 5
""")

cvedetails_cves = cursor.fetchall()
logger.info(f"Found {len(cvedetails_cves)} CVEdetails CVEs with CVSS = 0")

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

updated_count = 0
for row in cvedetails_cves:
    cve_id = row['cve_id']
    logger.info(f"Fetching details for {cve_id}...")
    
    try:
        # Try to get details from CVE Details API
        api_url = f"https://www.cvedetails.com/api/v1/vulnerability/{cve_id}"
        response = requests.get(api_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            cvss = data.get('cvss', {})
            cvss_score = 0
            
            if isinstance(cvss, dict):
                cvss_score = float(cvss.get('score', 0) or 0)
            else:
                cvss_score = float(cvss or 0)
            
            logger.info(f"  {cve_id}: CVSS = {cvss_score}")
            
            # Update database
            cursor.execute(
                "UPDATE cves SET cvss_score = ? WHERE cve_id = ?",
                (cvss_score, cve_id)
            )
            updated_count += 1
        else:
            logger.warning(f"  API returned {response.status_code} for {cve_id}")
    except Exception as e:
        logger.error(f"  Error fetching {cve_id}: {e}")

conn.commit()
conn.close()
logger.info(f"Updated {updated_count} CVEs with CVSS scores")
