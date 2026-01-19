"""
MSRC (Microsoft Security Response Center) Importer
Imports CVEs and security bulletins from Microsoft's security feed
"""

import requests
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class MSRCImporter:
    """
    Import CVEs from Microsoft Security Response Center (MSRC)
    Provides Microsoft-specific security vulnerability data including monthly bulletins
    """
    
    BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0"
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CTBA-CVE-Importer/1.0',
            'Accept': 'application/json'
        })
    
    def get_monthly_bulletins(self, year: int, month: int) -> List[Dict[str, Any]]:
        """
        Get Microsoft security bulletins for a specific month
        
        Args:
            year: Year (e.g., 2024)
            month: Month (1-12)
            
        Returns:
            List of CVE records from the month's bulletins
        """
        try:
            # MSRC CVRF API endpoint for monthly updates
            month_str = f"{month:02d}"
            url = f"{self.BASE_URL}/updates/{year}-{month_str}"
            
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            cves = self._extract_cves_from_cvrf(data)
            
            logger.info(f"MSRC: Found {len(cves)} CVEs from {year}-{month_str}")
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"MSRC API error ({year}-{month_str}): {e}")
            return []
    
    def get_latest_cves(self) -> List[Dict[str, Any]]:
        """
        Get the latest CVEs from MSRC's most recent bulletin
        
        Returns:
            List of recent CVE records
        """
        try:
            # Get current date for most recent bulletin
            today = datetime.now()
            
            # Try current month, then previous month
            for offset in [0, 1]:
                month = today.month - offset
                year = today.year
                if month < 1:
                    month += 12
                    year -= 1
                
                cves = self.get_monthly_bulletins(year, month)
                if cves:
                    return cves
            
            return []
            
        except Exception as e:
            logger.error(f"MSRC latest CVEs error: {e}")
            return []
    
    def search_cves(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for CVEs in MSRC database by keyword
        
        Args:
            keyword: Search term (vendor, product, or CVE ID)
            limit: Maximum number of results
            
        Returns:
            List of matching CVE records
        """
        try:
            # MSRC updates endpoint with filtering
            params = {
                'search': keyword,
                'limit': min(limit, 100),
                'format': 'json'
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/updates",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._extract_cves_from_cvrf(data)
            
            logger.info(f"MSRC: Found {len(cves)} CVEs for '{keyword}'")
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"MSRC search error: {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get details for a specific Microsoft CVE
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-12345')
            
        Returns:
            Detailed CVE record or None
        """
        try:
            params = {'filter': f"ID eq '{cve_id}'"}
            
            response = self.session.get(
                f"{self.BASE_URL}/updates",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._extract_cves_from_cvrf(data)
            
            return cves[0] if cves else None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"MSRC: Failed to fetch {cve_id}: {e}")
            return None
    
    def _extract_cves_from_cvrf(self, cvrf_data: Dict) -> List[Dict[str, Any]]:
        """Extract CVEs from MSRC CVRF XML response (parsed to JSON)"""
        cves = []
        
        try:
            vulnerabilities = cvrf_data.get('Vulnerability', [])
            if not isinstance(vulnerabilities, list):
                vulnerabilities = [vulnerabilities]
            
            for vuln in vulnerabilities:
                cve_id = vuln.get('CVE', '')
                
                # Extract affected products
                affected_products = []
                product_tree = cvrf_data.get('ProductTree', {})
                full_product_names = product_tree.get('FullProductName', [])
                
                if not isinstance(full_product_names, list):
                    full_product_names = [full_product_names]
                
                for product in full_product_names:
                    affected_products.append({
                        'vendor': 'Microsoft',
                        'product': product.get('Value', 'Unknown'),
                        'version_affected': product.get('ProductID')
                    })
                
                # Build CVE record
                cve_record = {
                    'id': cve_id,
                    'source': 'msrc',
                    'source_url': f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                    'published': vuln.get('PublicationDate'),
                    'cvss': float(vuln.get('CVSSScoreSets', [{}])[0].get('BaseScore', 0)),
                    'cvss_vector': vuln.get('CVSSScoreSets', [{}])[0].get('Vector'),
                    'cwe_id': vuln.get('CWE'),
                    'description': vuln.get('Description', {}).get('Value', ''),
                    'affected_products': affected_products,
                    'references': vuln.get('References', []),
                    'remediation': vuln.get('Remediation'),
                    'threat': vuln.get('Threat'),
                    'impact': vuln.get('Impact'),
                }
                
                if cve_id:
                    cves.append(cve_record)
        
        except Exception as e:
            logger.error(f"Error extracting CVEs from CVRF: {e}")
        
        return cves
