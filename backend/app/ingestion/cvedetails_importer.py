"""
CVE Details Importer
Imports CVEs from cvedetails.com API and data feeds
"""

import requests
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging
import sqlite3
from main import format_date_for_display

logger = logging.getLogger(__name__)


class CVEDetailsImporter:
    """
    Import CVEs from cvedetails.com
    Provides access to detailed vulnerability information including CVSS scores,
    attack vectors, and affected products
    """
    
    BASE_URL = "https://cvedetails.com"
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CTBA-CVE-Importer/1.0'
        })
    
    def search_cves(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for CVEs by keyword on cvedetails.com
        
        Args:
            keyword: Search term (vendor or product name)
            limit: Maximum number of results
            
        Returns:
            List of CVE records with details
        """
        try:
            # CVE Details search endpoint - search by vendor or product
            # Format: https://www.cvedetails.com/cve/CVE-XXXX-XXXXX/
            params = {
                'search': keyword,
                'limit': min(limit, 100),
                'format': 'json'
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/search",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._normalize_cvedetails_response(data)
            
            logger.info(f"CVE Details: Found {len(cves)} CVEs for '{keyword}'")
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"CVE Details API error: {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific CVE from cvedetails.com
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-12345')
            
        Returns:
            Detailed CVE record or None if not found
        """
        try:
            params = {'format': 'json'}
            
            response = self.session.get(
                f"{self.BASE_URL}/cve/{cve_id}",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return self._normalize_single_cve(data)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"CVE Details: Failed to fetch {cve_id}: {e}")
            return None
    
    def get_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get recently published CVEs from cvedetails.com
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of recent CVE records
        """
        try:
            params = {
                'days': days,
                'format': 'json'
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/recent",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._normalize_cvedetails_response(data)
            
            logger.info(f"CVE Details: Found {len(cves)} CVEs from last {days} days")
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"CVE Details recent CVEs error: {e}")
            return []
    
    def _normalize_cvedetails_response(self, data: Dict) -> List[Dict[str, Any]]:
        """Normalize CVE Details API response to standard format"""
        if isinstance(data, dict) and 'cves' in data:
            return [self._normalize_single_cve(cve) for cve in data.get('cves', [])]
        elif isinstance(data, list):
            return [self._normalize_single_cve(cve) for cve in data]
        return []
    
    def _normalize_single_cve(self, cve_data: Dict) -> Dict[str, Any]:
        """Convert CVE Details format to standard CTBA format"""
        cve_id = cve_data.get('id') or cve_data.get('cve_id', '')
        
        return {
            'id': cve_id,
            'source': 'cvedetails',
            'source_url': f"https://cvedetails.com/cve/{cve_id}/",
            'published': cve_data.get('published_date') or cve_data.get('publication_date'),
            'cvss': float(cve_data.get('cvss_score', 0)) if cve_data.get('cvss_score') else None,
            'cvss_vector': cve_data.get('cvss_vector'),
            'cwe_id': cve_data.get('cwe_id'),
            'description': cve_data.get('summary') or cve_data.get('description', ''),
            'affected_products': [
                {
                    'vendor': p.get('vendor', 'Unknown'),
                    'product': p.get('product', 'Unknown'),
                    'version_affected': p.get('version_affected')
                }
                for p in cve_data.get('affected_products', [])
            ],
            'references': cve_data.get('references', []),
            'attack_vector': cve_data.get('attack_vector'),
            'attack_complexity': cve_data.get('attack_complexity'),
            'confidentiality_impact': cve_data.get('confidentiality_impact'),
            'integrity_impact': cve_data.get('integrity_impact'),
            'availability_impact': cve_data.get('availability_impact'),
        }
