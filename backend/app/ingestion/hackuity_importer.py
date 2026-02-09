"""
Hackuity Importer
Imports CVEs and threat intelligence from Hackuity
"""

import requests
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class HackuityImporter:
    """
    Import CVEs from Hackuity's vulnerability intelligence platform
    Provides real-time threat data, exploitability indicators, and attack patterns
    """
    
    BASE_URL = "https://api.hackuity.io/v1"
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize Hackuity importer
        
        Args:
            api_key: Hackuity API key (optional, can be set via environment)
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.api_key = api_key
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'User-Agent': 'CTBA-CVE-Importer/1.0',
                'Accept': 'application/json'
            })
    
    def search_cves(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for CVEs in Hackuity database
        
        Args:
            keyword: Search term (vendor, product, CVE ID, or technique)
            limit: Maximum number of results
            
        Returns:
            List of CVE records with threat intelligence
        """
        if not self.api_key:
            logger.warning("Hackuity: API key not configured, search unavailable")
            return []
        
        try:
            params = {
                'search': keyword,
                'limit': min(limit, 100),
                'include': 'exploitability,threat_actors,attack_patterns'
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/vulnerabilities/search",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._normalize_hackuity_response(data)
            
            logger.info(f"Hackuity: Found {len(cves)} CVEs for '{keyword}'")
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Hackuity API error: {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed intelligence for a specific CVE from Hackuity
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-12345')
            
        Returns:
            Detailed CVE record with threat intelligence or None
        """
        if not self.api_key:
            logger.warning("Hackuity: API key not configured, details unavailable")
            return None
        
        try:
            params = {
                'include': 'exploitability,threat_actors,attack_patterns,remediation'
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/vulnerabilities/{cve_id}",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return self._normalize_single_cve(data)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Hackuity: Failed to fetch {cve_id}: {e}")
            return None
    
    def get_exploitable_cves(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get CVEs currently being exploited in the wild
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of actively exploited CVE records
        """
        if not self.api_key:
            logger.warning("Hackuity: API key not configured")
            return []
        
        try:
            params = {
                'filter': 'exploitability=active',
                'limit': min(limit, 100),
                'sort': '-exploitability_score'
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/vulnerabilities",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._normalize_hackuity_response(data)
            
            logger.info(f"Hackuity: Found {len(cves)} actively exploited CVEs")
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Hackuity exploitable CVEs error: {e}")
            return []
    
    def get_recent_cves(self, days: int = 7, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recently discovered CVEs from Hackuity
        
        Args:
            days: Number of days to look back
            limit: Maximum number of results
            
        Returns:
            List of recent CVE records
        """
        if not self.api_key:
            logger.warning("Hackuity: API key not configured")
            return []
        
        try:
            params = {
                'filter': f'published_date>[{days}d]',
                'limit': min(limit, 100),
                'sort': '-published_date'
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/vulnerabilities",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._normalize_hackuity_response(data)
            
            logger.info(f"Hackuity: Found {len(cves)} CVEs from last {days} days")
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Hackuity recent CVEs error: {e}")
            return []
    
    def _normalize_hackuity_response(self, data: Dict) -> List[Dict[str, Any]]:
        """Normalize Hackuity API response to standard format"""
        results = data.get('data', data.get('vulnerabilities', []))
        
        if isinstance(results, dict):
            results = [results]
        elif not isinstance(results, list):
            results = []
        
        return [self._normalize_single_cve(cve) for cve in results]
    
    def _normalize_single_cve(self, cve_data: Dict) -> Dict[str, Any]:
        """Convert Hackuity format to standard CTBA format"""
        return {
            'id': cve_data.get('cve_id') or cve_data.get('id', ''),
            'source': 'hackuity',
            'source_url': cve_data.get('url') or f"https://hackuity.io/cve/{cve_data.get('cve_id')}",
            'published': cve_data.get('published_date') or cve_data.get('disclosure_date'),
            'cvss': float(cve_data.get('cvss_score', 0)) if cve_data.get('cvss_score') else None,
            'cvss_vector': cve_data.get('cvss_vector'),
            'cwe_id': cve_data.get('cwe_id'),
            'description': cve_data.get('description', ''),
            'affected_products': [
                {
                    'vendor': p.get('vendor', 'Unknown'),
                    'product': p.get('product', 'Unknown'),
                    'version_affected': p.get('version')
                }
                for p in cve_data.get('affected_products', [])
            ],
            'references': cve_data.get('references', []),
            # Hackuity-specific fields
            'exploitability': {
                'status': cve_data.get('exploitability', {}).get('status'),  # 'active', 'known', 'none'
                'score': float(cve_data.get('exploitability', {}).get('score', 0)),
                'methods': cve_data.get('exploitability', {}).get('methods', []),
            },
            'threat_actors': cve_data.get('threat_actors', []),
            'attack_patterns': cve_data.get('attack_patterns', []),
            'remediation': cve_data.get('remediation'),
            'workarounds': cve_data.get('workarounds', []),
        }
