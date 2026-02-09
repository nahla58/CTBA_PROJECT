"""
Manual CVE Entry System
Allows analysts to manually add CVEs to the system with validation
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class CVESeverity(str, Enum):
    """CVE severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class CVESource(str, Enum):
    """CVE sources"""
    MANUAL = "manual"
    NVD = "nvd"
    CVE_DETAILS = "cvedetails"
    MSRC = "msrc"
    HACKUITY = "hackuity"


class ManualCVEEntry:
    """
    Handles manual CVE entry with validation and normalization
    Supports both minimal and detailed entry forms
    """
    
    # Validation constraints
    MIN_CVE_ID_LENGTH = 10  # CVE-XXXX-XXXXX
    MAX_DESCRIPTION_LENGTH = 5000
    MAX_REFERENCES = 20
    
    # Required fields for valid CVE
    REQUIRED_FIELDS = {'id', 'description'}
    
    # Optional but recommended fields
    RECOMMENDED_FIELDS = {'cvss', 'affected_products', 'references'}
    
    def __init__(self):
        self.validation_errors: List[str] = []
    
    def validate_and_create(self, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Validate and normalize manually entered CVE data
        
        Args:
            cve_data: Raw CVE data from user input
            
        Returns:
            Normalized CVE record or None if validation fails
        """
        self.validation_errors = []
        
        # Validate required fields
        if not self._validate_required_fields(cve_data):
            logger.error(f"Manual CVE validation failed: {self.validation_errors}")
            return None
        
        # Validate individual fields
        if not self._validate_cve_id(cve_data.get('id')):
            return None
        
        if not self._validate_description(cve_data.get('description')):
            return None
        
        if cve_data.get('cvss') and not self._validate_cvss(cve_data.get('cvss')):
            return None
        
        if cve_data.get('affected_products'):
            if not self._validate_affected_products(cve_data.get('affected_products')):
                return None
        
        if cve_data.get('references'):
            if not self._validate_references(cve_data.get('references')):
                return None
        
        # Normalize the data
        normalized = self._normalize_cve_data(cve_data)
        
        logger.info(f"Manual CVE entry validated: {normalized['id']}")
        return normalized
    
    def _validate_required_fields(self, cve_data: Dict) -> bool:
        """Validate that all required fields are present"""
        missing = []
        for field in self.REQUIRED_FIELDS:
            if field not in cve_data or not cve_data.get(field):
                missing.append(field)
        
        if missing:
            self.validation_errors.append(
                f"Missing required fields: {', '.join(missing)}"
            )
            return False
        
        return True
    
    def _validate_cve_id(self, cve_id: Optional[str]) -> bool:
        """Validate CVE ID format (CVE-YYYY-XXXXX)"""
        if not cve_id:
            self.validation_errors.append("CVE ID is required")
            return False
        
        cve_id = cve_id.strip().upper()
        
        if len(cve_id) < self.MIN_CVE_ID_LENGTH:
            self.validation_errors.append(
                f"CVE ID too short (minimum {self.MIN_CVE_ID_LENGTH} characters)"
            )
            return False
        
        if not cve_id.startswith('CVE-'):
            self.validation_errors.append("CVE ID must start with 'CVE-'")
            return False
        
        parts = cve_id.split('-')
        if len(parts) != 3:
            self.validation_errors.append(
                "CVE ID must be in format: CVE-YYYY-XXXXX"
            )
            return False
        
        try:
            year = int(parts[1])
            sequence = int(parts[2])
            
            if year < 1999 or year > datetime.now().year + 1:
                self.validation_errors.append(
                    f"CVE ID year {year} is invalid"
                )
                return False
            
            if sequence < 1:
                self.validation_errors.append("CVE ID sequence must be positive")
                return False
        
        except ValueError:
            self.validation_errors.append(
                "CVE ID year and sequence must be numeric"
            )
            return False
        
        return True
    
    def _validate_description(self, description: Optional[str]) -> bool:
        """Validate CVE description"""
        if not description:
            self.validation_errors.append("Description is required")
            return False
        
        description = description.strip()
        
        if len(description) < 10:
            self.validation_errors.append(
                "Description must be at least 10 characters"
            )
            return False
        
        if len(description) > self.MAX_DESCRIPTION_LENGTH:
            self.validation_errors.append(
                f"Description exceeds maximum length ({self.MAX_DESCRIPTION_LENGTH} chars)"
            )
            return False
        
        return True
    
    def _validate_cvss(self, cvss: Any) -> bool:
        """Validate CVSS score (0.0 - 10.0)"""
        try:
            cvss_score = float(cvss)
            
            if cvss_score < 0.0 or cvss_score > 10.0:
                self.validation_errors.append(
                    "CVSS score must be between 0.0 and 10.0"
                )
                return False
            
            return True
        
        except (ValueError, TypeError):
            self.validation_errors.append("CVSS score must be a decimal number")
            return False
    
    def _validate_affected_products(self, products: Any) -> bool:
        """Validate affected products list"""
        if not isinstance(products, list):
            self.validation_errors.append("Affected products must be a list")
            return False
        
        if not products:
            return True  # Empty list is valid
        
        for i, product in enumerate(products):
            if not isinstance(product, dict):
                self.validation_errors.append(
                    f"Product {i} is not a dictionary"
                )
                return False
            
            if 'vendor' not in product or not product.get('vendor'):
                self.validation_errors.append(
                    f"Product {i} missing vendor name"
                )
                return False
            
            if 'product' not in product or not product.get('product'):
                self.validation_errors.append(
                    f"Product {i} missing product name"
                )
                return False
        
        return True
    
    def _validate_references(self, references: Any) -> bool:
        """Validate references list"""
        if not isinstance(references, list):
            self.validation_errors.append("References must be a list")
            return False
        
        if len(references) > self.MAX_REFERENCES:
            self.validation_errors.append(
                f"References exceed maximum ({self.MAX_REFERENCES})"
            )
            return False
        
        for i, ref in enumerate(references):
            if isinstance(ref, str):
                if not ref.startswith(('http://', 'https://')):
                    self.validation_errors.append(
                        f"Reference {i} is not a valid URL"
                    )
                    return False
            elif isinstance(ref, dict):
                if 'url' in ref and not ref['url'].startswith(('http://', 'https://')):
                    self.validation_errors.append(
                        f"Reference {i} URL is invalid"
                    )
                    return False
            else:
                self.validation_errors.append(
                    f"Reference {i} must be string or object"
                )
                return False
        
        return True
    
    def _normalize_cve_data(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize and standardize CVE data"""
        return {
            'id': cve_data['id'].strip().upper(),
            'source': CVESource.MANUAL.value,
            'source_url': cve_data.get('source_url', ''),
            'published': cve_data.get('published') or datetime.utcnow().isoformat(),
            'modified': datetime.utcnow().isoformat(),
            'cvss': float(cve_data.get('cvss', 0)) if cve_data.get('cvss') else None,
            'cvss_vector': cve_data.get('cvss_vector', ''),
            'cwe_id': cve_data.get('cwe_id', ''),
            'description': cve_data['description'].strip(),
            'affected_products': [
                {
                    'vendor': p.get('vendor', '').strip(),
                    'product': p.get('product', '').strip(),
                    'version_affected': p.get('version_affected', '')
                }
                for p in (cve_data.get('affected_products') or [])
            ],
            'references': [
                ref if isinstance(ref, str) else ref.get('url', '')
                for ref in (cve_data.get('references') or [])
            ],
            'status': cve_data.get('status', 'IMPORTED'),
            'analyst_notes': cve_data.get('notes', ''),
            'manual_entry': True,
            'entry_timestamp': datetime.utcnow().isoformat(),
        }
    
    def get_validation_errors(self) -> List[str]:
        """Get list of validation errors"""
        return self.validation_errors
    
    def get_validation_summary(self) -> str:
        """Get formatted validation error summary"""
        if not self.validation_errors:
            return "No validation errors"
        
        return "\n".join([f"• {error}" for error in self.validation_errors])


def create_manual_entry_template() -> Dict[str, Any]:
    """
    Create a template for manual CVE entry
    
    Returns:
        Template dictionary with required and optional fields
    """
    return {
        # REQUIRED
        'id': 'CVE-2024-XXXXX',
        'description': 'Detailed description of the vulnerability...',
        
        # OPTIONAL BUT RECOMMENDED
        'published': datetime.utcnow().isoformat(),
        'cvss': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        'cwe_id': 'CWE-200',
        'affected_products': [
            {
                'vendor': 'Example Corp',
                'product': 'Example Product',
                'version_affected': '1.0.0 - 2.0.1'
            }
        ],
        'references': [
            'https://example.com/security-advisory',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX'
        ],
        
        # OPTIONAL
        'source_url': '',
        'status': 'IMPORTED',
        'notes': 'Analyst notes or additional context...'
    }
