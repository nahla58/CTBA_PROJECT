"""
Multi-Source CVE Ingestion Manager
Coordinates CVE import from NVD, CVE Details, MSRC, Hackuity, and manual entry
"""

import logging
from typing import List, Dict, Any, Optional, Literal
from datetime import datetime
from enum import Enum

from nvd_importer import import_from_nvd
from cvedetails_importer import CVEDetailsImporter
from msrc_importer import MSRCImporter
from hackuity_importer import HackuityImporter
from manual_entry import ManualCVEEntry, create_manual_entry_template

logger = logging.getLogger(__name__)


class IngestionSource(str, Enum):
    """Available CVE ingestion sources"""
    NVD = "nvd"
    CVE_DETAILS = "cvedetails"
    MSRC = "msrc"
    HACKUITY = "hackuity"
    MANUAL = "manual"


class IngestionResult:
    """Result of a single ingestion operation"""
    
    def __init__(self, source: str):
        self.source = source
        self.imported_count = 0
        self.duplicate_count = 0
        self.error_count = 0
        self.errors: List[str] = []
        self.cves: List[Dict[str, Any]] = []
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'source': self.source,
            'imported_count': self.imported_count,
            'duplicate_count': self.duplicate_count,
            'error_count': self.error_count,
            'total_processed': self.imported_count + self.duplicate_count + self.error_count,
            'errors': self.errors,
            'timestamp': self.timestamp.isoformat(),
            'cve_ids': [cve.get('id') for cve in self.cves]
        }


class MultiSourceIngestionManager:
    """
    Manages CVE ingestion from multiple sources with deduplication and validation
    """
    
    def __init__(self, database_handler: Optional[Any] = None):
        """
        Initialize ingestion manager
        
        Args:
            database_handler: Database connection for storing ingested CVEs
        """
        self.db = database_handler
        self.importers = {
            IngestionSource.CVE_DETAILS: CVEDetailsImporter(),
            IngestionSource.MSRC: MSRCImporter(),
            IngestionSource.HACKUITY: HackuityImporter(),
        }
        self.manual_entry = ManualCVEEntry()
        self.imported_cve_ids: set = set()  # Track imported CVEs to detect duplicates
    
    def ingest_from_nvd(self, days: int = 7) -> IngestionResult:
        """
        Import CVEs from NVD (National Vulnerability Database)
        
        Args:
            days: Number of days to look back for modified CVEs
            
        Returns:
            Ingestion result with statistics
        """
        result = IngestionResult(IngestionSource.NVD.value)
        
        try:
            logger.info(f"Starting NVD ingestion (last {days} days)...")
            cves = import_from_nvd()  # Uses existing scheduler or direct import
            
            for cve in cves:
                cve_id = cve.get('id')
                
                if cve_id in self.imported_cve_ids:
                    result.duplicate_count += 1
                    logger.debug(f"NVD: Duplicate CVE {cve_id}")
                else:
                    self.imported_cve_ids.add(cve_id)
                    result.cves.append(cve)
                    result.imported_count += 1
            
            logger.info(f"NVD ingestion complete: {result.imported_count} new, {result.duplicate_count} duplicates")
            
        except Exception as e:
            result.error_count += 1
            result.errors.append(str(e))
            logger.error(f"NVD ingestion error: {e}")
        
        return result
    
    def ingest_from_cvedetails(self, keyword: str, limit: int = 100) -> IngestionResult:
        """
        Import CVEs from CVE Details
        
        Args:
            keyword: Search keyword (vendor/product/CVE ID)
            limit: Maximum CVEs to import
            
        Returns:
            Ingestion result with statistics
        """
        result = IngestionResult(IngestionSource.CVE_DETAILS.value)
        
        try:
            logger.info(f"Starting CVE Details ingestion: {keyword}")
            cves = self.importers[IngestionSource.CVE_DETAILS].search_cves(keyword, limit)
            
            for cve in cves:
                cve_id = cve.get('id')
                
                if cve_id in self.imported_cve_ids:
                    result.duplicate_count += 1
                    logger.debug(f"CVE Details: Duplicate {cve_id}")
                else:
                    self.imported_cve_ids.add(cve_id)
                    result.cves.append(cve)
                    result.imported_count += 1
            
            logger.info(f"CVE Details ingestion complete: {result.imported_count} new")
            
        except Exception as e:
            result.error_count += 1
            result.errors.append(str(e))
            logger.error(f"CVE Details ingestion error: {e}")
        
        return result
    
    def ingest_from_msrc(self, year: int, month: int) -> IngestionResult:
        """
        Import CVEs from Microsoft Security Response Center
        
        Args:
            year: Year (e.g., 2024)
            month: Month (1-12)
            
        Returns:
            Ingestion result with statistics
        """
        result = IngestionResult(IngestionSource.MSRC.value)
        
        try:
            logger.info(f"Starting MSRC ingestion: {year}-{month:02d}")
            cves = self.importers[IngestionSource.MSRC].get_monthly_bulletins(year, month)
            
            for cve in cves:
                cve_id = cve.get('id')
                
                if cve_id in self.imported_cve_ids:
                    result.duplicate_count += 1
                    logger.debug(f"MSRC: Duplicate {cve_id}")
                else:
                    self.imported_cve_ids.add(cve_id)
                    result.cves.append(cve)
                    result.imported_count += 1
            
            logger.info(f"MSRC ingestion complete: {result.imported_count} new")
            
        except Exception as e:
            result.error_count += 1
            result.errors.append(str(e))
            logger.error(f"MSRC ingestion error: {e}")
        
        return result
    
    def ingest_from_hackuity(self, filter_type: str = 'recent', limit: int = 50) -> IngestionResult:
        """
        Import CVEs from Hackuity threat intelligence
        
        Args:
            filter_type: 'recent', 'exploitable', or search query
            limit: Maximum CVEs to import
            
        Returns:
            Ingestion result with statistics
        """
        result = IngestionResult(IngestionSource.HACKUITY.value)
        
        try:
            logger.info(f"Starting Hackuity ingestion: {filter_type}")
            
            if filter_type == 'exploitable':
                cves = self.importers[IngestionSource.HACKUITY].get_exploitable_cves(limit)
            elif filter_type == 'recent':
                cves = self.importers[IngestionSource.HACKUITY].get_recent_cves(limit=limit)
            else:
                cves = self.importers[IngestionSource.HACKUITY].search_cves(filter_type, limit)
            
            for cve in cves:
                cve_id = cve.get('id')
                
                if cve_id in self.imported_cve_ids:
                    result.duplicate_count += 1
                    logger.debug(f"Hackuity: Duplicate {cve_id}")
                else:
                    self.imported_cve_ids.add(cve_id)
                    result.cves.append(cve)
                    result.imported_count += 1
            
            logger.info(f"Hackuity ingestion complete: {result.imported_count} new")
            
        except Exception as e:
            result.error_count += 1
            result.errors.append(str(e))
            logger.error(f"Hackuity ingestion error: {e}")
        
        return result
    
    def ingest_manual_entry(self, cve_data: Dict[str, Any]) -> tuple[bool, Optional[Dict[str, Any]], List[str]]:
        """
        Process manually entered CVE
        
        Args:
            cve_data: CVE data from user input
            
        Returns:
            Tuple of (success, normalized_cve, error_messages)
        """
        try:
            logger.info("Processing manual CVE entry")
            
            normalized = self.manual_entry.validate_and_create(cve_data)
            
            if not normalized:
                errors = self.manual_entry.get_validation_errors()
                logger.warning(f"Manual entry validation failed: {errors}")
                return False, None, errors
            
            cve_id = normalized.get('id')
            if cve_id in self.imported_cve_ids:
                logger.warning(f"Duplicate manual entry: {cve_id}")
                return False, None, [f"CVE {cve_id} already imported"]
            
            self.imported_cve_ids.add(cve_id)
            logger.info(f"Manual entry validated: {cve_id}")
            return True, normalized, []
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Manual entry error: {error_msg}")
            return False, None, [error_msg]
    
    def get_ingestion_status(self) -> Dict[str, Any]:
        """Get current ingestion status and statistics"""
        return {
            'total_imported': len(self.imported_cve_ids),
            'imported_cve_ids': sorted(list(self.imported_cve_ids)),
            'sources_available': [s.value for s in IngestionSource],
            'timestamp': datetime.utcnow().isoformat(),
        }
    
    def get_manual_entry_template(self) -> Dict[str, Any]:
        """Get template for manual CVE entry"""
        return create_manual_entry_template()


# Convenience functions for quick ingestion

def ingest_nvd(days: int = 7) -> IngestionResult:
    """Quick import from NVD"""
    manager = MultiSourceIngestionManager()
    return manager.ingest_from_nvd(days)


def ingest_cvedetails(keyword: str) -> IngestionResult:
    """Quick import from CVE Details"""
    manager = MultiSourceIngestionManager()
    return manager.ingest_from_cvedetails(keyword)


def ingest_msrc(year: int, month: int) -> IngestionResult:
    """Quick import from MSRC"""
    manager = MultiSourceIngestionManager()
    return manager.ingest_from_msrc(year, month)


def ingest_hackuity(filter_type: str = 'recent') -> IngestionResult:
    """Quick import from Hackuity"""
    manager = MultiSourceIngestionManager()
    return manager.ingest_from_hackuity(filter_type)
