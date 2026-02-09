"""
Region Mailing Service - Automatic To/Cc/Bcc resolution for regions
Manages mailing lists and recipient lists per region with validation
"""
import sqlite3
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RegionMailingLists:
    """Container for region mailing configuration"""
    region_id: int
    region_name: str
    to_recipients: List[str]
    cc_recipients: Optional[List[str]] = None
    bcc_recipients: Optional[List[str]] = None
    
    def get_all_recipients(self) -> List[str]:
        """Get all recipients (To + Cc + Bcc)"""
        all_recipients = self.to_recipients.copy()
        if self.cc_recipients:
            all_recipients.extend(self.cc_recipients)
        if self.bcc_recipients:
            all_recipients.extend(self.bcc_recipients)
        return all_recipients
    
    def get_recipient_count(self) -> int:
        """Get count of all recipients"""
        return len(self.get_all_recipients())
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'region_id': self.region_id,
            'region_name': self.region_name,
            'to': self.to_recipients,
            'cc': self.cc_recipients or [],
            'bcc': self.bcc_recipients or [],
            'total_recipients': self.get_recipient_count()
        }


class RegionMailingService:
    """Manage mailing lists for regions"""
    
    def __init__(self, db_path: str = 'ctba_platform.db'):
        """Initialize region mailing service"""
        self.db_path = db_path
        self._ensure_mailing_tables()
        logger.info("✅ RegionMailingService initialized")
    
    def _ensure_mailing_tables(self):
        """Create mailing list tables if they don't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Region mailing lists (primary recipients per region)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS region_mailing_lists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    region_id INTEGER NOT NULL UNIQUE,
                    to_recipients TEXT NOT NULL,
                    cc_recipients TEXT,
                    bcc_recipients TEXT,
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (region_id) REFERENCES regions(id) ON DELETE CASCADE
                )
            ''')
            
            # Mailing list audit
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mailing_list_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    region_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    old_to_list TEXT,
                    new_to_list TEXT,
                    changed_by TEXT,
                    reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (region_id) REFERENCES regions(id) ON DELETE CASCADE
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error creating mailing tables: {e}")
    
    def setup_region_mailing(
        self,
        region_id: int,
        to_recipients: List[str],
        cc_recipients: Optional[List[str]] = None,
        bcc_recipients: Optional[List[str]] = None,
        changed_by: str = 'SYSTEM'
    ) -> RegionMailingLists:
        """
        Setup or update mailing lists for a region
        
        Args:
            region_id: Region ID
            to_recipients: List of primary recipients
            cc_recipients: List of CC recipients (optional)
            bcc_recipients: List of BCC recipients (optional)
            changed_by: Who made this change
        
        Returns:
            RegionMailingLists object
        """
        try:
            # Validate emails
            self._validate_email_list(to_recipients)
            if cc_recipients:
                self._validate_email_list(cc_recipients)
            if bcc_recipients:
                self._validate_email_list(bcc_recipients)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get region name
            cursor.execute('SELECT id, name FROM regions WHERE id = ?', (region_id,))
            region = cursor.fetchone()
            
            if not region:
                raise ValueError(f"Region ID {region_id} not found")
            
            region_name = region[1]
            
            # Check if mailing list exists
            cursor.execute(
                'SELECT id, to_recipients FROM region_mailing_lists WHERE region_id = ?',
                (region_id,)
            )
            existing = cursor.fetchone()
            
            # Convert lists to CSV strings
            to_csv = ','.join(to_recipients)
            cc_csv = ','.join(cc_recipients) if cc_recipients else None
            bcc_csv = ','.join(bcc_recipients) if bcc_recipients else None
            
            if existing:
                # Update existing
                old_to_list = existing[1]
                cursor.execute('''
                    UPDATE region_mailing_lists
                    SET to_recipients = ?, cc_recipients = ?, bcc_recipients = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE region_id = ?
                ''', (to_csv, cc_csv, bcc_csv, region_id))
                
                # Log audit
                cursor.execute('''
                    INSERT INTO mailing_list_audit (region_id, action, old_to_list, new_to_list, changed_by)
                    VALUES (?, ?, ?, ?, ?)
                ''', (region_id, 'UPDATED', old_to_list, to_csv, changed_by))
                
            else:
                # Create new
                cursor.execute('''
                    INSERT INTO region_mailing_lists (region_id, to_recipients, cc_recipients, bcc_recipients)
                    VALUES (?, ?, ?, ?)
                ''', (region_id, to_csv, cc_csv, bcc_csv))
                
                # Log audit
                cursor.execute('''
                    INSERT INTO mailing_list_audit (region_id, action, new_to_list, changed_by)
                    VALUES (?, ?, ?, ?)
                ''', (region_id, 'CREATED', to_csv, changed_by))
            
            conn.commit()
            conn.close()
            
            logger.info(
                f"✅ Setup mailing lists for region '{region_name}': "
                f"To={len(to_recipients)}, Cc={len(cc_recipients or [])}, Bcc={len(bcc_recipients or [])}"
            )
            
            return RegionMailingLists(
                region_id=region_id,
                region_name=region_name,
                to_recipients=to_recipients,
                cc_recipients=cc_recipients,
                bcc_recipients=bcc_recipients
            )
        
        except Exception as e:
            logger.error(f"Error setting up region mailing: {e}")
            raise
    
    def get_region_mailing_lists(self, region_id: int) -> Optional[RegionMailingLists]:
        """Get mailing lists for a region"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT rml.region_id, r.name, rml.to_recipients, rml.cc_recipients, rml.bcc_recipients
                FROM region_mailing_lists rml
                JOIN regions r ON rml.region_id = r.id
                WHERE rml.region_id = ? AND rml.active = 1
            ''', (region_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return None
            
            region_id, region_name, to_csv, cc_csv, bcc_csv = result
            
            return RegionMailingLists(
                region_id=region_id,
                region_name=region_name,
                to_recipients=to_csv.split(',') if to_csv else [],
                cc_recipients=cc_csv.split(',') if cc_csv else None,
                bcc_recipients=bcc_csv.split(',') if bcc_csv else None
            )
        
        except Exception as e:
            logger.error(f"Error retrieving region mailing lists: {e}")
            raise
    
    def get_region_mailing_by_name(self, region_name: str) -> Optional[RegionMailingLists]:
        """Get mailing lists for a region by name"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT rml.region_id, r.name, rml.to_recipients, rml.cc_recipients, rml.bcc_recipients
                FROM region_mailing_lists rml
                JOIN regions r ON rml.region_id = r.id
                WHERE r.name = ? AND rml.active = 1
            ''', (region_name,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return None
            
            region_id, name, to_csv, cc_csv, bcc_csv = result
            
            return RegionMailingLists(
                region_id=region_id,
                region_name=name,
                to_recipients=to_csv.split(',') if to_csv else [],
                cc_recipients=cc_csv.split(',') if cc_csv else None,
                bcc_recipients=bcc_csv.split(',') if bcc_csv else None
            )
        
        except Exception as e:
            logger.error(f"Error retrieving region mailing by name: {e}")
            raise
    
    def get_all_region_mailing_lists(self) -> List[RegionMailingLists]:
        """Get mailing lists for all regions"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT rml.region_id, r.name, rml.to_recipients, rml.cc_recipients, rml.bcc_recipients
                FROM region_mailing_lists rml
                JOIN regions r ON rml.region_id = r.id
                WHERE rml.active = 1
                ORDER BY r.name
            ''')
            
            results = []
            for row in cursor.fetchall():
                region_id, region_name, to_csv, cc_csv, bcc_csv = row
                results.append(RegionMailingLists(
                    region_id=region_id,
                    region_name=region_name,
                    to_recipients=to_csv.split(',') if to_csv else [],
                    cc_recipients=cc_csv.split(',') if cc_csv else None,
                    bcc_recipients=bcc_csv.split(',') if bcc_csv else None
                ))
            
            conn.close()
            return results
        
        except Exception as e:
            logger.error(f"Error retrieving all region mailing lists: {e}")
            raise
    
    def resolve_recipients_for_regions(
        self,
        region_names: List[str],
        override_to: Optional[List[str]] = None,
        override_cc: Optional[List[str]] = None,
        override_bcc: Optional[List[str]] = None
    ) -> Dict[str, RegionMailingLists]:
        """
        Resolve recipient lists for multiple regions
        
        Args:
            region_names: List of region names
            override_to: Override To recipients for all regions
            override_cc: Override Cc recipients for all regions
            override_bcc: Override Bcc recipients for all regions
        
        Returns:
            Dict of region_name -> RegionMailingLists
        """
        result = {}
        
        for region_name in region_names:
            mailing_list = self.get_region_mailing_by_name(region_name)
            
            if not mailing_list:
                logger.warning(f"No mailing list found for region: {region_name}")
                continue
            
            # Apply overrides if provided
            if override_to:
                mailing_list.to_recipients = override_to
            if override_cc:
                mailing_list.cc_recipients = override_cc
            if override_bcc:
                mailing_list.bcc_recipients = override_bcc
            
            result[region_name] = mailing_list
        
        return result
    
    @staticmethod
    def _validate_email_list(emails: List[str]) -> bool:
        """Validate email list format"""
        import re
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        for email in emails:
            email = email.strip()
            if not re.match(email_pattern, email):
                raise ValueError(f"Invalid email format: {email}")
        
        return True
    
    def get_mailing_list_audit(self, region_id: int) -> List[Dict]:
        """Get audit history for region mailing list changes"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM mailing_list_audit
                WHERE region_id = ?
                ORDER BY created_at DESC
            ''', (region_id,))
            
            audit_entries = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return audit_entries
        
        except Exception as e:
            logger.error(f"Error retrieving mailing list audit: {e}")
            raise
