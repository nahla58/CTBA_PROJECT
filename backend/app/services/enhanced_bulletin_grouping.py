"""
Enhanced Bulletin Service with Automatic CVE Grouping, Region Management, and Attachments
"""
import json
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from collections import defaultdict
import os
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)


class EnhancedBulletinService:
    """Service for managing bulletins with advanced features"""
    
    def __init__(self, db_connection):
        self.db = db_connection
        self.upload_dir = Path('bulletins/attachments')
        self.upload_dir.mkdir(parents=True, exist_ok=True)
    
    # ========== AUTO GROUPING METHODS ==========
    
    def group_cves_by_technology(self, cve_ids: List[str]) -> Dict[str, List[Dict]]:
        """
        Automatically group CVEs by vendor/product
        
        Returns:
            {
                "vendor:product": [
                    {"cve_id": "CVE-2024-1234", "severity": "CRITICAL", ...},
                    ...
                ]
            }
        """
        if not cve_ids:
            return {}
        
        try:
            # Query CVEs from database
            placeholders = ','.join(['?' for _ in cve_ids])
            query = f"""
                SELECT DISTINCT
                    cp.vendor,
                    cp.product,
                    c.cve_id,
                    c.severity,
                    c.cvss_score,
                    c.description
                FROM cves c
                LEFT JOIN cve_affected_products cp ON c.cve_id = cp.cve_id
                WHERE c.cve_id IN ({placeholders})
                ORDER BY cp.vendor, cp.product, c.severity DESC
            """
            
            cursor = self.db.cursor()
            cursor.execute(query, cve_ids)
            results = cursor.fetchall()
            
            # Group by vendor:product
            grouped = defaultdict(list)
            
            for row in results:
                vendor = row['vendor'] or 'Unknown Vendor'
                product = row['product'] or 'Unknown Product'
                key = f"{vendor}:{product}"
                
                grouped[key].append({
                    'cve_id': row['cve_id'],
                    'severity': row['severity'],
                    'cvss_score': row['cvss_score'],
                    'description': row['description'][:200] + '...' if row['description'] else 'N/A'
                })
            
            return dict(grouped)
        
        except Exception as e:
            logger.error(f"Error grouping CVEs: {e}")
            return {}
    
    
    def find_identical_remediation_cves(self, cve_ids: List[str]) -> Dict[str, List[str]]:
        """
        Group CVEs by identical remediation guidance
        
        Returns:
            {
                "remediation_hash": ["CVE-2024-1234", "CVE-2024-5678", ...]
            }
        """
        try:
            placeholders = ','.join(['?' for _ in cve_ids])
            query = f"""
                SELECT 
                    c.cve_id,
                    rc.remediation_steps,
                    rc.remediation_guidance
                FROM cves c
                LEFT JOIN remediation_recommendations rc ON c.cve_id = rc.cve_id
                WHERE c.cve_id IN ({placeholders})
            """
            
            cursor = self.db.cursor()
            cursor.execute(query, cve_ids)
            results = cursor.fetchall()
            
            # Group by remediation hash
            remediation_groups = defaultdict(list)
            
            for row in results:
                remediation_text = row['remediation_guidance'] or ''
                # Create hash of remediation text
                remediation_hash = hashlib.md5(remediation_text.encode()).hexdigest()[:8]
                remediation_groups[remediation_hash].append(row['cve_id'])
            
            return dict(remediation_groups)
        
        except Exception as e:
            logger.error(f"Error finding identical remediations: {e}")
            return {}
    
    
    def create_bullet_with_grouping(self, bulletin_data: Dict[str, Any]) -> int:
        """
        Create a bulletin with automatic CVE grouping
        """
        try:
            cursor = self.db.cursor()
            
            # Create bulletin
            query = """
                INSERT INTO bulletins (
                    title, body, status, cve_ids, regions, 
                    created_by, created_at, cve_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            cve_ids = bulletin_data.get('cve_ids', [])
            cve_count = len(cve_ids)
            regions = bulletin_data.get('regions', [])
            
            cursor.execute(query, (
                bulletin_data['title'],
                bulletin_data.get('body', ''),
                'DRAFT',
                json.dumps(cve_ids),
                json.dumps(regions),
                bulletin_data['created_by'],
                datetime.now(),
                cve_count
            ))
            
            bulletin_id = cursor.lastrowid
            self.db.commit()
            
            # Auto-group CVEs
            if cve_ids:
                self._create_cve_groupings(bulletin_id, cve_ids)
            
            logger.info(f"Created bulletin {bulletin_id} with {cve_count} CVEs")
            return bulletin_id
        
        except Exception as e:
            logger.error(f"Error creating bulletin: {e}")
            self.db.rollback()
            raise
    
    
    def _create_cve_groupings(self, bulletin_id: int, cve_ids: List[str]):
        """Create automatic CVE groupings in database"""
        try:
            grouped = self.group_cves_by_technology(cve_ids)
            cursor = self.db.cursor()
            
            for order, (tech_key, cves) in enumerate(grouped.items(), 1):
                vendor, product = tech_key.split(':')
                
                query = """
                    INSERT INTO bulletin_cve_groupings (
                        bulletin_id, vendor, product, cve_ids, 
                        cve_count, group_order, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """
                
                cursor.execute(query, (
                    bulletin_id,
                    vendor,
                    product,
                    json.dumps([cve['cve_id'] for cve in cves]),
                    len(cves),
                    order,
                    datetime.now()
                ))
            
            self.db.commit()
            logger.info(f"Created {len(grouped)} CVE groupings for bulletin {bulletin_id}")
        
        except Exception as e:
            logger.error(f"Error creating CVE groupings: {e}")
            self.db.rollback()
    
    
    # ========== REGION MANAGEMENT METHODS ==========
    
    def get_active_regions(self) -> List[Dict[str, Any]]:
        """Get all active regions"""
        try:
            query = """
                SELECT id, name, description, recipients, created_at
                FROM bulletin_regions
                WHERE is_active = TRUE AND archived_at IS NULL
                ORDER BY name
            """
            
            cursor = self.db.cursor()
            cursor.execute(query)
            return cursor.fetchall()
        
        except Exception as e:
            logger.error(f"Error fetching regions: {e}")
            return []
    
    
    def archive_region(self, region_id: int, archived_by: str) -> bool:
        """
        Archive a region without deleting data
        Supports future addition/archiving without impacting historical data
        """
        try:
            query = """
                UPDATE bulletin_regions
                SET archived_at = ?, is_active = FALSE, updated_at = ?
                WHERE id = ?
            """
            
            cursor = self.db.cursor()
            cursor.execute(query, (datetime.now(), datetime.now(), region_id))
            self.db.commit()
            
            logger.info(f"Archived region {region_id} by {archived_by}")
            return True
        
        except Exception as e:
            logger.error(f"Error archiving region: {e}")
            return False
    
    
    def create_region(self, name: str, description: str, recipients: List[str]) -> int:
        """Create a new region"""
        try:
            query = """
                INSERT INTO bulletin_regions (
                    name, description, recipients, created_by, created_at
                )
                VALUES (?, ?, ?, ?, ?)
            """
            
            cursor = self.db.cursor()
            cursor.execute(query, (
                name,
                description,
                json.dumps(recipients),
                'system',
                datetime.now()
            ))
            
            self.db.commit()
            return cursor.lastrowid
        
        except Exception as e:
            logger.error(f"Error creating region: {e}")
            raise
    
    
    def get_region_recipients(self, region_name: str) -> List[str]:
        """Get all recipients for a region"""
        try:
            query = """
                SELECT recipients
                FROM bulletin_regions
                WHERE name = ? AND is_active = TRUE AND archived_at IS NULL
            """
            
            cursor = self.db.cursor()
            cursor.execute(query, (region_name,))
            result = cursor.fetchone()
            
            if result and result['recipients']:
                return json.loads(result['recipients'])
            return []
        
        except Exception as e:
            logger.error(f"Error fetching region recipients: {e}")
            return []
    
    
    # ========== ATTACHMENT MANAGEMENT ==========
    
    def save_attachment(self, bulletin_id: int, file_content: bytes, 
                       original_filename: str, attachment_type: str, 
                       description: str, uploaded_by: str) -> Dict[str, Any]:
        """
        Save file attachment to bulletin
        
        Args:
            bulletin_id: ID of bulletin
            file_content: File bytes
            original_filename: Original filename
            attachment_type: Type of attachment (PATCH, GUIDE, CONFIG, etc)
            description: Description of attachment
            uploaded_by: Username of uploader
        
        Returns:
            Attachment metadata
        """
        try:
            # Calculate file hash and create safe filename
            file_hash = hashlib.sha256(file_content).hexdigest()[:8]
            file_ext = Path(original_filename).suffix
            safe_filename = f"{bulletin_id}_{file_hash}_{original_filename}"
            file_path = self.upload_dir / safe_filename
            
            # Save file to disk
            file_path.write_bytes(file_content)
            
            # Save metadata to database
            query = """
                INSERT INTO bulletin_attachments (
                    bulletin_id, filename, file_path, file_size, 
                    file_type, checksum, attachment_type, description, 
                    uploaded_by, upload_date
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            cursor = self.db.cursor()
            cursor.execute(query, (
                bulletin_id,
                original_filename,
                str(file_path),
                len(file_content),
                file_ext.lstrip('.'),
                file_hash,
                attachment_type,
                description,
                uploaded_by,
                datetime.now()
            ))
            
            self.db.commit()
            attachment_id = cursor.lastrowid
            
            logger.info(f"Saved attachment {attachment_id} to bulletin {bulletin_id}")
            
            return {
                'id': attachment_id,
                'bulletin_id': bulletin_id,
                'filename': original_filename,
                'size': len(file_content),
                'type': attachment_type,
                'uploaded_by': uploaded_by,
                'upload_date': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error saving attachment: {e}")
            raise
    
    
    def get_attachments(self, bulletin_id: int) -> List[Dict[str, Any]]:
        """Get all attachments for a bulletin"""
        try:
            query = """
                SELECT 
                    id, filename, file_size, file_type, attachment_type,
                    description, uploaded_by, upload_date, download_count
                FROM bulletin_attachments
                WHERE bulletin_id = ? AND is_archived = FALSE
                ORDER BY upload_date DESC
            """
            
            cursor = self.db.cursor()
            cursor.execute(query, (bulletin_id,))
            return cursor.fetchall()
        
        except Exception as e:
            logger.error(f"Error fetching attachments: {e}")
            return []
    
    
    def download_attachment(self, attachment_id: int) -> Optional[tuple]:
        """
        Download attachment and update download count
        
        Returns:
            (file_path, original_filename)
        """
        try:
            # Get attachment info
            query = """
                SELECT file_path, filename
                FROM bulletin_attachments
                WHERE id = ?
            """
            
            cursor = self.db.cursor()
            cursor.execute(query, (attachment_id,))
            result = cursor.fetchone()
            
            if not result:
                return None
            
            # Update download count
            update_query = """
                UPDATE bulletin_attachments
                SET download_count = download_count + 1, 
                    last_downloaded = ?
                WHERE id = ?
            """
            cursor.execute(update_query, (datetime.now(), attachment_id))
            self.db.commit()
            
            return (result['file_path'], result['filename'])
        
        except Exception as e:
            logger.error(f"Error downloading attachment: {e}")
            return None
    
    
    # ========== BULLETIN STATUS & DELIVERY ==========
    
    def update_bulletin_status(self, bulletin_id: int, new_status: str, 
                               updated_by: str, reason: str = '') -> bool:
        """Update bulletin status and create version history"""
        try:
            cursor = self.db.cursor()
            
            # Get current bulletin state
            get_query = """
                SELECT title, body, status, regions, cve_ids
                FROM bulletins WHERE id = ?
            """
            cursor.execute(get_query, (bulletin_id,))
            current = cursor.fetchone()
            
            # Update status
            update_query = """
                UPDATE bulletins
                SET status = ?, updated_by = ?, updated_at = ?,
                    sent_at = CASE WHEN ? = 'SENT' THEN ? ELSE sent_at END,
                    sent_by = CASE WHEN ? = 'SENT' THEN ? ELSE sent_by END,
                    version = version + 1
                WHERE id = ?
            """
            
            cursor.execute(update_query, (
                new_status, updated_by, datetime.now(),
                new_status, datetime.now(),
                new_status, updated_by,
                bulletin_id
            ))
            
            # Create version history entry
            history_query = """
                INSERT INTO bulletin_version_history (
                    bulletin_id, version_number, change_type, changed_by,
                    changed_at, previous_state, change_reason
                )
                VALUES (?, 
                    (SELECT version FROM bulletins WHERE id = ?),
                    ?, ?, ?, ?, ?)
            """
            
            cursor.execute(history_query, (
                bulletin_id, bulletin_id,
                'STATUS_CHANGED', updated_by, datetime.now(),
                json.dumps({
                    'previous_status': current['status'],
                    'new_status': new_status
                }),
                reason
            ))
            
            self.db.commit()
            logger.info(f"Updated bulletin {bulletin_id} status to {new_status}")
            return True
        
        except Exception as e:
            logger.error(f"Error updating bulletin status: {e}")
            self.db.rollback()
            return False
    
    
    def create_delivery_log(self, bulletin_id: int, region_id: int, 
                           recipients: List[str], delivery_method: str) -> bool:
        """Create delivery log entries for a bulletin"""
        try:
            cursor = self.db.cursor()
            
            query = """
                INSERT INTO bulletin_delivery_log (
                    bulletin_id, region_id, recipient_email, 
                    delivery_status, delivery_method, scheduled_time
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """
            
            for recipient in recipients:
                cursor.execute(query, (
                    bulletin_id, region_id, recipient,
                    'PENDING', delivery_method, datetime.now()
                ))
            
            self.db.commit()
            logger.info(f"Created {len(recipients)} delivery log entries for bulletin {bulletin_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error creating delivery log: {e}")
            self.db.rollback()
            return False
    
    
    def get_bulletin_with_details(self, bulletin_id: int) -> Optional[Dict[str, Any]]:
        """Get complete bulletin with groupings and attachments"""
        try:
            cursor = self.db.cursor()
            
            # Get bulletin
            query = """
                SELECT id, title, body, status, cve_ids, regions, 
                       created_by, created_at, sent_at, cve_count
                FROM bulletins WHERE id = ?
            """
            cursor.execute(query, (bulletin_id,))
            bulletin = cursor.fetchone()
            
            if not bulletin:
                return None
            
            # Get groupings
            grouping_query = """
                SELECT vendor, product, cve_ids, cve_count, 
                       remediation_guidance, remediation_priority
                FROM bulletin_cve_groupings
                WHERE bulletin_id = ?
                ORDER BY group_order
            """
            cursor.execute(grouping_query, (bulletin_id,))
            groupings = cursor.fetchall()
            
            # Get attachments
            attachments = self.get_attachments(bulletin_id)
            
            # Get delivery status
            delivery_query = """
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN delivery_status = 'SENT' THEN 1 ELSE 0 END) as sent,
                    SUM(CASE WHEN delivery_status = 'FAILED' THEN 1 ELSE 0 END) as failed
                FROM bulletin_delivery_log
                WHERE bulletin_id = ?
            """
            cursor.execute(delivery_query, (bulletin_id,))
            delivery_status = cursor.fetchone()
            
            return {
                **dict(bulletin),
                'groupings': [dict(g) for g in groupings],
                'attachments': attachments,
                'delivery_status': dict(delivery_status) if delivery_status else {},
                'cve_ids': json.loads(bulletin['cve_ids']) if bulletin['cve_ids'] else [],
                'regions': json.loads(bulletin['regions']) if bulletin['regions'] else []
            }
        
        except Exception as e:
            logger.error(f"Error fetching bulletin details: {e}")
            return None
