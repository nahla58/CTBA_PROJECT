"""
Enhanced Bulletin Service - CVE Grouping, Region Management, and Attachment Support
"""
import json
import logging
import sqlite3
import os
import hashlib
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
import pytz

logger = logging.getLogger(__name__)

# ============================================================================
# CVE GROUPING SERVICE
# ============================================================================

class CVEGroupingService:
    """Service for grouping CVEs by technology and remediation guidance"""
    
    def __init__(self, db_path: str = 'ctba_platform.db'):
        self.db_path = db_path
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn
    
    def group_cves_by_technology(self, cve_ids: List[str]) -> Dict[str, List[Dict]]:
        """
        Group validated CVEs by vendor/product technology
        
        Args:
            cve_ids: List of CVE IDs to group
            
        Returns:
            Dictionary with structure:
            {
                "vendor:product": [
                    {
                        "cve_id": "CVE-2026-1234",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "description": "...",
                        "published_date": "..."
                    },
                    ...
                ],
                ...
            }
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            groups = defaultdict(list)
            
            # Get CVE and affected product information
            for cve_id in cve_ids:
                cursor.execute('''
                    SELECT DISTINCT 
                        c.cve_id, c.severity, c.cvss_score, c.description, 
                        c.published_date, ap.vendor, ap.product
                    FROM cves c
                    LEFT JOIN affected_products ap ON c.cve_id = ap.cve_id
                    WHERE c.cve_id = ? AND c.status = 'VALIDATED'
                    ORDER BY ap.vendor, ap.product
                ''', (cve_id,))
                
                rows = cursor.fetchall()
                for row in rows:
                    if row['vendor'] and row['product']:
                        key = f"{row['vendor']}:{row['product']}"
                        groups[key].append({
                            'cve_id': row['cve_id'],
                            'severity': row['severity'],
                            'cvss_score': row['cvss_score'],
                            'description': row['description'],
                            'published_date': row['published_date'],
                            'vendor': row['vendor'],
                            'product': row['product']
                        })
            
            conn.close()
            return dict(groups)
        except Exception as e:
            logger.error(f"Error grouping CVEs: {e}")
            raise
    
    def get_remediation_guidance(self, vendor: str, product: str, severity: Optional[str] = None) -> Optional[str]:
        """
        Get remediation guidance from library for a technology
        
        Args:
            vendor: Vendor name
            product: Product name
            severity: Optional severity level
            
        Returns:
            Remediation guidance text or None
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            if severity:
                cursor.execute('''
                    SELECT remediation_text 
                    FROM remediation_library
                    WHERE vendor = ? AND product = ? AND severity = ? AND active = TRUE
                    LIMIT 1
                ''', (vendor, product, severity))
            else:
                cursor.execute('''
                    SELECT remediation_text 
                    FROM remediation_library
                    WHERE vendor = ? AND product = ? AND active = TRUE
                    ORDER BY CASE 
                        WHEN severity = 'CRITICAL' THEN 1
                        WHEN severity = 'HIGH' THEN 2
                        WHEN severity = 'MEDIUM' THEN 3
                        ELSE 4
                    END
                    LIMIT 1
                ''', (vendor, product))
            
            row = cursor.fetchone()
            conn.close()
            
            return row['remediation_text'] if row else None
        except Exception as e:
            logger.error(f"Error fetching remediation guidance: {e}")
            return None


# ============================================================================
# REGION MANAGEMENT SERVICE
# ============================================================================

class RegionService:
    """Service for managing delivery regions"""
    
    def __init__(self, db_path: str = 'ctba_platform.db'):
        self.db_path = db_path
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_region(
        self,
        name: str,
        description: str = '',
        recipients: str = '',
        region_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new region"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            created_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
            
            cursor.execute('''
                INSERT INTO regions (name, description, recipients, region_code, active, archived, created_at)
                VALUES (?, ?, ?, ?, TRUE, FALSE, ?)
            ''', (name, description, recipients, region_code or name.upper()[:10], created_at))
            
            region_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.info(f"Created region {region_id}: {name}")
            
            return {
                'id': region_id,
                'name': name,
                'description': description,
                'region_code': region_code or name.upper()[:10],
                'active': True,
                'archived': False,
                'created_at': created_at
            }
        except Exception as e:
            logger.error(f"Error creating region: {e}")
            raise
    
    def get_active_regions(self) -> List[Dict[str, Any]]:
        """Get all active (non-archived) regions"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, name, description, region_code, recipients, created_at
                FROM regions
                WHERE active = TRUE AND archived = FALSE
                ORDER BY name
            ''')
            
            regions = []
            for row in cursor.fetchall():
                regions.append({
                    'id': row['id'],
                    'name': row['name'],
                    'description': row['description'],
                    'region_code': row['region_code'],
                    'recipients': row['recipients'].split(',') if row['recipients'] else [],
                    'created_at': row['created_at']
                })
            
            conn.close()
            return regions
        except Exception as e:
            logger.error(f"Error fetching active regions: {e}")
            raise
    
    def archive_region(
        self,
        region_id: int,
        reason: str = ''
    ) -> bool:
        """
        Archive a region without deleting it (preserves historical data)
        
        Args:
            region_id: ID of region to archive
            reason: Reason for archiving
            
        Returns:
            True if successful
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            archived_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
            
            cursor.execute('''
                UPDATE regions
                SET archived = TRUE, active = FALSE, archived_at = ?, archive_reason = ?
                WHERE id = ?
            ''', (archived_at, reason, region_id))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Archived region {region_id}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Error archiving region: {e}")
            raise


# ============================================================================
# ATTACHMENT MANAGEMENT SERVICE
# ============================================================================

class AttachmentService:
    """Service for managing bulletin attachments"""
    
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'zip', 'csv', 'jpg', 'png'}
    UPLOAD_DIR = 'bulletins/attachments'
    
    def __init__(self, db_path: str = 'ctba_platform.db'):
        self.db_path = db_path
        os.makedirs(self.UPLOAD_DIR, exist_ok=True)
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn
    
    def validate_file(self, filename: str, file_size: int) -> Tuple[bool, str]:
        """
        Validate file before upload
        
        Args:
            filename: Original filename
            file_size: File size in bytes
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if file_size > self.MAX_FILE_SIZE:
            return False, f"File size exceeds {self.MAX_FILE_SIZE / (1024*1024):.0f} MB limit"
        
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext not in self.ALLOWED_EXTENSIONS:
            return False, f"File type .{ext} not allowed. Allowed: {', '.join(self.ALLOWED_EXTENSIONS)}"
        
        return True, ""
    
    def save_attachment(
        self,
        bulletin_id: int,
        filename: str,
        file_content: bytes,
        uploaded_by: str,
        content_type: str = 'application/octet-stream'
    ) -> Dict[str, Any]:
        """
        Save file attachment to bulletin
        
        Args:
            bulletin_id: ID of bulletin
            filename: Original filename
            file_content: File bytes
            uploaded_by: Username of uploader
            content_type: MIME type
            
        Returns:
            Attachment record
        """
        try:
            # Validate file
            is_valid, error = self.validate_file(filename, len(file_content))
            if not is_valid:
                raise ValueError(error)
            
            # Generate unique filename and save file
            file_hash = hashlib.sha256(file_content).hexdigest()[:16]
            safe_filename = f"{bulletin_id}_{file_hash}_{filename}"
            file_path = os.path.join(self.UPLOAD_DIR, safe_filename)
            
            with open(file_path, 'wb') as f:
                f.write(file_content)
            
            # Store in database
            conn = self._get_connection()
            cursor = conn.cursor()
            
            file_checksum = hashlib.sha256(file_content).hexdigest()
            uploaded_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
            
            cursor.execute('''
                INSERT INTO bulletin_attachments 
                (bulletin_id, filename, original_filename, file_path, file_size, 
                 content_type, checksum, uploaded_by, uploaded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                bulletin_id, safe_filename, filename, file_path, len(file_content),
                content_type, file_checksum, uploaded_by, uploaded_at
            ))
            
            attachment_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.info(f"Saved attachment {attachment_id} to bulletin {bulletin_id}")
            
            return {
                'id': attachment_id,
                'bulletin_id': bulletin_id,
                'filename': filename,
                'file_path': file_path,
                'file_size': len(file_content),
                'content_type': content_type,
                'checksum': file_checksum,
                'uploaded_by': uploaded_by,
                'uploaded_at': uploaded_at
            }
        except Exception as e:
            logger.error(f"Error saving attachment: {e}")
            raise
    
    def get_attachments(self, bulletin_id: int) -> List[Dict[str, Any]]:
        """Get all attachments for a bulletin"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, filename, original_filename, file_size, content_type, 
                       uploaded_by, uploaded_at, checksum
                FROM bulletin_attachments
                WHERE bulletin_id = ? AND archived = FALSE
                ORDER BY uploaded_at DESC
            ''', (bulletin_id,))
            
            attachments = []
            for row in cursor.fetchall():
                attachments.append({
                    'id': row['id'],
                    'filename': row['original_filename'],
                    'size': row['file_size'],
                    'content_type': row['content_type'],
                    'uploaded_by': row['uploaded_by'],
                    'uploaded_at': row['uploaded_at'],
                    'checksum': row['checksum']
                })
            
            conn.close()
            return attachments
        except Exception as e:
            logger.error(f"Error fetching attachments: {e}")
            raise
    
    def download_attachment(self, attachment_id: int) -> Optional[Tuple[str, bytes]]:
        """
        Download an attachment file
        
        Returns:
            Tuple of (filename, file_content) or None if not found
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT original_filename, file_path
                FROM bulletin_attachments
                WHERE id = ?
            ''', (attachment_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            with open(row['file_path'], 'rb') as f:
                content = f.read()
            
            return (row['original_filename'], content)
        except Exception as e:
            logger.error(f"Error downloading attachment: {e}")
            return None
    
    def delete_attachment(self, attachment_id: int) -> bool:
        """Soft delete (archive) an attachment"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE bulletin_attachments
                SET archived = TRUE
                WHERE id = ?
            ''', (attachment_id,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Archived attachment {attachment_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting attachment: {e}")
            raise


# ============================================================================
# ENHANCED BULLETIN SERVICE
# ============================================================================

class EnhancedBulletinService:
    """Enhanced bulletin service with grouping, regions, and attachments"""
    
    def __init__(self, db_path: str = 'ctba_platform.db'):
        self.db_path = db_path
        self.grouping_service = CVEGroupingService(db_path)
        self.region_service = RegionService(db_path)
        self.attachment_service = AttachmentService(db_path)
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_bulletin_with_grouping(
        self,
        title: str,
        cve_ids: List[str],
        region_ids: List[int],
        created_by: str,
        body: str = '',
        auto_group: bool = True
    ) -> Dict[str, Any]:
        """
        Create a bulletin with automatic CVE grouping
        
        Args:
            title: Bulletin title
            cve_ids: List of CVE IDs to include
            region_ids: List of region IDs to send to
            created_by: Username of creator
            body: Bulletin body text
            auto_group: Whether to automatically group CVEs
            
        Returns:
            Created bulletin details
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            created_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
            
            # Create bulletin record
            cursor.execute('''
                INSERT INTO bulletins 
                (title, body, status, created_by, created_at, grouped_by_technology, archived)
                VALUES (?, ?, ?, ?, ?, ?, FALSE)
            ''', (title, body, 'DRAFT', created_by, created_at, auto_group))
            
            bulletin_id = cursor.lastrowid
            
            # Add regions
            for region_id in region_ids:
                try:
                    cursor.execute('''
                        INSERT INTO bulletin_regions (bulletin_id, region_id, selected_at)
                        VALUES (?, ?, ?)
                    ''', (bulletin_id, region_id, created_at))
                except sqlite3.IntegrityError:
                    pass  # Skip if already added
            
            # Group CVEs if requested
            if auto_group:
                groups = self.grouping_service.group_cves_by_technology(cve_ids)
                group_counter = 0
                
                for tech_key, cves in groups.items():
                    vendor, product = tech_key.split(':')
                    group_id = f"g_{bulletin_id}_{group_counter}"
                    
                    # Get remediation guidance
                    remediation = self.grouping_service.get_remediation_guidance(
                        vendor, product, cves[0].get('severity') if cves else None
                    )
                    
                    # Create group record
                    cursor.execute('''
                        INSERT INTO bulletin_cve_groups 
                        (bulletin_id, group_id, vendor, product, cve_count, remediation_guidance)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (bulletin_id, group_id, vendor, product, len(cves), remediation))
                    
                    # Add CVEs to group
                    for cve in cves:
                        cursor.execute('''
                            INSERT INTO bulletin_cves 
                            (bulletin_id, cve_id, group_id, vendor, product, remediation_guidance)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (bulletin_id, cve['cve_id'], group_id, vendor, product, remediation))
                    
                    group_counter += 1
            else:
                # Add CVEs without grouping
                for cve_id in cve_ids:
                    cursor.execute('''
                        INSERT INTO bulletin_cves (bulletin_id, cve_id)
                        VALUES (?, ?)
                    ''', (bulletin_id, cve_id))
            
            # Create metadata record
            cursor.execute('''
                INSERT INTO bulletin_metadata (bulletin_id, total_cves)
                VALUES (?, ?)
            ''', (bulletin_id, len(cve_ids)))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Created bulletin {bulletin_id}: {title} with {len(cve_ids)} CVEs")
            
            return {
                'id': bulletin_id,
                'title': title,
                'status': 'DRAFT',
                'created_by': created_by,
                'created_at': created_at,
                'cve_count': len(cve_ids),
                'region_count': len(region_ids),
                'grouped_by_technology': auto_group
            }
        except Exception as e:
            logger.error(f"Error creating bulletin: {e}")
            raise
    
    def get_bulletin_detail(self, bulletin_id: int) -> Dict[str, Any]:
        """Get full bulletin details with CVEs, groups, and metadata"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get bulletin
            cursor.execute('SELECT * FROM bulletins WHERE id = ?', (bulletin_id,))
            bulletin_row = cursor.fetchone()
            
            if not bulletin_row:
                conn.close()
                raise ValueError(f"Bulletin {bulletin_id} not found")
            
            bulletin = dict(bulletin_row)
            
            # Get grouped CVEs
            cursor.execute('''
                SELECT group_id, vendor, product, remediation_guidance, COUNT(*) as cve_count
                FROM bulletin_cves
                WHERE bulletin_id = ?
                GROUP BY group_id, vendor, product
            ''', (bulletin_id,))
            
            groups = []
            for group_row in cursor.fetchall():
                # Get CVEs in this group
                cursor.execute('''
                    SELECT cve_id, severity, cvss_score, description
                    FROM bulletin_cves bc
                    JOIN cves c ON bc.cve_id = c.cve_id
                    WHERE bc.bulletin_id = ? AND bc.group_id = ?
                ''', (bulletin_id, group_row['group_id']))
                
                cves_in_group = [dict(row) for row in cursor.fetchall()]
                
                groups.append({
                    'vendor': group_row['vendor'],
                    'product': group_row['product'],
                    'cve_count': group_row['cve_count'],
                    'remediation_guidance': group_row['remediation_guidance'],
                    'cves': cves_in_group
                })
            
            # Get regions
            cursor.execute('''
                SELECT r.id, r.name, r.region_code
                FROM bulletin_regions br
                JOIN regions r ON br.region_id = r.id
                WHERE br.bulletin_id = ?
            ''', (bulletin_id,))
            
            regions = [dict(row) for row in cursor.fetchall()]
            
            # Get attachments
            attachments = self.attachment_service.get_attachments(bulletin_id)
            
            conn.close()
            
            return {
                'id': bulletin['id'],
                'title': bulletin['title'],
                'body': bulletin['body'],
                'status': bulletin['status'],
                'created_by': bulletin['created_by'],
                'created_at': bulletin['created_at'],
                'grouped_cves': groups,
                'regions': regions,
                'attachments': attachments,
                'remediation_guidance': bulletin['remediation_guidance'],
                'grouped_by_technology': bulletin['grouped_by_technology'],
                'archived': bulletin['archived']
            }
        except Exception as e:
            logger.error(f"Error fetching bulletin detail: {e}")
            raise
    
    def update_bulletin_status(
        self,
        bulletin_id: int,
        new_status: str,
        updated_by: str
    ) -> bool:
        """
        Update bulletin status (Draft, Sent, Not Processed, Archived)
        
        Args:
            bulletin_id: ID of bulletin
            new_status: New status value
            updated_by: Username of updater
            
        Returns:
            True if successful
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            updated_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
            
            cursor.execute('''
                UPDATE bulletins
                SET status = ?, updated_at = ?, updated_by = ?
                WHERE id = ?
            ''', (new_status, updated_at, updated_by, bulletin_id))
            
            # Log the change
            cursor.execute('''
                INSERT INTO bulletin_audit_log (bulletin_id, action, actor, created_at)
                VALUES (?, ?, ?, ?)
            ''', (bulletin_id, f'STATUS_CHANGED_TO_{new_status}', updated_by, updated_at))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Updated bulletin {bulletin_id} status to {new_status}")
            return True
        except Exception as e:
            logger.error(f"Error updating bulletin status: {e}")
            raise
