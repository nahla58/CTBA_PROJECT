"""
Bulletin Service - Business logic for bulletin management and CVE grouping
"""
import json
import logging
import sqlite3
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)


class BulletinService:
    """Service for bulletin CRUD operations and management"""
    
    def __init__(self, db_path: str = 'ctba_platform.db'):
        """Initialize bulletin service"""
        self.db_path = db_path
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_bulletin(
        self,
        title: str,
        body: Optional[str],
        regions: List[str],
        cve_ids: Optional[List[str]],
        created_by: str
    ) -> Dict[str, Any]:
        """Create a new bulletin"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            regions_json = json.dumps(regions)
            created_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
            
            cursor.execute('''
                INSERT INTO bulletins (title, body, regions, status, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (title, body, regions_json, 'DRAFT', created_by, created_at))
            
            bulletin_id = cursor.lastrowid
            
            # Associate CVEs if provided
            if cve_ids:
                for cve_id in cve_ids:
                    try:
                        cursor.execute('''
                            INSERT INTO bulletin_cves (bulletin_id, cve_id)
                            VALUES (?, ?)
                        ''')
                    except sqlite3.OperationalError:
                        # Table doesn't exist yet, skip
                        pass
            
            conn.commit()
            conn.close()
            
            logger.info(f"Created bulletin {bulletin_id}: {title}")
            
            return {
                'id': bulletin_id,
                'title': title,
                'regions': regions,
                'status': 'DRAFT',
                'created_by': created_by,
                'created_at': created_at
            }
        except Exception as e:
            logger.error(f"Error creating bulletin: {e}")
            raise
    
    def get_bulletins(
        self,
        status: Optional[str] = None,
        region: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Dict], int]:
        """Get bulletins with optional filtering and pagination"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            query = "SELECT * FROM bulletins WHERE 1=1"
            params = []
            
            if status:
                query += " AND status = ?"
                params.append(status)
            
            if region:
                query += " AND regions LIKE ?"
                params.append(f'%{region}%')
            
            # Get total count
            count_query = query.replace('SELECT *', 'SELECT COUNT(*)')
            cursor.execute(count_query, params)
            total = cursor.fetchone()[0]
            
            # Get paginated results
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            
            bulletins = []
            for row in cursor.fetchall():
                bulletin = dict(row)
                bulletin['regions'] = json.loads(bulletin['regions'] or '[]')
                bulletin['cve_count'] = self._get_bulletin_cve_count(bulletin['id'])
                bulletins.append(bulletin)
            
            conn.close()
            
            return bulletins, total
        except Exception as e:
            logger.error(f"Error fetching bulletins: {e}")
            raise
    
    def get_bulletin_detail(self, bulletin_id: int) -> Dict[str, Any]:
        """Get full bulletin details including CVEs and attachments"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get bulletin
            cursor.execute("SELECT * FROM bulletins WHERE id = ?", (bulletin_id,))
            row = cursor.fetchone()
            
            if not row:
                conn.close()
                raise ValueError(f"Bulletin {bulletin_id} not found")
            
            bulletin = dict(row)
            bulletin['regions'] = json.loads(bulletin['regions'] or '[]')
            
            # Get CVEs
            cves = self._get_bulletin_cves(bulletin_id)
            bulletin['cves'] = cves
            
            # Group CVEs by technology
            bulletin['grouped_cves'] = self._group_cves_by_technology(cves)
            
            # Get attachments
            cursor.execute('''
                SELECT id, filename, path FROM bulletin_attachments WHERE bulletin_id = ?
            ''', (bulletin_id,))
            
            attachments = []
            for att_row in cursor.fetchall():
                attachments.append({
                    'id': att_row['id'],
                    'filename': att_row['filename'],
                    'path': att_row['path']
                })
            
            bulletin['attachments'] = attachments
            
            conn.close()
            
            return bulletin
        except Exception as e:
            logger.error(f"Error fetching bulletin detail: {e}")
            raise
    
    def update_bulletin(
        self,
        bulletin_id: int,
        title: Optional[str] = None,
        body: Optional[str] = None,
        regions: Optional[List[str]] = None,
        status: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update a bulletin"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Build update query
            updates = []
            params = []
            
            if title is not None:
                updates.append("title = ?")
                params.append(title)
            
            if body is not None:
                updates.append("body = ?")
                params.append(body)
            
            if regions is not None:
                updates.append("regions = ?")
                params.append(json.dumps(regions))
            
            if status is not None:
                updates.append("status = ?")
                params.append(status)
            
            if updates:
                query = f"UPDATE bulletins SET {', '.join(updates)} WHERE id = ?"
                params.append(bulletin_id)
                cursor.execute(query, params)
                conn.commit()
                
                logger.info(f"Updated bulletin {bulletin_id}")
            
            # Return updated bulletin
            conn.close()
            return self.get_bulletin_detail(bulletin_id)
        except Exception as e:
            logger.error(f"Error updating bulletin: {e}")
            raise
    
    def delete_bulletin(self, bulletin_id: int) -> bool:
        """Delete a bulletin (cascades to attachments and logs)"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM bulletins WHERE id = ?", (bulletin_id,))
            conn.commit()
            conn.close()
            
            logger.info(f"Deleted bulletin {bulletin_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting bulletin: {e}")
            raise
    
    def add_attachment(self, bulletin_id: int, filename: str, filepath: str) -> Dict[str, Any]:
        """Add file attachment to bulletin"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO bulletin_attachments (bulletin_id, filename, path)
                VALUES (?, ?, ?)
            ''', (bulletin_id, filename, filepath))
            
            attachment_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.info(f"Added attachment {filename} to bulletin {bulletin_id}")
            
            return {
                'id': attachment_id,
                'bulletin_id': bulletin_id,
                'filename': filename,
                'path': filepath
            }
        except Exception as e:
            logger.error(f"Error adding attachment: {e}")
            raise
    
    def log_delivery(
        self,
        bulletin_id: int,
        action: str,
        region: str,
        recipients: Optional[str],
        message: Optional[str] = None
    ) -> Dict[str, Any]:
        """Log a delivery event"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            created_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
            
            cursor.execute('''
                INSERT INTO bulletin_logs (bulletin_id, action, region, recipients, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (bulletin_id, action, region, recipients, message, created_at))
            
            log_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return {
                'id': log_id,
                'bulletin_id': bulletin_id,
                'action': action,
                'region': region,
                'recipients': recipients,
                'message': message,
                'created_at': created_at
            }
        except Exception as e:
            logger.error(f"Error logging delivery: {e}")
            raise
    
    def get_delivery_history(self, bulletin_id: int) -> List[Dict[str, Any]]:
        """Get all delivery logs for a bulletin"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM bulletin_logs WHERE bulletin_id = ? ORDER BY created_at DESC
            ''', (bulletin_id,))
            
            logs = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return logs
        except Exception as e:
            logger.error(f"Error fetching delivery history: {e}")
            raise
    
    def _get_bulletin_cve_count(self, bulletin_id: int) -> int:
        """Get count of CVEs associated with bulletin"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Try to use bulletin_cves table if it exists
            try:
                cursor.execute('''
                    SELECT COUNT(*) as count FROM bulletin_cves WHERE bulletin_id = ?
                ''', (bulletin_id,))
                row = cursor.fetchone()
                conn.close()
                return row['count'] if row else 0
            except sqlite3.OperationalError:
                # Table doesn't exist
                conn.close()
                return 0
        except Exception:
            return 0
    
    def _get_bulletin_cves(self, bulletin_id: int) -> List[Dict[str, Any]]:
        """Get CVEs associated with bulletin"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Try to use bulletin_cves table if it exists
            try:
                cursor.execute('''
                    SELECT c.* FROM cves c
                    JOIN bulletin_cves bc ON c.cve_id = bc.cve_id
                    WHERE bc.bulletin_id = ?
                ''', (bulletin_id,))
                
                cves = []
                for row in cursor.fetchall():
                    cve = dict(row)
                    # Get affected products for this CVE
                    cursor2 = conn.cursor()
                    cursor2.execute('''
                        SELECT vendor, product FROM affected_products WHERE cve_id = ? LIMIT 5
                    ''', (cve['cve_id'],))
                    cve['products'] = [{'vendor': r['vendor'], 'product': r['product']} 
                                       for r in cursor2.fetchall()]
                    cves.append(cve)
                
                conn.close()
                return cves
            except sqlite3.OperationalError:
                # Table doesn't exist
                conn.close()
                return []
        except Exception as e:
            logger.warning(f"Error fetching bulletin CVEs: {e}")
            return []
    
    @staticmethod
    def _group_cves_by_technology(cves: List[Dict]) -> List[Dict[str, Any]]:
        """Group CVEs by vendor/product"""
        groups = {}
        
        for cve in cves:
            for product in cve.get('products', []):
                vendor = product['vendor']
                prod_name = product['product']
                key = f"{vendor}:{prod_name}"
                
                if key not in groups:
                    groups[key] = {
                        'vendor': vendor,
                        'product': prod_name,
                        'cve_count': 0,
                        'cves': [],
                        'remediation': None
                    }
                
                groups[key]['cve_count'] += 1
                groups[key]['cves'].append({
                    'cve_id': cve.get('cve_id'),
                    'severity': cve.get('severity', 'UNKNOWN'),
                    'cvss_score': cve.get('cvss_score', 0)
                })
        
        return list(groups.values())


class RegionService:
    """Service for region management"""
    
    def __init__(self, db_path: str = 'ctba_platform.db'):
        """Initialize region service"""
        self.db_path = db_path
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_region(self, name: str, description: str, recipients: str) -> Dict[str, Any]:
        """Create a new region"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            created_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
            
            cursor.execute('''
                INSERT INTO regions (name, description, recipients, created_at)
                VALUES (?, ?, ?, ?)
            ''', (name, description, recipients, created_at))
            
            region_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.info(f"Created region {name}")
            
            return {
                'id': region_id,
                'name': name,
                'description': description,
                'recipients': recipients.split(','),
                'created_at': created_at
            }
        except sqlite3.IntegrityError as e:
            logger.warning(f"Region already exists: {name}")
            raise ValueError(f"Region '{name}' already exists")
        except Exception as e:
            logger.error(f"Error creating region: {e}")
            raise
    
    def get_regions(self) -> List[Dict[str, Any]]:
        """Get all regions"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM regions ORDER BY name")
            
            regions = []
            for row in cursor.fetchall():
                region = dict(row)
                region['recipients'] = region['recipients'].split(',') if region['recipients'] else []
                regions.append(region)
            
            conn.close()
            
            return regions
        except Exception as e:
            logger.error(f"Error fetching regions: {e}")
            raise
    
    def get_region(self, region_id: int) -> Dict[str, Any]:
        """Get a specific region"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM regions WHERE id = ?", (region_id,))
            row = cursor.fetchone()
            
            if not row:
                conn.close()
                raise ValueError(f"Region {region_id} not found")
            
            region = dict(row)
            region['recipients'] = region['recipients'].split(',') if region['recipients'] else []
            
            conn.close()
            
            return region
        except Exception as e:
            logger.error(f"Error fetching region: {e}")
            raise
    
    def update_region(
        self,
        region_id: int,
        description: Optional[str] = None,
        recipients: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update a region"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            updates = []
            params = []
            
            if description is not None:
                updates.append("description = ?")
                params.append(description)
            
            if recipients is not None:
                updates.append("recipients = ?")
                params.append(recipients)
            
            if updates:
                query = f"UPDATE regions SET {', '.join(updates)} WHERE id = ?"
                params.append(region_id)
                cursor.execute(query, params)
                conn.commit()
                
                logger.info(f"Updated region {region_id}")
            
            conn.close()
            return self.get_region(region_id)
        except Exception as e:
            logger.error(f"Error updating region: {e}")
            raise
    
    def delete_region(self, region_id: int) -> bool:
        """Delete a region"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM regions WHERE id = ?", (region_id,))
            conn.commit()
            conn.close()
            
            logger.info(f"Deleted region {region_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting region: {e}")
            raise
