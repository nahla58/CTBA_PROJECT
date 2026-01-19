"""
Bulletin Service Layer - Business logic for bulletin management
"""
import logging
import json
import sqlite3
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from models.bulletin_models import CVEGrouping, BulletinStatus
from database import get_db_connection

logger = logging.getLogger(__name__)


class BulletinService:
    """Service for managing bulletins"""
    
    @staticmethod
    def create_bulletin(
        title: str,
        body: Optional[str],
        regions: List[str],
        cve_ids: Optional[List[str]] = None,
        created_by: str = "system"
    ) -> Dict:
        """Create a new bulletin"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Convert regions list to JSON
            regions_json = json.dumps(regions)
            
            cursor.execute('''
                INSERT INTO bulletins (title, body, regions, status, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (title, body, regions_json, BulletinStatus.DRAFT.value, created_by))
            
            bulletin_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"✅ Bulletin #{bulletin_id} created: {title}")
            
            return {
                'id': bulletin_id,
                'title': title,
                'regions': regions,
                'status': BulletinStatus.DRAFT.value,
                'created_by': created_by
            }
        
        except Exception as e:
            logger.error(f"Error creating bulletin: {e}")
            raise
    
    @staticmethod
    def get_bulletins(
        status: Optional[str] = None,
        region: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Dict], int]:
        """Fetch bulletins with optional filters"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            query = "SELECT * FROM bulletins WHERE 1=1"
            params = []
            
            if status:
                query += " AND status = ?"
                params.append(status)
            
            # Count total
            count_query = query.replace('SELECT *', 'SELECT COUNT(*)')
            cursor.execute(count_query, params)
            total = cursor.fetchone()[0]
            
            # Fetch with pagination
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            bulletins = []
            for row in rows:
                bulletin = dict(row) if isinstance(row, sqlite3.Row) else row
                if isinstance(bulletin['regions'], str):
                    bulletin['regions'] = json.loads(bulletin['regions'])
                
                # Count associated CVEs
                cve_count = BulletinService._get_bulletin_cve_count(bulletin['id'])
                bulletin['cve_count'] = cve_count
                
                bulletins.append(bulletin)
            
            return bulletins, total
        
        except Exception as e:
            logger.error(f"Error fetching bulletins: {e}")
            raise
    
    @staticmethod
    def get_bulletin_detail(bulletin_id: int) -> Optional[Dict]:
        """Get detailed bulletin with CVEs and attachments"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get bulletin
            cursor.execute("SELECT * FROM bulletins WHERE id = ?", (bulletin_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            bulletin = dict(row) if isinstance(row, sqlite3.Row) else row
            if isinstance(bulletin['regions'], str):
                bulletin['regions'] = json.loads(bulletin['regions'])
            
            # Get attached CVEs
            cves = BulletinService._get_bulletin_cves(bulletin_id)
            bulletin['cves'] = cves
            
            # Get grouped CVEs by technology
            grouped = BulletinService._group_cves_by_technology(cves)
            bulletin['grouped_cves'] = grouped
            
            # Get attachments
            cursor.execute('''
                SELECT id, bulletin_id, filename, path, created_at
                FROM bulletin_attachments
                WHERE bulletin_id = ?
            ''', (bulletin_id,))
            
            attachments = []
            for row in cursor.fetchall():
                attachments.append(dict(row) if isinstance(row, sqlite3.Row) else row)
            
            bulletin['attachments'] = attachments
            bulletin['attachment_count'] = len(attachments)
            
            return bulletin
        
        except Exception as e:
            logger.error(f"Error fetching bulletin detail: {e}")
            raise
    
    @staticmethod
    def update_bulletin(
        bulletin_id: int,
        title: Optional[str] = None,
        body: Optional[str] = None,
        regions: Optional[List[str]] = None,
        status: Optional[str] = None
    ) -> Dict:
        """Update bulletin"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Build update query
            updates = []
            params = []
            
            if title:
                updates.append("title = ?")
                params.append(title)
            
            if body is not None:
                updates.append("body = ?")
                params.append(body)
            
            if regions:
                updates.append("regions = ?")
                params.append(json.dumps(regions))
            
            if status:
                updates.append("status = ?")
                params.append(status)
            
            if not updates:
                return {'message': 'No updates provided'}
            
            params.append(bulletin_id)
            
            query = f"UPDATE bulletins SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, params)
            conn.commit()
            
            logger.info(f"✅ Bulletin #{bulletin_id} updated")
            
            return BulletinService.get_bulletin_detail(bulletin_id)
        
        except Exception as e:
            logger.error(f"Error updating bulletin: {e}")
            raise
    
    @staticmethod
    def delete_bulletin(bulletin_id: int) -> bool:
        """Delete bulletin and associated data"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Delete CASCADE will handle attachments and logs
            cursor.execute("DELETE FROM bulletins WHERE id = ?", (bulletin_id,))
            conn.commit()
            
            logger.info(f"✅ Bulletin #{bulletin_id} deleted")
            
            return True
        
        except Exception as e:
            logger.error(f"Error deleting bulletin: {e}")
            raise
    
    @staticmethod
    def add_attachment(bulletin_id: int, filename: str, filepath: str) -> Dict:
        """Add attachment to bulletin"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO bulletin_attachments (bulletin_id, filename, path, created_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (bulletin_id, filename, filepath))
            
            attachment_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"✅ Attachment added to bulletin #{bulletin_id}: {filename}")
            
            return {
                'id': attachment_id,
                'bulletin_id': bulletin_id,
                'filename': filename,
                'path': filepath
            }
        
        except Exception as e:
            logger.error(f"Error adding attachment: {e}")
            raise
    
    @staticmethod
    def log_delivery(
        bulletin_id: int,
        action: str,
        region: str,
        recipients: str,
        message: Optional[str] = None
    ) -> Dict:
        """Log bulletin delivery action"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO bulletin_logs
                (bulletin_id, action, region, recipients, message, created_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (bulletin_id, action, region, recipients, message))
            
            log_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"✅ Delivery logged for bulletin #{bulletin_id}: {action} to {region}")
            
            return {
                'id': log_id,
                'bulletin_id': bulletin_id,
                'action': action,
                'region': region
            }
        
        except Exception as e:
            logger.error(f"Error logging delivery: {e}")
            raise
    
    @staticmethod
    def get_delivery_history(bulletin_id: int) -> List[Dict]:
        """Get all delivery logs for a bulletin"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, bulletin_id, action, region, recipients, message, created_at
                FROM bulletin_logs
                WHERE bulletin_id = ?
                ORDER BY created_at DESC
            ''', (bulletin_id,))
            
            logs = []
            for row in cursor.fetchall():
                logs.append(dict(row) if isinstance(row, sqlite3.Row) else row)
            
            return logs
        
        except Exception as e:
            logger.error(f"Error fetching delivery history: {e}")
            raise
    
    # ========================================================================
    # PRIVATE HELPER METHODS
    # ========================================================================
    
    @staticmethod
    def _get_bulletin_cve_count(bulletin_id: int) -> int:
        """Get count of CVEs related to bulletin (via affected_products)"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # For now, return 0 - will be implemented based on business logic
            # Future: implement CVE grouping and assignment to bulletins
            return 0
        
        except Exception as e:
            logger.error(f"Error counting CVEs: {e}")
            return 0
    
    @staticmethod
    def _get_bulletin_cves(bulletin_id: int) -> List[Dict]:
        """Get CVEs associated with bulletin"""
        try:
            # Placeholder - will be implemented based on business logic
            return []
        
        except Exception as e:
            logger.error(f"Error fetching bulletin CVEs: {e}")
            return []
    
    @staticmethod
    def _group_cves_by_technology(cves: List[Dict]) -> List[CVEGrouping]:
        """Group CVEs by technology/product"""
        grouped = {}
        
        for cve in cves:
            # Get affected products for this CVE
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT vendor, product
                    FROM affected_products
                    WHERE cve_id = ?
                ''', (cve['cve_id'],))
                
                products = cursor.fetchall()
                
                for product in products:
                    tech_key = f"{product[0]}: {product[1]}"
                    
                    if tech_key not in grouped:
                        grouped[tech_key] = {
                            'technology': tech_key,
                            'cves': [],
                            'count': 0
                        }
                    
                    grouped[tech_key]['cves'].append(cve)
                    grouped[tech_key]['count'] += 1
            
            except Exception as e:
                logger.warning(f"Error grouping CVE {cve.get('cve_id')}: {e}")
        
        return [CVEGrouping(**g) for g in grouped.values()]


class RegionService:
    """Service for managing regions and mailing lists"""
    
    @staticmethod
    def create_region(name: str, description: Optional[str], recipients: str) -> Dict:
        """Create a new region"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO regions (name, description, recipients, created_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (name, description, recipients))
            
            region_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"✅ Region created: {name} (ID: {region_id})")
            
            return {
                'id': region_id,
                'name': name,
                'description': description,
                'recipients': recipients.split(',')
            }
        
        except Exception as e:
            logger.error(f"Error creating region: {e}")
            raise
    
    @staticmethod
    def get_regions() -> List[Dict]:
        """Get all regions"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, name, description, recipients, created_at
                FROM regions
                ORDER BY name
            ''')
            
            regions = []
            for row in cursor.fetchall():
                region = dict(row) if isinstance(row, sqlite3.Row) else row
                region['recipients'] = region['recipients'].split(',') if region['recipients'] else []
                regions.append(region)
            
            return regions
        
        except Exception as e:
            logger.error(f"Error fetching regions: {e}")
            raise
    
    @staticmethod
    def get_region(region_id: int) -> Optional[Dict]:
        """Get single region"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, name, description, recipients, created_at
                FROM regions
                WHERE id = ?
            ''', (region_id,))
            
            row = cursor.fetchone()
            
            if not row:
                return None
            
            region = dict(row) if isinstance(row, sqlite3.Row) else row
            region['recipients'] = region['recipients'].split(',') if region['recipients'] else []
            
            return region
        
        except Exception as e:
            logger.error(f"Error fetching region: {e}")
            raise
    
    @staticmethod
    def update_region(region_id: int, description: Optional[str] = None, recipients: Optional[str] = None) -> Dict:
        """Update region"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            updates = []
            params = []
            
            if description is not None:
                updates.append("description = ?")
                params.append(description)
            
            if recipients is not None:
                updates.append("recipients = ?")
                params.append(recipients)
            
            if not updates:
                return RegionService.get_region(region_id)
            
            params.append(region_id)
            
            query = f"UPDATE regions SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, params)
            conn.commit()
            
            logger.info(f"✅ Region #{region_id} updated")
            
            return RegionService.get_region(region_id)
        
        except Exception as e:
            logger.error(f"Error updating region: {e}")
            raise
    
    @staticmethod
    def delete_region(region_id: int) -> bool:
        """Delete region (archive instead of delete for audit trail)"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM regions WHERE id = ?", (region_id,))
            conn.commit()
            
            logger.warning(f"⚠️ Region #{region_id} deleted (consider archiving instead)")
            
            return True
        
        except Exception as e:
            logger.error(f"Error deleting region: {e}")
            raise
