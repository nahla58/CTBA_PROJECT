"""
Audit Logger - Comprehensive logging for bulletin delivery and system actions
Provides traceability and compliance audit trails for all critical operations
"""
import logging
import sqlite3
from typing import Dict, Optional, Any, List
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AuditActionType(Enum):
    """Types of auditable actions"""
    BULLETIN_CREATED = "BULLETIN_CREATED"
    BULLETIN_UPDATED = "BULLETIN_UPDATED"
    BULLETIN_DELETED = "BULLETIN_DELETED"
    BULLETIN_SENT = "BULLETIN_SENT"
    BULLETIN_FAILED = "BULLETIN_FAILED"
    BULLETIN_QUEUED = "BULLETIN_QUEUED"
    EMAIL_SENT = "EMAIL_SENT"
    EMAIL_FAILED = "EMAIL_FAILED"
    REGION_CREATED = "REGION_CREATED"
    REGION_UPDATED = "REGION_UPDATED"
    REGION_DELETED = "REGION_DELETED"
    RETRY_ATTEMPTED = "RETRY_ATTEMPTED"
    PREVIEW_GENERATED = "PREVIEW_GENERATED"


class AuditLogger:
    """Comprehensive audit logging for bulletin system"""
    
    def __init__(self, db_path: str = 'ctba_platform.db'):
        """Initialize audit logger"""
        self.db_path = db_path
        self._ensure_audit_table()
        logger.info("✅ AuditLogger initialized")
    
    def _ensure_audit_table(self):
        """Create audit table if it doesn't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create audit_logs table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    actor TEXT,
                    resource_type TEXT,
                    resource_id INTEGER,
                    details TEXT,
                    status TEXT DEFAULT 'SUCCESS' CHECK(status IN ('SUCCESS', 'FAILURE', 'PARTIAL')),
                    recipient_count INTEGER DEFAULT 0,
                    region TEXT,
                    email_addresses TEXT,
                    cc_addresses TEXT,
                    bcc_addresses TEXT,
                    attachment_count INTEGER DEFAULT 0,
                    error_message TEXT,
                    duration_ms INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index on action and resource_id for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_action_resource 
                ON audit_logs(action, resource_id)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_created_at 
                ON audit_logs(created_at DESC)
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error creating audit table: {e}")
    
    def log_action(
        self,
        action: AuditActionType,
        resource_type: str,
        resource_id: Optional[int] = None,
        actor: Optional[str] = None,
        details: Optional[str] = None,
        status: str = 'SUCCESS',
        recipient_count: int = 0,
        region: Optional[str] = None,
        email_addresses: Optional[List[str]] = None,
        cc_addresses: Optional[List[str]] = None,
        bcc_addresses: Optional[List[str]] = None,
        attachment_count: int = 0,
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Log an audit event
        
        Args:
            action: Type of action performed
            resource_type: Type of resource (e.g., 'bulletin', 'region', 'email')
            resource_id: ID of the resource
            actor: User/system that performed action
            details: Additional JSON details
            status: SUCCESS, FAILURE, or PARTIAL
            recipient_count: Number of recipients affected
            region: Region name (for regional actions)
            email_addresses: List of To addresses
            cc_addresses: List of Cc addresses
            bcc_addresses: List of Bcc addresses
            attachment_count: Number of attachments
            error_message: Error message if failed
            duration_ms: Duration of operation in milliseconds
        
        Returns:
            Dict with audit log entry
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Prepare email address lists as CSV strings
            to_csv = ','.join(email_addresses) if email_addresses else None
            cc_csv = ','.join(cc_addresses) if cc_addresses else None
            bcc_csv = ','.join(bcc_addresses) if bcc_addresses else None
            
            cursor.execute('''
                INSERT INTO audit_logs (
                    action, actor, resource_type, resource_id, details, status,
                    recipient_count, region, email_addresses, cc_addresses, bcc_addresses,
                    attachment_count, error_message, duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                action.value,
                actor or 'SYSTEM',
                resource_type,
                resource_id,
                details,
                status,
                recipient_count,
                region,
                to_csv,
                cc_csv,
                bcc_csv,
                attachment_count,
                error_message,
                duration_ms
            ))
            
            log_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Log summary
            log_level = logging.ERROR if status == 'FAILURE' else logging.INFO
            logger.log(
                log_level,
                f"[AUDIT] {action.value} - {resource_type}#{resource_id} | "
                f"Status: {status} | Recipients: {recipient_count} | "
                f"Region: {region} | Duration: {duration_ms}ms"
            )
            
            return {
                'id': log_id,
                'action': action.value,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'status': status,
                'recipient_count': recipient_count,
                'region': region,
                'created_at': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error logging audit action: {e}")
            raise
    
    def get_audit_history(
        self,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        action: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> tuple[List[Dict[str, Any]], int]:
        """
        Retrieve audit history with filtering
        
        Args:
            resource_type: Filter by resource type
            resource_id: Filter by resource ID
            action: Filter by action type
            limit: Maximum records to return
            offset: Pagination offset
        
        Returns:
            (audit_records, total_count)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Build query
            query = 'SELECT * FROM audit_logs WHERE 1=1'
            params = []
            
            if resource_type:
                query += ' AND resource_type = ?'
                params.append(resource_type)
            
            if resource_id:
                query += ' AND resource_id = ?'
                params.append(resource_id)
            
            if action:
                query += ' AND action = ?'
                params.append(action)
            
            # Get total count
            count_query = query.replace('SELECT *', 'SELECT COUNT(*)')
            cursor.execute(count_query, params)
            total = cursor.fetchone()[0]
            
            # Get paginated results
            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            records = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            
            return records, total
        
        except Exception as e:
            logger.error(f"Error retrieving audit history: {e}")
            raise
    
    def get_bulletin_delivery_audit(self, bulletin_id: int) -> Dict[str, Any]:
        """Get comprehensive audit trail for bulletin delivery"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get all delivery-related audit entries
            cursor.execute('''
                SELECT * FROM audit_logs
                WHERE resource_type = 'bulletin' AND resource_id = ?
                AND action IN ('BULLETIN_QUEUED', 'EMAIL_SENT', 'EMAIL_FAILED', 
                               'RETRY_ATTEMPTED', 'BULLETIN_SENT', 'BULLETIN_FAILED')
                ORDER BY created_at ASC
            ''', (bulletin_id,))
            
            entries = [dict(row) for row in cursor.fetchall()]
            
            # Calculate delivery statistics
            total_sent = len([e for e in entries if e['action'] == 'EMAIL_SENT'])
            total_failed = len([e for e in entries if e['action'] == 'EMAIL_FAILED'])
            total_retries = len([e for e in entries if e['action'] == 'RETRY_ATTEMPTED'])
            
            # Get regions involved
            regions = set()
            for entry in entries:
                if entry['region']:
                    regions.add(entry['region'])
            
            conn.close()
            
            return {
                'bulletin_id': bulletin_id,
                'audit_entries': entries,
                'statistics': {
                    'total_sent': total_sent,
                    'total_failed': total_failed,
                    'total_retries': total_retries,
                    'regions_affected': list(regions),
                    'total_recipients': sum([e['recipient_count'] or 0 for e in entries])
                }
            }
        
        except Exception as e:
            logger.error(f"Error retrieving bulletin delivery audit: {e}")
            raise
    
    def export_audit_report(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        resource_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export audit report for compliance
        
        Args:
            start_date: ISO format start date
            end_date: ISO format end date
            resource_type: Filter by resource type
        
        Returns:
            Audit report with summary and entries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM audit_logs WHERE 1=1'
            params = []
            
            if start_date:
                query += ' AND created_at >= ?'
                params.append(start_date)
            
            if end_date:
                query += ' AND created_at <= ?'
                params.append(end_date)
            
            if resource_type:
                query += ' AND resource_type = ?'
                params.append(resource_type)
            
            query += ' ORDER BY created_at DESC'
            
            cursor.execute(query, params)
            entries = [dict(row) for row in cursor.fetchall()]
            
            # Calculate summary statistics
            by_action = {}
            by_status = {'SUCCESS': 0, 'FAILURE': 0, 'PARTIAL': 0}
            total_recipients = 0
            
            for entry in entries:
                # Count by action
                action = entry['action']
                by_action[action] = by_action.get(action, 0) + 1
                
                # Count by status
                status = entry['status']
                by_status[status] = by_status.get(status, 0) + 1
                
                # Sum recipients
                if entry['recipient_count']:
                    total_recipients += entry['recipient_count']
            
            conn.close()
            
            return {
                'export_date': datetime.now().isoformat(),
                'filters': {
                    'start_date': start_date,
                    'end_date': end_date,
                    'resource_type': resource_type
                },
                'summary': {
                    'total_entries': len(entries),
                    'by_action': by_action,
                    'by_status': by_status,
                    'total_recipients_affected': total_recipients
                },
                'entries': entries
            }
        
        except Exception as e:
            logger.error(f"Error exporting audit report: {e}")
            raise
