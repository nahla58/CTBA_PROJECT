"""
Analytics Service - KPIs and dashboards for CTBA Platform
"""
import logging
import sqlite3
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from database import get_db_connection

logger = logging.getLogger(__name__)


class AnalyticsService:
    """Service for generating analytics, KPIs, and dashboard data"""
    
    @staticmethod
    def get_analyst_performance(
        analyst_username: Optional[str] = None,
        days: int = 30
    ) -> Dict:
        """
        Get analyst performance metrics
        
        - CVE throughput (accepted/rejected decisions)
        - Processing times
        - Workload distribution
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Calculate date range
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # If specific analyst, filter by them
            where_clause = ""
            params = []
            
            if analyst_username:
                where_clause = "WHERE reviewed_by = ?"
                params.append(analyst_username)
            
            # Get CVE decisions by analyst
            query = f'''
                SELECT 
                    reviewed_by,
                    decision,
                    COUNT(*) as count
                FROM cves
                {where_clause}
                GROUP BY reviewed_by, decision
            '''
            
            cursor.execute(query, params)
            decisions = cursor.fetchall()
            
            # Aggregate by analyst
            analyst_stats = {}
            
            for reviewed_by, decision, count in decisions:
                if not reviewed_by:
                    continue
                
                if reviewed_by not in analyst_stats:
                    analyst_stats[reviewed_by] = {
                        'analyst': reviewed_by,
                        'accepted': 0,
                        'rejected': 0,
                        'pending': 0,
                        'total': 0
                    }
                
                if decision == 'ACCEPTED':
                    analyst_stats[reviewed_by]['accepted'] = count
                elif decision == 'REJECTED':
                    analyst_stats[reviewed_by]['rejected'] = count
                elif decision == 'PENDING':
                    analyst_stats[reviewed_by]['pending'] = count
                
                analyst_stats[reviewed_by]['total'] += count
            
            # Get action history counts
            cursor.execute('''
                SELECT analyst_username, action_type, COUNT(*) as count
                FROM action_history
                GROUP BY analyst_username, action_type
            ''')
            
            actions = cursor.fetchall()
            
            for analyst, action_type, count in actions:
                if analyst not in analyst_stats:
                    analyst_stats[analyst] = {
                        'analyst': analyst,
                        'accepted': 0,
                        'rejected': 0,
                        'pending': 0,
                        'total': 0,
                        'actions': {}
                    }
                
                if 'actions' not in analyst_stats[analyst]:
                    analyst_stats[analyst]['actions'] = {}
                
                analyst_stats[analyst]['actions'][action_type] = count
            
            # Calculate throughput (CVEs per day)
            for analyst in analyst_stats:
                total = analyst_stats[analyst]['total']
                analyst_stats[analyst]['throughput_per_day'] = round(total / days, 2)
            
            return {
                'period_days': days,
                'analysts': list(analyst_stats.values())
            }
        
        except Exception as e:
            logger.error(f"Error getting analyst performance: {e}")
            raise
    
    @staticmethod
    def get_operational_dashboard() -> Dict:
        """
        Get operational dashboard metrics
        
        - CVE volumes by source
        - CVE volumes by severity
        - Processing status distribution
        - Bulletin statistics
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # CVE counts by source
            cursor.execute('''
                SELECT source, COUNT(*) as count
                FROM cves
                GROUP BY source
            ''')
            
            cve_by_source = {}
            for source, count in cursor.fetchall():
                cve_by_source[source] = count
            
            # CVE counts by severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM cves
                GROUP BY severity
            ''')
            
            cve_by_severity = {}
            for severity, count in cursor.fetchall():
                cve_by_severity[severity] = count
            
            # CVE counts by decision status
            cursor.execute('''
                SELECT decision, COUNT(*) as count
                FROM cves
                GROUP BY decision
            ''')
            
            cve_by_decision = {}
            for decision, count in cursor.fetchall():
                cve_by_decision[decision] = count
            
            # Bulletin statistics
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM bulletins
                GROUP BY status
            ''')
            
            bulletin_by_status = {}
            for status, count in cursor.fetchall():
                bulletin_by_status[status] = count
            
            # Recent CVE ingestion trends (last 7 days)
            cursor.execute('''
                SELECT DATE(published_date) as date, COUNT(*) as count
                FROM cves
                WHERE published_date >= date('now', '-7 days')
                GROUP BY DATE(published_date)
                ORDER BY date DESC
            ''')
            
            ingestion_trend = []
            for date, count in cursor.fetchall():
                ingestion_trend.append({
                    'date': date,
                    'count': count
                })
            
            return {
                'cve_by_source': cve_by_source,
                'cve_by_severity': cve_by_severity,
                'cve_by_decision': cve_by_decision,
                'bulletin_by_status': bulletin_by_status,
                'ingestion_trend_7days': ingestion_trend,
                'total_cves': sum(cve_by_source.values()),
                'total_bulletins': sum(bulletin_by_status.values())
            }
        
        except Exception as e:
            logger.error(f"Error getting operational dashboard: {e}")
            raise
    
    @staticmethod
    def get_bulletin_timelines() -> Dict:
        """
        Get bulletin timeline metrics
        
        - Average time from creation to sending
        - Reminder cycle statistics
        - Bulletins awaiting action
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get all bulletins with timestamps
            cursor.execute('''
                SELECT 
                    id,
                    title,
                    status,
                    created_at,
                    sent_at,
                    last_reminder
                FROM bulletins
                ORDER BY created_at DESC
            ''')
            
            bulletins = cursor.fetchall()
            
            # Calculate timeline metrics
            total_bulletins = len(bulletins)
            draft_bulletins = 0
            sent_bulletins = 0
            closed_bulletins = 0
            
            avg_creation_to_send_hours = []
            
            bulletins_awaiting_reminder = 0
            bulletins_in_escalation = 0
            
            now = datetime.utcnow()
            
            for bulletin in bulletins:
                bulletin_id, title, status, created_at, sent_at, last_reminder = bulletin
                
                if status == 'DRAFT':
                    draft_bulletins += 1
                elif status == 'SENT':
                    sent_bulletins += 1
                elif status == 'NOT_PROCESSED':
                    closed_bulletins += 1
                
                # Calculate creation to send time
                if created_at and sent_at:
                    try:
                        created = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
                        sent = datetime.strptime(sent_at, '%Y-%m-%d %H:%M:%S')
                        hours = (sent - created).total_seconds() / 3600
                        avg_creation_to_send_hours.append(hours)
                    except:
                        pass
                
                # Check if awaiting reminders
                if status == 'SENT' and sent_at:
                    try:
                        sent = datetime.strptime(sent_at, '%Y-%m-%d %H:%M:%S')
                        days_since_sent = (now - sent).days
                        
                        if days_since_sent >= 30 and last_reminder < 3:
                            bulletins_in_escalation += 1
                        elif days_since_sent >= 7 and last_reminder < 1:
                            bulletins_awaiting_reminder += 1
                    except:
                        pass
            
            avg_hours = sum(avg_creation_to_send_hours) / len(avg_creation_to_send_hours) if avg_creation_to_send_hours else 0
            
            return {
                'total_bulletins': total_bulletins,
                'draft': draft_bulletins,
                'sent': sent_bulletins,
                'closed': closed_bulletins,
                'avg_creation_to_send_hours': round(avg_hours, 2),
                'bulletins_awaiting_reminder': bulletins_awaiting_reminder,
                'bulletins_in_escalation': bulletins_in_escalation
            }
        
        except Exception as e:
            logger.error(f"Error getting bulletin timelines: {e}")
            raise
    
    @staticmethod
    def get_reviewer_workload() -> Dict:
        """
        Get reviewer workload metrics
        
        - Pending CVEs by analyst assignment
        - Average processing times per analyst
        - Workload distribution
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get pending CVEs count
            cursor.execute('''
                SELECT COUNT(*) as count
                FROM cves
                WHERE decision = 'PENDING'
            ''')
            
            total_pending = cursor.fetchone()[0]
            
            # Get pending CVEs by severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM cves
                WHERE decision = 'PENDING'
                GROUP BY severity
            ''')
            
            pending_by_severity = {}
            for severity, count in cursor.fetchall():
                pending_by_severity[severity] = count
            
            # Get current workload by analyst (based on recent activity)
            cursor.execute('''
                SELECT reviewed_by, COUNT(*) as count
                FROM cves
                WHERE decision = 'PENDING'
                AND reviewed_by IS NOT NULL
                GROUP BY reviewed_by
            ''')
            
            workload_by_analyst = {}
            for analyst, count in cursor.fetchall():
                workload_by_analyst[analyst] = count
            
            # Get average processing times
            cursor.execute('''
                SELECT 
                    reviewed_by,
                    AVG(
                        CASE 
                            WHEN reviewed_at IS NOT NULL AND published_date IS NOT NULL
                            THEN (JULIANDAY(reviewed_at) - JULIANDAY(published_date)) * 24
                            ELSE NULL
                        END
                    ) as avg_processing_hours
                FROM cves
                WHERE reviewed_by IS NOT NULL
                AND reviewed_at IS NOT NULL
                AND published_date IS NOT NULL
                GROUP BY reviewed_by
            ''')
            
            avg_processing_times = {}
            for analyst, avg_hours in cursor.fetchall():
                if avg_hours:
                    avg_processing_times[analyst] = round(avg_hours, 2)
            
            return {
                'total_pending': total_pending,
                'pending_by_severity': pending_by_severity,
                'workload_by_analyst': workload_by_analyst,
                'avg_processing_hours_by_analyst': avg_processing_times
            }
        
        except Exception as e:
            logger.error(f"Error getting reviewer workload: {e}")
            raise
    
    @staticmethod
    def get_real_time_dashboard() -> Dict:
        """
        Get real-time dashboard with live metrics
        
        - Current pending CVEs
        - Today's ingestion
        - Active bulletins
        - Recent actions
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Current pending CVEs
            cursor.execute('''
                SELECT COUNT(*) FROM cves WHERE decision = 'PENDING'
            ''')
            pending_cves = cursor.fetchone()[0]
            
            # Today's ingestion
            cursor.execute('''
                SELECT COUNT(*) 
                FROM cves 
                WHERE DATE(published_date) = DATE('now')
            ''')
            today_ingestion = cursor.fetchone()[0]
            
            # Active bulletins (DRAFT + SENT)
            cursor.execute('''
                SELECT COUNT(*) 
                FROM bulletins 
                WHERE status IN ('DRAFT', 'SENT')
            ''')
            active_bulletins = cursor.fetchone()[0]
            
            # Recent actions (last 24 hours)
            cursor.execute('''
                SELECT 
                    action_type,
                    analyst_username,
                    cve_id,
                    timestamp
                FROM action_history
                WHERE timestamp >= datetime('now', '-24 hours')
                ORDER BY timestamp DESC
                LIMIT 10
            ''')
            
            recent_actions = []
            for action_type, analyst, cve_id, timestamp in cursor.fetchall():
                recent_actions.append({
                    'action': action_type,
                    'analyst': analyst,
                    'cve_id': cve_id,
                    'timestamp': timestamp
                })
            
            # CVE velocity (CVEs processed in last hour)
            cursor.execute('''
                SELECT COUNT(*)
                FROM cves
                WHERE reviewed_at >= datetime('now', '-1 hour')
            ''')
            hourly_velocity = cursor.fetchone()[0]
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'pending_cves': pending_cves,
                'today_ingestion': today_ingestion,
                'active_bulletins': active_bulletins,
                'recent_actions': recent_actions,
                'hourly_velocity': hourly_velocity
            }
        
        except Exception as e:
            logger.error(f"Error getting real-time dashboard: {e}")
            raise
