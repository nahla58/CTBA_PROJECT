"""
Bulletin Reminder Service - Automatic reminders and escalation for bulletins
"""
import logging
import sqlite3
import schedule
import time
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from database import get_db_connection

logger = logging.getLogger(__name__)


class BulletinReminderService:
    """
    Service for managing automatic bulletin reminders
    
    - Reminder 1: 7 days after sending
    - Reminder 2: 14 days after sending
    - Escalation: 30 days after sending
    """
    
    def __init__(self):
        self.running = False
        self.thread = None
    
    def start(self, interval_seconds: int = 3600):
        """Start the reminder scheduler (runs every hour by default)"""
        if self.running:
            logger.warning("⚠️ Reminder service already running")
            return
        
        self.running = True
        
        # Schedule the reminder check
        schedule.every(interval_seconds).seconds.do(self.check_and_send_reminders)
        
        # Start scheduler in background thread
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()
        
        logger.info(f"✅ Bulletin reminder service started (checks every {interval_seconds}s)")
    
    def stop(self):
        """Stop the reminder scheduler"""
        self.running = False
        schedule.clear()
        logger.info("⏹️ Bulletin reminder service stopped")
    
    def _run_scheduler(self):
        """Run the scheduler loop in background"""
        while self.running:
            schedule.run_pending()
            time.sleep(1)
    
    def check_and_send_reminders(self):
        """Check all sent bulletins and send reminders if needed"""
        try:
            logger.info("🔍 Checking bulletins for reminders...")
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get all SENT bulletins that aren't closed
            cursor.execute('''
                SELECT id, title, regions, sent_at, 
                       reminder_7_sent_at, reminder_14_sent_at, escalation_30_sent_at
                FROM bulletins
                WHERE status = 'SENT'
                AND sent_at IS NOT NULL
                AND closed_at IS NULL
            ''')
            
            bulletins = cursor.fetchall()
            
            now = datetime.utcnow()
            
            reminders_sent = 0
            
            for bulletin in bulletins:
                bulletin_id = bulletin[0]
                title = bulletin[1]
                regions_json = bulletin[2]
                sent_at_str = bulletin[3]
                reminder_7_sent = bulletin[4]
                reminder_14_sent = bulletin[5]
                escalation_30_sent = bulletin[6]
                
                # Parse sent_at timestamp
                try:
                    sent_at = datetime.strptime(sent_at_str, '%Y-%m-%d %H:%M:%S')
                except:
                    # Try alternate format
                    try:
                        sent_at = datetime.fromisoformat(sent_at_str.replace('Z', '+00:00'))
                    except:
                        logger.warning(f"⚠️ Could not parse sent_at for bulletin {bulletin_id}")
                        continue
                
                days_since_sent = (now - sent_at).days
                
                # Determine which reminder to send
                reminder_level = None
                
                if days_since_sent >= 30 and not escalation_30_sent:
                    reminder_level = 3  # Escalation
                elif days_since_sent >= 14 and not reminder_14_sent:
                    reminder_level = 2  # Reminder 2
                elif days_since_sent >= 7 and not reminder_7_sent:
                    reminder_level = 1  # Reminder 1
                
                if reminder_level:
                    # Send reminder
                    success = self._send_reminder(
                        bulletin_id=bulletin_id,
                        title=title,
                        regions_json=regions_json,
                        reminder_level=reminder_level,
                        days_since_sent=days_since_sent
                    )
                    
                    if success:
                        # Update specific reminder timestamp in database
                        if reminder_level == 1:
                            cursor.execute('''
                                UPDATE bulletins
                                SET reminder_7_sent_at = ?
                                WHERE id = ?
                            ''', (now.isoformat(), bulletin_id))
                        elif reminder_level == 2:
                            cursor.execute('''
                                UPDATE bulletins
                                SET reminder_14_sent_at = ?
                                WHERE id = ?
                            ''', (now.isoformat(), bulletin_id))
                        elif reminder_level == 3:
                            cursor.execute('''
                                UPDATE bulletins
                                SET escalation_30_sent_at = ?
                                WHERE id = ?
                            ''', (now.isoformat(), bulletin_id))
                        
                        conn.commit()
                        reminders_sent += 1
            
            if reminders_sent > 0:
                logger.info(f"✅ Sent {reminders_sent} bulletin reminders")
            else:
                logger.debug("✓ No reminders needed at this time")
        
        except Exception as e:
            logger.error(f"❌ Error checking bulletins for reminders: {e}")
    
    def _send_reminder(
        self,
        bulletin_id: int,
        title: str,
        regions_json: str,
        reminder_level: int,
        days_since_sent: int
    ) -> bool:
        """Send a reminder email for a bulletin"""
        try:
            import json
            from app.services.region_mailing_service import RegionMailingService
            from services.email_service import EmailService
            from services.bulletin_service import BulletinService
            
            # Parse regions
            regions = json.loads(regions_json) if isinstance(regions_json, str) else regions_json
            
            # Determine reminder type
            if reminder_level == 1:
                reminder_type = "REMINDER_1"
                subject_prefix = "[Reminder 1]"
            elif reminder_level == 2:
                reminder_type = "REMINDER_2"
                subject_prefix = "[Reminder 2]"
            else:
                reminder_type = "ESCALATION"
                subject_prefix = "[ESCALATION]"
            
            subject = f"{subject_prefix} {title}"
            
            body = f"""
            <html>
            <body>
                <h2>Bulletin Reminder</h2>
                <p>This is a reminder regarding the bulletin: <strong>{title}</strong></p>
                <p>Original bulletin was sent {days_since_sent} days ago.</p>
                <p>Please review and take necessary action.</p>
                
                <hr>
                
                <p style="color: #666; font-size: 12px;">
                    Bulletin ID: {bulletin_id}<br>
                    Reminder Level: {reminder_level}<br>
                    Days since sent: {days_since_sent}
                </p>
            </body>
            </html>
            """
            
            email_service = EmailService()
            mailing_service = RegionMailingService()
            
            # Send to each region
            for region_name in regions:
                try:
                    # Get region ID
                    conn = sqlite3.connect('ctba_platform.db')
                    cursor = conn.cursor()
                    cursor.execute('SELECT id FROM regions WHERE name = ?', (region_name,))
                    region_row = cursor.fetchone()
                    conn.close()
                    
                    if not region_row:
                        continue
                    
                    region_id = region_row[0]
                    
                    # Get mailing lists
                    mailing_lists = mailing_service.get_region_mailing_lists(region_id)
                    
                    if not mailing_lists:
                        continue
                    
                    # Send email
                    to_recipients = mailing_lists.to_recipients
                    cc_recipients = mailing_lists.cc_recipients if mailing_lists.cc_recipients else []
                    
                    email_service.send_email(
                        to=to_recipients,
                        cc=cc_recipients,
                        bcc=[],
                        subject=subject,
                        html_body=body,
                        text_body=f"Bulletin Reminder: {title} (sent {days_since_sent} days ago)"
                    )
                    
                    # Log reminder
                    BulletinService.log_delivery(
                        bulletin_id=bulletin_id,
                        action=reminder_type,
                        region=region_name,
                        recipients=', '.join(to_recipients),
                        message=f"Reminder sent after {days_since_sent} days"
                    )
                    
                    logger.info(f"📧 {reminder_type} sent for bulletin #{bulletin_id} to {region_name}")
                
                except Exception as e:
                    logger.error(f"❌ Error sending reminder to {region_name}: {e}")
            
            return True
        
        except Exception as e:
            logger.error(f"❌ Error sending reminder for bulletin {bulletin_id}: {e}")
            return False
    
    def manually_close_bulletin(self, bulletin_id: int, closed_by: str) -> bool:
        """Manually close a bulletin (stops reminders)"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Update status to NOT_PROCESSED (closed)
            cursor.execute('''
                UPDATE bulletins
                SET status = 'NOT_PROCESSED'
                WHERE id = ?
            ''', (bulletin_id,))
            
            conn.commit()
            
            # Log closure
            from services.bulletin_service import BulletinService
            BulletinService.log_delivery(
                bulletin_id=bulletin_id,
                action='MANUALLY_CLOSED',
                region='ALL',
                recipients='',
                message=f"Bulletin manually closed by {closed_by}"
            )
            
            logger.info(f"✅ Bulletin #{bulletin_id} manually closed by {closed_by}")
            
            return True
        
        except Exception as e:
            logger.error(f"❌ Error closing bulletin {bulletin_id}: {e}")
            return False
    
    def get_reminder_statistics(self) -> Dict:
        """Get statistics about bulletins and reminders"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Count bulletins by status
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM bulletins
                GROUP BY status
            ''')
            
            status_counts = {}
            for row in cursor.fetchall():
                status_counts[row[0]] = row[1]
            
            # Count bulletins awaiting reminders
            now = datetime.utcnow()
            
            cursor.execute('''
                SELECT id, sent_at, last_reminder
                FROM bulletins
                WHERE status = 'SENT'
                AND sent_at IS NOT NULL
            ''')
            
            bulletins = cursor.fetchall()
            
            awaiting_reminder_1 = 0
            awaiting_reminder_2 = 0
            awaiting_escalation = 0
            
            for bulletin in bulletins:
                sent_at_str = bulletin[1]
                last_reminder = bulletin[2]
                
                try:
                    sent_at = datetime.strptime(sent_at_str, '%Y-%m-%d %H:%M:%S')
                except:
                    try:
                        sent_at = datetime.fromisoformat(sent_at_str.replace('Z', '+00:00'))
                    except:
                        continue
                
                days_since_sent = (now - sent_at).days
                
                if days_since_sent >= 30 and last_reminder < 3:
                    awaiting_escalation += 1
                elif days_since_sent >= 14 and last_reminder < 2:
                    awaiting_reminder_2 += 1
                elif days_since_sent >= 7 and last_reminder < 1:
                    awaiting_reminder_1 += 1
            
            return {
                'status_counts': status_counts,
                'awaiting_reminder_1': awaiting_reminder_1,
                'awaiting_reminder_2': awaiting_reminder_2,
                'awaiting_escalation': awaiting_escalation,
                'total_sent': status_counts.get('SENT', 0)
            }
        
        except Exception as e:
            logger.error(f"❌ Error getting reminder statistics: {e}")
            return {}


# Global instance
reminder_service = BulletinReminderService()
