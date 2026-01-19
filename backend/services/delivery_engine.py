"""
Bulletin Delivery Engine - Queue management, sending, and async delivery
"""
import logging
import json
from typing import List, Dict, Optional
from datetime import datetime
from queue import Queue
from threading import Thread
import time

from services.bulletin_service import BulletinService, RegionService
from services.email_service import EmailService, EmailTemplate
from database import get_db_connection

logger = logging.getLogger(__name__)


class BulletinDeliveryEngine:
    """Manages bulletin sending to regions with queuing and retry logic"""
    
    def __init__(self, email_service: EmailService = None):
        """Initialize delivery engine"""
        self.email_service = email_service or EmailService()
        self.delivery_queue = Queue()
        self.max_retries = 3
        self.retry_delay = 60  # seconds
        
        logger.info("✅ BulletinDeliveryEngine initialized")
    
    def queue_bulletin_send(
        self,
        bulletin_id: int,
        regions: Optional[List[str]] = None,
        test_mode: bool = False
    ) -> Dict:
        """
        Queue bulletin for sending
        
        Args:
            bulletin_id: Bulletin to send
            regions: Specific regions to send to (None = all)
            test_mode: If True, don't actually send
        
        Returns:
            Queue job info
        """
        try:
            # Get bulletin details
            bulletin = BulletinService.get_bulletin_detail(bulletin_id)
            
            if not bulletin:
                raise ValueError(f"Bulletin {bulletin_id} not found")
            
            # Determine target regions
            target_regions = regions or bulletin['regions']
            
            if not target_regions:
                raise ValueError("No regions specified for sending")
            
            # Create delivery job
            job = {
                'bulletin_id': bulletin_id,
                'regions': target_regions,
                'test_mode': test_mode,
                'created_at': datetime.now().isoformat(),
                'status': 'QUEUED',
                'retries': 0
            }
            
            self.delivery_queue.put(job)
            
            logger.info(f"✅ Bulletin #{bulletin_id} queued for delivery to {len(target_regions)} regions")
            
            return job
        
        except Exception as e:
            logger.error(f"Error queuing bulletin: {e}")
            raise
    
    def process_queue(self, max_jobs: int = 10):
        """
        Process delivery queue
        
        Args:
            max_jobs: Maximum jobs to process in this batch
        """
        logger.info(f"📬 Processing delivery queue ({self.delivery_queue.qsize()} jobs pending)")
        
        processed = 0
        
        while not self.delivery_queue.empty() and processed < max_jobs:
            try:
                job = self.delivery_queue.get_nowait()
                
                success = self._execute_delivery_job(job)
                
                if not success and job['retries'] < self.max_retries:
                    # Re-queue failed job
                    job['retries'] += 1
                    job['status'] = 'RETRY'
                    self.delivery_queue.put(job)
                    logger.warning(f"⚠️ Bulletin #{job['bulletin_id']} re-queued (retry {job['retries']})")
                
                processed += 1
                
            except Exception as e:
                logger.error(f"Error processing queue: {e}")
    
    def _execute_delivery_job(self, job: Dict) -> bool:
        """
        Execute a single delivery job
        
        Returns:
            True if successful, False if failed
        """
        bulletin_id = job['bulletin_id']
        regions = job['regions']
        test_mode = job.get('test_mode', False)
        
        try:
            logger.info(f"📧 Processing bulletin #{bulletin_id} for {len(regions)} regions")
            
            bulletin = BulletinService.get_bulletin_detail(bulletin_id)
            
            if not bulletin:
                logger.error(f"Bulletin #{bulletin_id} not found")
                return False
            
            all_regions = RegionService.get_regions()
            region_map = {r['name']: r for r in all_regions}
            
            total_sent = 0
            total_failed = 0
            
            for region_name in regions:
                region = region_map.get(region_name)
                
                if not region:
                    logger.warning(f"Region '{region_name}' not found")
                    total_failed += 1
                    continue
                
                # Parse recipients
                recipients = [e.strip() for e in region['recipients']]
                
                if not recipients:
                    logger.warning(f"No recipients for region {region_name}")
                    total_failed += 1
                    continue
                
                # Render bulletin to HTML
                html_content = self._render_bulletin_html(bulletin, region_name)
                
                # Send email
                result = self.email_service.send_bulletin(
                    to_emails=recipients,
                    subject=f"[{region_name}] {bulletin['title']}",
                    html_content=html_content,
                    test_mode=test_mode
                )
                
                # Log delivery
                BulletinService.log_delivery(
                    bulletin_id=bulletin_id,
                    action='SENT' if result['status'] == 'success' else 'FAILED',
                    region=region_name,
                    recipients=','.join(recipients),
                    message=result.get('errors', [None])[0] if result.get('errors') else 'Success'
                )
                
                if result['status'] == 'success' or result['status'] == 'test':
                    total_sent += result['sent_count']
                    logger.info(f"✅ Sent to {region_name}: {result['sent_count']} recipients")
                else:
                    total_failed += 1
                    logger.error(f"❌ Failed to send to {region_name}: {result.get('errors')}")
            
            # Update bulletin status
            if total_failed == 0:
                BulletinService.update_bulletin(bulletin_id, status='SENT')
                
                # Update sent timestamp
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE bulletins SET sent_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (bulletin_id,)
                )
                conn.commit()
            
            logger.info(f"✅ Bulletin #{bulletin_id} delivery complete: {total_sent} sent, {total_failed} failed")
            
            return total_failed == 0
        
        except Exception as e:
            logger.error(f"Error executing delivery job: {e}")
            return False
    
    def _render_bulletin_html(self, bulletin: Dict, region: str) -> str:
        """Render bulletin to HTML format"""
        try:
            # Count severity levels
            critical_count = 0
            high_count = 0
            
            for cve in bulletin.get('cves', []):
                if cve.get('severity') == 'CRITICAL':
                    critical_count += 1
                elif cve.get('severity') == 'HIGH':
                    high_count += 1
            
            html = EmailTemplate.render_bulletin(
                title=bulletin['title'],
                region=region,
                bulletin_id=bulletin['id'],
                body=bulletin.get('body'),
                grouped_cves=bulletin.get('grouped_cves', []),
                total_cves=len(bulletin.get('cves', [])),
                critical_count=critical_count,
                high_count=high_count,
                footer_message=f"Bulletin ID: {bulletin['id']} | Sent: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            return html
        
        except Exception as e:
            logger.error(f"Error rendering bulletin HTML: {e}")
            # Return fallback HTML
            return f"""
            <html>
            <body>
            <h1>{bulletin['title']}</h1>
            <p>{bulletin.get('body', 'No content')}</p>
            <p>Region: {region}</p>
            <p>Bulletin ID: {bulletin['id']}</p>
            </body>
            </html>
            """
    
    def start_background_processor(self, interval_seconds: int = 60):
        """
        Start background thread to process delivery queue
        
        Args:
            interval_seconds: How often to check queue
        """
        def processor():
            logger.info(f"📬 Background delivery processor started (interval: {interval_seconds}s)")
            
            while True:
                try:
                    self.process_queue(max_jobs=5)
                    time.sleep(interval_seconds)
                
                except Exception as e:
                    logger.error(f"Background processor error: {e}")
                    time.sleep(interval_seconds)
        
        thread = Thread(target=processor, daemon=True)
        thread.start()
        
        logger.info("✅ Background delivery processor thread started")


class BulletinScheduler:
    """Schedule recurring bulletin sends (future extension)"""
    
    @staticmethod
    def schedule_periodic_send(
        bulletin_id: int,
        schedule: str,  # "daily", "weekly", "monthly"
        regions: List[str],
        delivery_engine: BulletinDeliveryEngine
    ) -> Dict:
        """
        Schedule bulletin for recurring sends
        
        Args:
            bulletin_id: Bulletin to schedule
            schedule: Recurrence pattern
            regions: Target regions
            delivery_engine: Delivery engine instance
        
        Returns:
            Schedule info
        """
        logger.info(f"📅 Scheduling bulletin #{bulletin_id} for {schedule} sends to {regions}")
        
        # TODO: Implement with APScheduler or similar
        
        return {
            'bulletin_id': bulletin_id,
            'schedule': schedule,
            'regions': regions,
            'status': 'SCHEDULED'
        }


class BulletinValidator:
    """Validate bulletins before sending"""
    
    @staticmethod
    def validate_for_send(bulletin_id: int) -> tuple[bool, List[str]]:
        """
        Validate bulletin is ready to send
        
        Args:
            bulletin_id: Bulletin to validate
        
        Returns:
            (is_valid, errors)
        """
        errors = []
        
        try:
            bulletin = BulletinService.get_bulletin_detail(bulletin_id)
            
            if not bulletin:
                errors.append("Bulletin not found")
                return False, errors
            
            # Check title
            if not bulletin.get('title') or len(bulletin['title']) < 5:
                errors.append("Title must be at least 5 characters")
            
            # Check regions
            if not bulletin.get('regions'):
                errors.append("At least one region must be selected")
            
            # Check recipients exist for selected regions
            all_regions = RegionService.get_regions()
            region_map = {r['name']: r for r in all_regions}
            
            for region_name in bulletin.get('regions', []):
                region = region_map.get(region_name)
                
                if not region:
                    errors.append(f"Region '{region_name}' not found")
                elif not region.get('recipients'):
                    errors.append(f"No recipients configured for region '{region_name}'")
            
            return len(errors) == 0, errors
        
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            return False, errors
