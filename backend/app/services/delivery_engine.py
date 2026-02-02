"""
Bulletin Delivery Engine - Asynchronous queue-based delivery with retry logic
"""
import json
import logging
import threading
import time
from queue import Queue
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import pytz

from app.services.email_service import EmailService, EmailTemplate
from app.services.bulletin_service import BulletinService, RegionService
from app.services.region_mailing_service import RegionMailingService

logger = logging.getLogger(__name__)


class BulletinDeliveryEngine:
    """Asynchronous delivery engine for bulletins with queue and retry logic"""
    
    def __init__(self, email_service: EmailService, max_retries: int = 3, retry_delay: int = 60):
        """
        Initialize delivery engine
        
        Args:
            email_service: EmailService instance for sending
            max_retries: Maximum retry attempts for failed sends
            retry_delay: Delay in seconds between retries
        """
        self.email_service = email_service
        self.bulletin_service = BulletinService()
        self.region_service = RegionService()
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        # Delivery queue
        self.delivery_queue = Queue()
        self.processing_thread = None
        self.is_running = False
        
        logger.info(f"BulletinDeliveryEngine initialized (max_retries={max_retries})")
    
    def queue_bulletin_send(
        self,
        bulletin_id: int,
        regions: Optional[List[str]] = None,
        test_mode: bool = False,
        cc_recipients: Optional[List[str]] = None,
        bcc_recipients: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Queue a bulletin for delivery
        
        Args:
            bulletin_id: ID of bulletin to send
            regions: Specific regions to send to (use all if None)
            test_mode: If True, don't actually send emails
            cc_recipients: Additional CC recipients
            bcc_recipients: Additional BCC recipients
        
        Returns:
            Job details with status
        """
        try:
            # Get bulletin
            bulletin = self.bulletin_service.get_bulletin_detail(bulletin_id)
            
            # Use specified regions or all bulletin regions
            send_regions = regions or bulletin['regions']
            
            # Create job
            job = {
                'job_id': f"job_{bulletin_id}_{int(time.time())}",
                'bulletin_id': bulletin_id,
                'regions': send_regions,
                'test_mode': test_mode,
                'cc_recipients': cc_recipients,
                'bcc_recipients': bcc_recipients,
                'status': 'QUEUED',
                'attempts': 0,
                'created_at': datetime.now().isoformat()
            }
            
            self.delivery_queue.put(job)
            
            logger.info(f"Queued bulletin {bulletin_id} for delivery to regions: {send_regions}")
            
            return job
        except Exception as e:
            logger.error(f"Error queuing bulletin {bulletin_id}: {e}")
            return {
                'status': 'ERROR',
                'error': str(e)
            }
    
    def process_queue(self, max_jobs: int = 10) -> Dict[str, Any]:
        """
        Process delivery queue
        
        Args:
            max_jobs: Maximum jobs to process in this batch
        
        Returns:
            Processing results
        """
        processed = 0
        succeeded = 0
        failed = 0
        retried = 0
        
        for _ in range(max_jobs):
            if self.delivery_queue.empty():
                break
            
            try:
                job = self.delivery_queue.get_nowait()
                processed += 1
                
                logger.info(f"Processing job {job['job_id']} for bulletin {job['bulletin_id']}")
                
                # Execute delivery
                success = self._execute_delivery_job(job)
                
                if success:
                    succeeded += 1
                    # Update bulletin status
                    self.bulletin_service.update_bulletin(
                        job['bulletin_id'],
                        status='SENT'
                    )
                else:
                    # Retry if not exceeded max retries
                    job['attempts'] = job.get('attempts', 0) + 1
                    
                    if job['attempts'] < self.max_retries:
                        logger.info(f"Requeuing job {job['job_id']} (attempt {job['attempts']})")
                        # Add back to queue after delay
                        time.sleep(self.retry_delay)
                        self.delivery_queue.put(job)
                        retried += 1
                    else:
                        logger.error(f"Job {job['job_id']} failed after {self.max_retries} attempts")
                        failed += 1
            
            except Exception as e:
                logger.error(f"Error processing queue item: {e}")
                failed += 1
        
        result = {
            'processed': processed,
            'succeeded': succeeded,
            'failed': failed,
            'retried': retried,
            'queue_size': self.delivery_queue.qsize()
        }
        
        logger.info(f"Queue processing complete: {result}")
        return result
    
    def _execute_delivery_job(self, job: Dict[str, Any]) -> bool:
        """
        Execute a single delivery job
        
        Returns:
            True if all sends succeeded, False otherwise
        """
        try:
            bulletin_id = job['bulletin_id']
            regions = job['regions']
            test_mode = job.get('test_mode', False)
            
            # Get bulletin details
            bulletin = self.bulletin_service.get_bulletin_detail(bulletin_id)
            
            all_succeeded = True
            
            # Send to each region
            for region_name in regions:
                try:
                    # Get region
                    regions_list = self.region_service.get_regions()
                    region = None
                    for r in regions_list:
                        if r['name'] == region_name:
                            region = r
                            break
                    
                    if not region:
                        logger.warning(f"Region {region_name} not found")
                        self.bulletin_service.log_delivery(
                            bulletin_id,
                            'FAILED',
                            region_name,
                            None,
                            f'Region {region_name} not found'
                        )
                        all_succeeded = False
                        continue
                    
                    # Get recipients
                    to_list = region.get('recipients', [])
                    if not to_list:
                        logger.warning(f"No recipients for region {region_name}")
                        all_succeeded = False
                        continue
                    
                    # Render bulletin HTML
                    html_body = self._render_bulletin_html(bulletin, region_name)
                    
                    # Send email
                    result = self.email_service.send_bulletin(
                        to_list=to_list,
                        subject=bulletin['title'],
                        html_body=html_body,
                        cc_list=job.get('cc_recipients'),
                        bcc_list=job.get('bcc_recipients'),
                        test_mode=test_mode
                    )
                    
                    # Log delivery
                    if result['status'] == 'success' or result['status'] == 'test':
                        self.bulletin_service.log_delivery(
                            bulletin_id,
                            'SENT',
                            region_name,
                            ','.join(to_list),
                            result.get('message')
                        )
                        logger.info(f"✅ Sent bulletin {bulletin_id} to {region_name}")
                    else:
                        self.bulletin_service.log_delivery(
                            bulletin_id,
                            'FAILED',
                            region_name,
                            ','.join(to_list),
                            result.get('errors', [None])[0] if result.get('errors') else 'Unknown error'
                        )
                        logger.error(f"❌ Failed to send bulletin {bulletin_id} to {region_name}")
                        all_succeeded = False
                
                except Exception as e:
                    logger.error(f"Error sending to region {region_name}: {e}")
                    self.bulletin_service.log_delivery(
                        bulletin_id,
                        'FAILED',
                        region_name,
                        None,
                        str(e)
                    )
                    all_succeeded = False
            
            return all_succeeded
        
        except Exception as e:
            logger.error(f"Error executing delivery job: {e}")
            return False
    
    def _render_bulletin_html(self, bulletin: Dict[str, Any], region: str) -> str:
        """Render bulletin HTML for email"""
        try:
            # Get grouped CVEs
            grouped_cves = bulletin.get('grouped_cves', [])
            
            # Calculate statistics
            critical_count = 0
            high_count = 0
            for group in grouped_cves:
                for cve in group.get('cves', []):
                    severity = cve.get('severity', '').lower()
                    if severity == 'critical':
                        critical_count += 1
                    elif severity == 'high':
                        high_count += 1
            
            statistics = {
                'critical_count': critical_count,
                'high_count': high_count
            }
            
            # Render HTML
            html = EmailTemplate.render_bulletin(
                title=bulletin['title'],
                region=region,
                bulletin_id=bulletin['id'],
                body=bulletin.get('body'),
                grouped_cves=grouped_cves,
                statistics=statistics
            )
            
            return html
        except Exception as e:
            logger.error(f"Error rendering bulletin HTML: {e}")
            # Return simple HTML as fallback
            return f"<html><body><h2>{bulletin['title']}</h2><p>{bulletin.get('body', '')}</p></body></html>"
    
    def start_background_processor(self, interval_seconds: int = 60) -> None:
        """Start background processing thread"""
        if self.is_running:
            logger.warning("Background processor already running")
            return
        
        self.is_running = True
        
        def processor_loop():
            logger.info(f"Background processor started (interval: {interval_seconds}s)")
            while self.is_running:
                try:
                    self.process_queue(max_jobs=10)
                    time.sleep(interval_seconds)
                except Exception as e:
                    logger.error(f"Error in background processor: {e}")
                    time.sleep(interval_seconds)
        
        self.processing_thread = threading.Thread(target=processor_loop, daemon=True)
        self.processing_thread.start()
        
        logger.info("✅ Background delivery processor started")
    
    def stop_background_processor(self) -> None:
        """Stop background processing thread"""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Background processor stopped")


class BulletinValidator:
    """Validate bulletins before sending"""
    
    @staticmethod
    def validate_for_send(bulletin_id: int) -> tuple:
        """
        Validate bulletin for sending
        
        Returns:
            (is_valid: bool, errors: List[str])
        """
        try:
            bulletin_service = BulletinService()
            region_mailing_service = RegionMailingService()
            
            bulletin = bulletin_service.get_bulletin_detail(bulletin_id)
            errors = []
            
            # Check title
            if not bulletin.get('title') or len(bulletin['title']) < 5:
                errors.append("Bulletin title is required and must be at least 5 characters")
            
            # Check regions
            if not bulletin.get('regions') or len(bulletin['regions']) == 0:
                errors.append("At least one region required")
            
            # Check recipients for each region
            for region_name in bulletin.get('regions', []):
                mailing = region_mailing_service.get_region_mailing_by_name(region_name)
                if not mailing:
                    errors.append(f"No recipients configured for region {region_name}")
                elif mailing.get_recipient_count() == 0:
                    errors.append(f"No recipients configured for region {region_name}")
            
            return len(errors) == 0, errors
        
        except Exception as e:
            logger.error(f"Error validating bulletin: {e}")
            return False, [str(e)]


class BulletinScheduler:
    """Schedule recurring bulletins (stub for future implementation)"""
    
    def __init__(self, delivery_engine: BulletinDeliveryEngine):
        """Initialize scheduler"""
        self.delivery_engine = delivery_engine
        self.schedules = {}
    
    def schedule_periodic_send(
        self,
        bulletin_id: int,
        frequency: str,  # 'daily', 'weekly', 'monthly'
        regions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Schedule a bulletin for periodic delivery"""
        # TODO: Implement scheduling logic
        logger.warning("Bulletin scheduling not yet implemented")
        return {
            'status': 'not_implemented',
            'message': 'Scheduling coming soon'
        }
