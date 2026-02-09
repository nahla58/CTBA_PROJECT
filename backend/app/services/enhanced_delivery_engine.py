"""
Enhanced Bulletin Delivery Engine - Queue management, sending, and async delivery with audit logging
Integrates with region mailing service and audit logging for full traceability
"""
import logging
import json
import time
import sqlite3
from typing import List, Dict, Optional
from datetime import datetime
from queue import Queue
from threading import Thread

from app.services.bulletin_service import BulletinService, RegionService
from services.email_service import EmailService, EmailTemplate
from app.services.region_mailing_service import RegionMailingService
from app.services.audit_logger import AuditLogger, AuditActionType

logger = logging.getLogger(__name__)


class EnhancedBulletinDeliveryEngine:
    """
    Enhanced delivery engine with:
    - Region-aware mailing list resolution
    - To/Cc/Bcc support
    - Comprehensive audit logging
    - Retry logic with exponential backoff
    - Test mode support
    """
    
    def __init__(
        self,
        email_service: EmailService = None,
        mailing_service: RegionMailingService = None,
        audit_logger: AuditLogger = None
    ):
        """Initialize enhanced delivery engine"""
        self.email_service = email_service or EmailService()
        self.mailing_service = mailing_service or RegionMailingService()
        self.audit_logger = audit_logger or AuditLogger()
        
        self.delivery_queue = Queue()
        self.max_retries = 3
        self.retry_delay = 60  # seconds
        
        logger.info("✅ EnhancedBulletinDeliveryEngine initialized with audit logging")
    
    def queue_bulletin_send(
        self,
        bulletin_id: int,
        regions: Optional[List[str]] = None,
        test_mode: bool = False,
        cc_recipients: Optional[List[str]] = None,
        bcc_recipients: Optional[List[str]] = None,
        actor: str = 'SYSTEM'
    ) -> Dict:
        """
        Queue bulletin for sending with audit logging
        
        Args:
            bulletin_id: Bulletin to send
            regions: Specific regions to send to (None = all)
            test_mode: If True, don't actually send (log only)
            cc_recipients: Override Cc recipients for all regions
            bcc_recipients: Override Bcc recipients for all regions
            actor: User/system queuing the send
        
        Returns:
            Queue job info with job_id
        """
        try:
            # Get bulletin details
            bulletin = BulletinService().get_bulletin_detail(bulletin_id)
            
            if not bulletin:
                self.audit_logger.log_action(
                    action=AuditActionType.BULLETIN_QUEUED,
                    resource_type='bulletin',
                    resource_id=bulletin_id,
                    actor=actor,
                    status='FAILURE',
                    error_message=f'Bulletin not found'
                )
                raise ValueError(f"Bulletin {bulletin_id} not found")
            
            # Determine target regions
            target_regions = regions or bulletin.get('regions', [])
            
            if not target_regions:
                self.audit_logger.log_action(
                    action=AuditActionType.BULLETIN_QUEUED,
                    resource_type='bulletin',
                    resource_id=bulletin_id,
                    actor=actor,
                    status='FAILURE',
                    error_message='No regions specified'
                )
                raise ValueError("No regions specified for sending")
            
            # Create delivery job
            job = {
                'job_id': f"{bulletin_id}_{int(time.time())}",
                'bulletin_id': bulletin_id,
                'regions': target_regions,
                'test_mode': test_mode,
                'cc_recipients': cc_recipients,
                'bcc_recipients': bcc_recipients,
                'actor': actor,
                'created_at': datetime.now().isoformat(),
                'status': 'QUEUED',
                'retries': 0
            }
            
            self.delivery_queue.put(job)
            
            # Log to audit
            self.audit_logger.log_action(
                action=AuditActionType.BULLETIN_QUEUED,
                resource_type='bulletin',
                resource_id=bulletin_id,
                actor=actor,
                details=json.dumps({'regions': target_regions, 'test_mode': test_mode}),
                status='SUCCESS'
            )
            
            logger.info(
                f"✅ Bulletin #{bulletin_id} queued for delivery (Job: {job['job_id']}) "
                f"to {len(target_regions)} region(s)"
            )
            
            return job
        
        except Exception as e:
            logger.error(f"Error queuing bulletin: {e}")
            raise
    
    def process_queue(self, max_jobs: int = 10) -> Dict:
        """
        Process delivery queue
        
        Args:
            max_jobs: Maximum jobs to process in this batch
        
        Returns:
            Processing summary
        """
        logger.info(f"📬 Processing delivery queue ({self.delivery_queue.qsize()} jobs pending)")
        
        processed = 0
        successful = 0
        failed = 0
        
        while not self.delivery_queue.empty() and processed < max_jobs:
            try:
                job = self.delivery_queue.get_nowait()
                
                success = self._execute_delivery_job(job)
                
                if success:
                    successful += 1
                else:
                    failed += 1
                
                # Handle retries
                if not success and job['retries'] < self.max_retries:
                    job['retries'] += 1
                    job['status'] = 'RETRY'
                    self.delivery_queue.put(job)
                    logger.warning(
                        f"⚠️ Bulletin #{job['bulletin_id']} re-queued "
                        f"(retry {job['retries']}/{self.max_retries})"
                    )
                
                processed += 1
                
            except Exception as e:
                logger.error(f"Error processing queue: {e}")
                failed += 1
        
        return {
            'processed': processed,
            'successful': successful,
            'failed': failed,
            'remaining': self.delivery_queue.qsize()
        }
    
    def _execute_delivery_job(self, job: Dict) -> bool:
        """
        Execute a single delivery job with full audit logging
        
        Returns:
            True if successful, False if failed
        """
        bulletin_id = job['bulletin_id']
        regions = job['regions']
        test_mode = job.get('test_mode', False)
        job_id = job.get('job_id')
        actor = job.get('actor', 'SYSTEM')
        
        start_time = time.time()
        total_sent = 0
        total_failed = 0
        failed_regions = []
        
        try:
            logger.info(f"📧 Processing bulletin #{bulletin_id} (Job: {job_id}) for {len(regions)} regions")
            
            bulletin = BulletinService().get_bulletin_detail(bulletin_id)
            
            if not bulletin:
                logger.error(f"Bulletin #{bulletin_id} not found")
                
                # Log failure
                duration_ms = int((time.time() - start_time) * 1000)
                self.audit_logger.log_action(
                    action=AuditActionType.BULLETIN_FAILED,
                    resource_type='bulletin',
                    resource_id=bulletin_id,
                    actor=actor,
                    status='FAILURE',
                    error_message='Bulletin not found',
                    duration_ms=duration_ms
                )
                
                return False
            
            # For each target region, resolve recipients and send
            for region_name in regions:
                try:
                    # Resolve mailing lists for region
                    mailing_list = self.mailing_service.get_region_mailing_by_name(region_name)
                    
                    if not mailing_list:
                        logger.warning(f"No mailing list found for region: {region_name}")
                        total_failed += 1
                        failed_regions.append((region_name, 'No mailing list'))
                        continue
                    
                    # Apply overrides if provided
                    to_emails = job.get('cc_recipients') or mailing_list.to_recipients
                    cc_emails = job.get('cc_recipients') or mailing_list.cc_recipients
                    bcc_emails = job.get('bcc_recipients') or mailing_list.bcc_recipients
                    
                    # Render bulletin to HTML
                    html_content = self._render_bulletin_html(bulletin, region_name)
                    
                    # Send email
                    send_start = time.time()
                    result = self.email_service.send_bulletin(
                        to_emails=to_emails,
                        subject=f"[{region_name}] Security Bulletin: {bulletin['title']}",
                        html_content=html_content,
                        cc_emails=cc_emails,
                        bcc_emails=bcc_emails,
                        test_mode=test_mode
                    )
                    send_duration = int((time.time() - send_start) * 1000)
                    
                    # Log sending action
                    if result['status'] == 'success' or result['status'] == 'test':
                        self.audit_logger.log_action(
                            action=AuditActionType.EMAIL_SENT,
                            resource_type='bulletin',
                            resource_id=bulletin_id,
                            actor=actor,
                            region=region_name,
                            status='SUCCESS',
                            recipient_count=len(to_emails),
                            email_addresses=to_emails,
                            cc_addresses=cc_emails,
                            bcc_addresses=bcc_emails,
                            details=json.dumps({'test_mode': test_mode, 'job_id': job_id}),
                            duration_ms=send_duration
                        )
                        
                        total_sent += result.get('sent_count', len(to_emails))
                        logger.info(
                            f"✅ Sent to {region_name}: {result.get('sent_count', len(to_emails))} recipients "
                            f"(To: {len(to_emails)}, Cc: {len(cc_emails or [])}, Bcc: {len(bcc_emails or [])})"
                        )
                    else:
                        # Log failure
                        error_msg = ', '.join(result.get('errors', ['Unknown error']))
                        self.audit_logger.log_action(
                            action=AuditActionType.EMAIL_FAILED,
                            resource_type='bulletin',
                            resource_id=bulletin_id,
                            actor=actor,
                            region=region_name,
                            status='FAILURE',
                            recipient_count=len(to_emails),
                            email_addresses=to_emails,
                            error_message=error_msg,
                            duration_ms=send_duration
                        )
                        
                        total_failed += 1
                        failed_regions.append((region_name, error_msg))
                        logger.error(f"❌ Failed to send to {region_name}: {error_msg}")
                
                except Exception as e:
                    logger.error(f"Error sending to region {region_name}: {e}")
                    total_failed += 1
                    failed_regions.append((region_name, str(e)))
                    
                    # Log exception
                    self.audit_logger.log_action(
                        action=AuditActionType.EMAIL_FAILED,
                        resource_type='bulletin',
                        resource_id=bulletin_id,
                        actor=actor,
                        region=region_name,
                        status='FAILURE',
                        error_message=str(e)
                    )
            
            # Update bulletin status
            duration_ms = int((time.time() - start_time) * 1000)
            
            if total_failed == 0 and total_sent > 0:
                # Update to SENT
                BulletinService().update_bulletin(bulletin_id, status='SENT')
                
                self.audit_logger.log_action(
                    action=AuditActionType.BULLETIN_SENT,
                    resource_type='bulletin',
                    resource_id=bulletin_id,
                    actor=actor,
                    status='SUCCESS',
                    recipient_count=total_sent,
                    details=json.dumps({'regions': regions, 'job_id': job_id}),
                    duration_ms=duration_ms
                )
                
                logger.info(f"✅ Bulletin #{bulletin_id} delivery complete: {total_sent} sent to all regions")
                return True
            else:
                # Partial or complete failure
                status = 'PARTIAL' if total_sent > 0 else 'FAILURE'
                self.audit_logger.log_action(
                    action=AuditActionType.BULLETIN_FAILED,
                    resource_type='bulletin',
                    resource_id=bulletin_id,
                    actor=actor,
                    status=status,
                    recipient_count=total_sent,
                    error_message=f"Failed to send to regions: {', '.join([r[0] for r in failed_regions])}",
                    details=json.dumps({
                        'total_sent': total_sent,
                        'failed_regions': failed_regions,
                        'job_id': job_id
                    }),
                    duration_ms=duration_ms
                )
                
                logger.warning(
                    f"⚠️ Bulletin #{bulletin_id} delivery {'partial' if total_sent > 0 else 'failed'}: "
                    f"{total_sent} sent, {total_failed} failed"
                )
                return False
        
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(f"Error executing delivery job: {e}")
            
            self.audit_logger.log_action(
                action=AuditActionType.BULLETIN_FAILED,
                resource_type='bulletin',
                resource_id=bulletin_id,
                actor=actor,
                status='FAILURE',
                error_message=str(e),
                details=json.dumps({'job_id': job_id}),
                duration_ms=duration_ms
            )
            
            return False
    
    def _render_bulletin_html(self, bulletin: Dict, region: str) -> str:
        """Render bulletin to HTML format for region"""
        try:
            # Count severity levels
            critical_count = 0
            high_count = 0
            medium_count = 0
            
            for cve in bulletin.get('cves', []):
                severity = cve.get('severity', '').upper()
                if severity == 'CRITICAL':
                    critical_count += 1
                elif severity == 'HIGH':
                    high_count += 1
                elif severity == 'MEDIUM':
                    medium_count += 1
            
            html = EmailTemplate.render_bulletin(
                title=bulletin['title'],
                region=region,
                bulletin_id=bulletin['id'],
                body=bulletin.get('body'),
                grouped_cves=bulletin.get('grouped_cves', []),
                total_cves=len(bulletin.get('cves', [])),
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                footer_message=f"Bulletin ID: {bulletin['id']} | Delivery Region: {region}"
            )
            
            return html
        
        except Exception as e:
            logger.error(f"Error rendering bulletin HTML: {e}")
            # Return minimal fallback HTML
            return f"""
            <html>
            <head><meta charset="UTF-8"></head>
            <body>
            <h1>{bulletin.get('title', 'Security Bulletin')}</h1>
            <p>{bulletin.get('body', 'No content')}</p>
            <p><strong>Region:</strong> {region}</p>
            <p><strong>Bulletin ID:</strong> {bulletin.get('id')}</p>
            </body>
            </html>
            """
    
    def start_background_processor(self, interval_seconds: int = 60):
        """
        Start background thread to process delivery queue
        
        Args:
            interval_seconds: How often to check queue (in seconds)
        """
        def processor():
            logger.info(f"📬 Background delivery processor started (interval: {interval_seconds}s)")
            
            while True:
                try:
                    result = self.process_queue(max_jobs=5)
                    if result['processed'] > 0:
                        logger.debug(f"Queue processing result: {result}")
                    time.sleep(interval_seconds)
                
                except Exception as e:
                    logger.error(f"Background processor error: {e}")
                    time.sleep(interval_seconds)
        
        thread = Thread(target=processor, daemon=True)
        thread.start()
        
        logger.info("✅ Background delivery processor thread started")
        return thread


class BulletinValidator:
    """Validate bulletins before sending"""
    
    def __init__(self, mailing_service: RegionMailingService = None):
        """Initialize validator"""
        self.mailing_service = mailing_service or RegionMailingService()
    
    def validate_for_send(self, bulletin_id: int) -> tuple[bool, List[str]]:
        """
        Validate bulletin is ready to send
        
        Args:
            bulletin_id: Bulletin to validate
        
        Returns:
            (is_valid, errors)
        """
        errors = []
        
        try:
            bulletin = BulletinService().get_bulletin_detail(bulletin_id)
            
            if not bulletin:
                errors.append("Bulletin not found")
                return False, errors
            
            # Check title
            if not bulletin.get('title') or len(bulletin['title']) < 5:
                errors.append("Title must be at least 5 characters")
            
            # Check regions
            if not bulletin.get('regions'):
                errors.append("At least one region must be selected")
            
            # Check mailing lists exist for selected regions
            for region_name in bulletin.get('regions', []):
                mailing_list = self.mailing_service.get_region_mailing_by_name(region_name)
                
                if not mailing_list:
                    errors.append(f"No mailing list configured for region '{region_name}'")
                elif not mailing_list.to_recipients:
                    errors.append(f"No recipients configured for region '{region_name}'")
            
            return len(errors) == 0, errors
        
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            return False, errors
