"""
Delivery Engine & Audit API Routes
Endpoints for sending bulletins, tracking delivery, and viewing audit logs
"""
import logging
from typing import Optional, List
from fastapi import APIRouter, Query, HTTPException, Request
from pydantic import BaseModel

from app.models.bulletin_models import (
    BulletinSendRequest, BulletinPreviewResponse,
    RegionResponse
)
from app.services.enhanced_delivery_engine import EnhancedBulletinDeliveryEngine, BulletinValidator
from app.services.region_mailing_service import RegionMailingService, RegionMailingLists
from app.services.audit_logger import AuditLogger, AuditActionType

logger = logging.getLogger(__name__)

# Initialize services
delivery_engine: Optional[EnhancedBulletinDeliveryEngine] = None
mailing_service = RegionMailingService()
audit_logger = AuditLogger()
validator = BulletinValidator(mailing_service)

router = APIRouter()


# ========== REQUEST MODELS ==========

class MailingListUpdate(BaseModel):
    """Request body for updating mailing lists"""
    to_recipients: List[str] = []
    cc_recipients: Optional[List[str]] = None
    bcc_recipients: Optional[List[str]] = None
    updated_by: str = "api"


# ========== SEND & PREVIEW ENDPOINTS ==========

@router.post("/bulletins/{bulletin_id}/send", status_code=202, tags=["delivery"])
async def send_bulletin(
    bulletin_id: int,
    request: BulletinSendRequest
):
    """
    Queue bulletin for delivery to regions
    
    Response status 202 (Accepted) indicates bulletin has been queued for delivery.
    Actual sending happens asynchronously in background processor.
    """
    try:
        if not delivery_engine:
            raise HTTPException(status_code=503, detail="Delivery engine not available")
        
        # Validate bulletin
        is_valid, errors = validator.validate_for_send(bulletin_id)
        
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Bulletin validation failed: {', '.join(errors)}")
        
        # Queue for delivery
        job = delivery_engine.queue_bulletin_send(
            bulletin_id=bulletin_id,
            regions=request.regions,
            test_mode=request.test_mode,
            cc_recipients=request.cc_recipients,
            bcc_recipients=request.bcc_recipients,
            actor=request.actor or 'API'
        )
        
        return {
            "status": "QUEUED",
            "job_id": job.get('job_id'),
            "bulletin_id": bulletin_id,
            "regions": request.regions or [],
            "test_mode": request.test_mode,
            "message": f"Bulletin queued for delivery (Job: {job.get('job_id')})"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bulletins/{bulletin_id}/preview", response_model=BulletinPreviewResponse, tags=["delivery"])
async def preview_bulletin(bulletin_id: int, request: Optional[BulletinSendRequest] = None):
    """
    Generate preview of bulletin with recipient counts
    
    Shows how the bulletin will look when sent to each region,
    including To/Cc/Bcc recipient counts.
    """
    try:
        from app.services.bulletin_service import BulletinService
        from app.services.email_service import EmailTemplate
        
        bulletin_service = BulletinService()
        bulletin = bulletin_service.get_bulletin_detail(bulletin_id)
        
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        # Get regions to preview
        regions_to_preview = request.regions if request else bulletin.get('regions', [])
        
        # Validate
        is_valid, errors = validator.validate_for_send(bulletin_id)
        
        # Resolve mailing lists and count recipients
        recipient_counts = {}
        total_recipients = 0
        mailing_lists = {}
        
        for region_name in regions_to_preview:
            mailing_list = mailing_service.get_region_mailing_by_name(region_name)
            
            if mailing_list:
                to_count = len(mailing_list.to_recipients) if mailing_list.to_recipients else 0
                cc_count = len(mailing_list.cc_recipients) if mailing_list.cc_recipients else 0
                bcc_count = len(mailing_list.bcc_recipients) if mailing_list.bcc_recipients else 0
                total = to_count + cc_count + bcc_count
                
                recipient_counts[region_name] = {
                    "to": to_count,
                    "cc": cc_count,
                    "bcc": bcc_count,
                    "total": total
                }
                
                mailing_lists[region_name] = mailing_list.to_dict()
                total_recipients += total
        
        # Generate preview HTML
        preview_html = EmailTemplate.render_bulletin(
            title=bulletin['title'],
            region=', '.join(regions_to_preview),
            bulletin_id=bulletin_id,
            body=bulletin.get('body'),
            grouped_cves=bulletin.get('grouped_cves', []),
            total_cves=len(bulletin.get('cves', [])),
            critical_count=len([c for c in bulletin.get('cves', []) if c.get('severity') == 'CRITICAL']),
            high_count=len([c for c in bulletin.get('cves', []) if c.get('severity') == 'HIGH']),
            medium_count=len([c for c in bulletin.get('cves', []) if c.get('severity') == 'MEDIUM'])
        )
        
        return {
            "bulletin_id": bulletin_id,
            "title": bulletin['title'],
            "regions": regions_to_preview,
            "recipient_counts": recipient_counts,
            "mailing_lists": mailing_lists,
            "total_recipients": total_recipients,
            "preview_html": preview_html,
            "validation_errors": errors,
            "is_valid": is_valid
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error previewing bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== DELIVERY AUDIT ENDPOINTS ==========

@router.get("/bulletins/{bulletin_id}/delivery-audit", tags=["audit"])
async def get_bulletin_delivery_audit(bulletin_id: int):
    """
    Get complete audit trail for bulletin delivery
    
    Returns all delivery-related actions with timestamps, recipient counts,
    success/failure details for compliance and traceability.
    """
    try:
        audit_data = audit_logger.get_bulletin_delivery_audit(bulletin_id)
        
        return {
            "bulletin_id": bulletin_id,
            "audit_trail": audit_data['audit_entries'],
            "statistics": audit_data['statistics']
        }
    
    except Exception as e:
        logger.error(f"Error fetching delivery audit: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit-logs", tags=["audit"])
async def get_audit_logs(
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[int] = Query(None, description="Filter by resource ID"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """
    Get audit log entries with filtering
    
    Available resource types: 'bulletin', 'region', 'email'
    Available actions: BULLETIN_CREATED, BULLETIN_SENT, EMAIL_SENT, EMAIL_FAILED, etc.
    """
    try:
        logs, total = audit_logger.get_audit_history(
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            limit=limit,
            offset=offset
        )
        
        return {
            "logs": logs,
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total
            }
        }
    
    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit-report", tags=["audit"])
async def export_audit_report(
    start_date: Optional[str] = Query(None, description="ISO format start date"),
    end_date: Optional[str] = Query(None, description="ISO format end date"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type")
):
    """
    Export comprehensive audit report for compliance
    
    Generates full audit report with statistics and all matching entries.
    Useful for compliance audits and security reviews.
    """
    try:
        report = audit_logger.export_audit_report(
            start_date=start_date,
            end_date=end_date,
            resource_type=resource_type
        )
        
        return report
    
    except Exception as e:
        logger.error(f"Error exporting audit report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== REGION MAILING LIST ENDPOINTS ==========

@router.get("/regions/{region_id}/mailing-list", tags=["regions"])
async def get_region_mailing_list(region_id: int):
    """Get mailing lists (To/Cc/Bcc) for a region"""
    try:
        mailing_list = mailing_service.get_region_mailing_lists(region_id)
        
        # If no mailing list exists, return default empty structure
        if not mailing_list:
            return {
                'region_id': region_id,
                'region_name': f'Region {region_id}',
                'to_recipients': [],
                'cc_recipients': [],
                'bcc_recipients': [],
                'total_recipients': 0
            }
        
        result = mailing_list.to_dict()
        # Ensure proper field names for frontend
        return {
            'region_id': result['region_id'],
            'region_name': result['region_name'],
            'to_recipients': result.get('to', []),
            'cc_recipients': result.get('cc', []),
            'bcc_recipients': result.get('bcc', []),
            'total_recipients': result.get('total_recipients', 0)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching mailing list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/regions/{region_id}/mailing-list", tags=["regions"])
async def update_region_mailing_list(
    region_id: int,
    data: MailingListUpdate
):
    """
    Update mailing lists for a region
    
    Request body:
    {
        "to_recipients": ["email1@example.com", "email2@example.com"],
        "cc_recipients": ["cc@example.com"],
        "bcc_recipients": ["bcc@example.com"],
        "updated_by": "username"
    }
    """
    try:
        to_recipients = data.to_recipients or []
        cc_recipients = data.cc_recipients or []
        bcc_recipients = data.bcc_recipients or []
        updated_by = data.updated_by or 'api'
        
        mailing_list = mailing_service.setup_region_mailing(
            region_id=region_id,
            to_recipients=to_recipients,
            cc_recipients=cc_recipients,
            bcc_recipients=bcc_recipients,
            changed_by=updated_by
        )
        
        # Log to audit
        audit_logger.log_action(
            action=AuditActionType.MAILING_LIST_UPDATED,
            resource_type='region',
            resource_id=region_id,
            actor=updated_by,
            details=f"Updated mailing lists: To={len(to_recipients)}, Cc={len(cc_recipients)}, Bcc={len(bcc_recipients)}"
        )
        
        if mailing_list:
            return mailing_list.to_dict()
        else:
            return {
                'region_id': region_id,
                'to_recipients': to_recipients,
                'cc_recipients': cc_recipients,
                'bcc_recipients': bcc_recipients,
                'total_recipients': len(to_recipients) + len(cc_recipients) + len(bcc_recipients)
            }
    
    except Exception as e:
        logger.error(f"Error updating mailing list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/regions/mailing-lists/all", tags=["regions"])
async def get_all_mailing_lists():
    """Get mailing lists for all regions"""
    try:
        mailing_lists = mailing_service.get_all_region_mailing_lists()
        
        return {
            "mailing_lists": [ml.to_dict() for ml in mailing_lists],
            "total": len(mailing_lists)
        }
    
    except Exception as e:
        logger.error(f"Error fetching all mailing lists: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/regions/{region_id}/mailing-audit", tags=["audit"])
async def get_mailing_list_audit(region_id: int):
    """Get audit history for region mailing list changes"""
    try:
        audit_history = mailing_service.get_mailing_list_audit(region_id)
        
        return {
            "region_id": region_id,
            "audit_history": audit_history
        }
    
    except Exception as e:
        logger.error(f"Error fetching mailing audit: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== QUEUE MANAGEMENT ENDPOINTS ==========

@router.post("/delivery-queue/process", tags=["delivery"])
async def process_delivery_queue(max_jobs: int = Query(10, ge=1, le=100)):
    """
    Manually trigger delivery queue processing
    
    Useful for testing or forcing immediate processing of queued bulletins.
    """
    try:
        if not delivery_engine:
            raise HTTPException(status_code=503, detail="Delivery engine not available")
        
        result = delivery_engine.process_queue(max_jobs=max_jobs)
        
        return {
            "success": True,
            "result": result
        }
    
    except Exception as e:
        logger.error(f"Error processing queue: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/delivery-queue/status", tags=["delivery"])
async def get_queue_status():
    """Get current delivery queue status"""
    try:
        if not delivery_engine:
            return {
                "queue_size": 0,
                "engine_status": "NOT_AVAILABLE"
            }
        
        return {
            "queue_size": delivery_engine.delivery_queue.qsize(),
            "engine_status": "RUNNING",
            "max_retries": delivery_engine.max_retries,
            "retry_delay": delivery_engine.retry_delay
        }
    
    except Exception as e:
        logger.error(f"Error fetching queue status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== AUDIT LOG ENDPOINTS ==========

@router.get("/audit-logs", tags=["audit"])
async def get_audit_logs(
    bulletin_id: Optional[int] = Query(None),
    action_type: Optional[str] = Query(None),
    region_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=1000)
):
    """
    Get audit logs with optional filtering
    """
    try:
        logs = audit_logger.get_audit_history(
            bulletin_id=bulletin_id,
            action_type=action_type,
            limit=limit
        )
        
        # Filter by region and status on server-side
        if region_id or status:
            logs = [
                log for log in logs
                if (not region_id or log.get('region_id') == region_id) and
                   (not status or log.get('status') == status)
            ]
        
        return logs
    
    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit-report", tags=["audit"])
async def get_audit_report(
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None)
):
    """
    Generate audit report for compliance
    """
    try:
        report = audit_logger.export_audit_report()
        return report
    
    except Exception as e:
        logger.error(f"Error generating audit report: {e}")
        raise HTTPException(status_code=500, detail=str(e))
