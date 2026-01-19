"""
Bulletin API Routes - FastAPI endpoints for bulletin management
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Query
from typing import List, Optional
import os
import logging
from datetime import datetime

from models.bulletin_models import (
    BulletinCreate, BulletinUpdate, BulletinResponse, BulletinDetailResponse,
    BulletinSendRequest, BulletinPreviewResponse, DeliveryLogResponse, BulletinHistoryResponse,
    RegionCreate, RegionUpdate, RegionResponse, BulletinStatsResponse
)
from services.bulletin_service import BulletinService, RegionService
from services.delivery_engine import BulletinDeliveryEngine, BulletinValidator
from services.email_service import EmailService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/bulletins", tags=["bulletins"])
region_router = APIRouter(prefix="/api/regions", tags=["regions"])

# Initialize services
email_service = EmailService()
delivery_engine = BulletinDeliveryEngine(email_service)
UPLOAD_DIR = "uploads/bulletin_attachments"

# Create upload directory if not exists
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================================
# REGION ENDPOINTS
# ============================================================================

@region_router.post("", response_model=RegionResponse, status_code=201)
async def create_region(region: RegionCreate):
    """Create a new region"""
    try:
        result = RegionService.create_region(
            name=region.name,
            description=region.description,
            recipients=region.recipients
        )
        return result
    except Exception as e:
        logger.error(f"Error creating region: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@region_router.get("", response_model=List[RegionResponse])
async def list_regions():
    """List all regions"""
    try:
        regions = RegionService.get_regions()
        return regions
    except Exception as e:
        logger.error(f"Error listing regions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@region_router.get("/{region_id}", response_model=RegionResponse)
async def get_region(region_id: int):
    """Get specific region"""
    try:
        region = RegionService.get_region(region_id)
        
        if not region:
            raise HTTPException(status_code=404, detail="Region not found")
        
        return region
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@region_router.put("/{region_id}", response_model=RegionResponse)
async def update_region(region_id: int, region: RegionUpdate):
    """Update region"""
    try:
        updated = RegionService.update_region(
            region_id,
            description=region.description,
            recipients=region.recipients
        )
        
        if not updated:
            raise HTTPException(status_code=404, detail="Region not found")
        
        return updated
    except Exception as e:
        logger.error(f"Error updating region: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@region_router.delete("/{region_id}", status_code=204)
async def delete_region(region_id: int):
    """Delete region (archive recommended)"""
    try:
        RegionService.delete_region(region_id)
        return {"message": "Region deleted"}
    except Exception as e:
        logger.error(f"Error deleting region: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================================
# BULLETIN ENDPOINTS
# ============================================================================

@router.post("", response_model=BulletinResponse, status_code=201)
async def create_bulletin(bulletin: BulletinCreate, current_user: str = "system"):
    """Create new bulletin"""
    try:
        result = BulletinService.create_bulletin(
            title=bulletin.title,
            body=bulletin.body,
            regions=bulletin.regions,
            cve_ids=bulletin.cve_ids,
            created_by=current_user
        )
        return result
    except Exception as e:
        logger.error(f"Error creating bulletin: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=dict)
async def list_bulletins(
    status: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """List bulletins with pagination"""
    try:
        bulletins, total = BulletinService.get_bulletins(
            status=status,
            region=region,
            limit=limit,
            offset=offset
        )
        
        return {
            'items': bulletins,
            'total': total,
            'limit': limit,
            'offset': offset
        }
    except Exception as e:
        logger.error(f"Error listing bulletins: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{bulletin_id}", response_model=BulletinDetailResponse)
async def get_bulletin(bulletin_id: int):
    """Get bulletin details"""
    try:
        bulletin = BulletinService.get_bulletin_detail(bulletin_id)
        
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        return bulletin
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{bulletin_id}", response_model=BulletinDetailResponse)
async def update_bulletin(bulletin_id: int, bulletin: BulletinUpdate):
    """Update bulletin"""
    try:
        updated = BulletinService.update_bulletin(
            bulletin_id,
            title=bulletin.title,
            body=bulletin.body,
            regions=bulletin.regions,
            status=bulletin.status.value if bulletin.status else None
        )
        
        if not updated:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        return updated
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating bulletin: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{bulletin_id}", status_code=204)
async def delete_bulletin(bulletin_id: int):
    """Delete bulletin"""
    try:
        success = BulletinService.delete_bulletin(bulletin_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        return {"message": "Bulletin deleted"}
    except Exception as e:
        logger.error(f"Error deleting bulletin: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================================
# ATTACHMENT ENDPOINTS
# ============================================================================

@router.post("/{bulletin_id}/attachments", status_code=201)
async def upload_attachment(bulletin_id: int, file: UploadFile = File(...)):
    """Upload attachment to bulletin"""
    try:
        # Verify bulletin exists
        bulletin = BulletinService.get_bulletin_detail(bulletin_id)
        
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        # Save file
        file_path = os.path.join(UPLOAD_DIR, f"bulletin_{bulletin_id}_{file.filename}")
        
        with open(file_path, 'wb') as f:
            content = await file.read()
            f.write(content)
        
        # Log attachment
        result = BulletinService.add_attachment(bulletin_id, file.filename, file_path)
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading attachment: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{bulletin_id}/attachments/{attachment_id}", status_code=204)
async def delete_attachment(bulletin_id: int, attachment_id: int):
    """Delete attachment"""
    try:
        # TODO: Implement deletion from database and filesystem
        return {"message": "Attachment deleted"}
    except Exception as e:
        logger.error(f"Error deleting attachment: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================================
# BULLETIN SENDING ENDPOINTS
# ============================================================================

@router.post("/{bulletin_id}/preview", response_model=BulletinPreviewResponse)
async def preview_bulletin(bulletin_id: int, send_request: Optional[BulletinSendRequest] = None):
    """Preview bulletin before sending"""
    try:
        bulletin = BulletinService.get_bulletin_detail(bulletin_id)
        
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        # Validate before preview
        is_valid, errors = BulletinValidator.validate_for_send(bulletin_id)
        
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Bulletin validation failed: {errors}")
        
        # Get target regions
        target_regions = send_request.regions if send_request and send_request.regions else bulletin['regions']
        
        # Count recipients per region
        all_regions = RegionService.get_regions()
        region_map = {r['name']: r for r in all_regions}
        
        recipient_counts = {}
        total_recipients = 0
        
        for region_name in target_regions:
            region = region_map.get(region_name)
            if region and region.get('recipients'):
                count = len([e.strip() for e in region['recipients']])
                recipient_counts[region_name] = count
                total_recipients += count
        
        # Generate preview HTML
        preview_html = delivery_engine._render_bulletin_html(bulletin, target_regions[0] if target_regions else "")
        
        return {
            'bulletin_id': bulletin_id,
            'regions_to_send': target_regions,
            'recipient_counts': recipient_counts,
            'preview_html': preview_html,
            'total_recipients': total_recipients
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error previewing bulletin: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{bulletin_id}/send", response_model=dict, status_code=202)
async def send_bulletin(bulletin_id: int, send_request: Optional[BulletinSendRequest] = None):
    """Send bulletin to regions"""
    try:
        # Validate
        is_valid, errors = BulletinValidator.validate_for_send(bulletin_id)
        
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Validation failed: {errors}")
        
        # Queue for delivery
        regions = send_request.regions if send_request and send_request.regions else None
        test_mode = send_request.preview_mode if send_request else False
        
        job = delivery_engine.queue_bulletin_send(
            bulletin_id=bulletin_id,
            regions=regions,
            test_mode=test_mode
        )
        
        return {
            'status': 'queued',
            'bulletin_id': bulletin_id,
            'message': 'Bulletin queued for delivery',
            'job': job
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending bulletin: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================================
# DELIVERY LOG ENDPOINTS
# ============================================================================

@router.get("/{bulletin_id}/history", response_model=BulletinHistoryResponse)
async def get_bulletin_history(bulletin_id: int):
    """Get bulletin delivery history"""
    try:
        bulletin = BulletinService.get_bulletin_detail(bulletin_id)
        
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        logs = BulletinService.get_delivery_history(bulletin_id)
        
        # Count by status
        total_sent = len([l for l in logs if l.get('action') == 'SENT'])
        total_failed = len([l for l in logs if l.get('action') == 'FAILED'])
        total_pending = len([l for l in logs if l.get('action') == 'PENDING'])
        
        return {
            'bulletin': bulletin,
            'delivery_logs': logs,
            'total_sent': total_sent,
            'total_failed': total_failed,
            'total_pending': total_pending
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# STATISTICS ENDPOINTS
# ============================================================================

@router.get("/stats/overview", response_model=BulletinStatsResponse)
async def get_bulletin_stats():
    """Get bulletin statistics"""
    try:
        bulletins, total = BulletinService.get_bulletins(limit=1000)
        
        # Count by status
        by_status = {}
        by_region = {}
        total_cves = 0
        
        for bulletin in bulletins:
            status = bulletin.get('status', 'UNKNOWN')
            by_status[status] = by_status.get(status, 0) + 1
            
            for region in bulletin.get('regions', []):
                by_region[region] = by_region.get(region, 0) + 1
            
            total_cves += bulletin.get('cve_count', 0)
        
        # TODO: Calculate other stats from delivery logs
        
        return {
            'total_bulletins': total,
            'by_status': by_status,
            'by_region': by_region,
            'total_cves_sent': total_cves,
            'total_recipients_contacted': 0,  # TODO: Calculate from logs
            'avg_send_time_minutes': 0  # TODO: Calculate from logs
        }
    
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@router.post("/process-queue", status_code=202)
async def process_delivery_queue():
    """Manually trigger delivery queue processing"""
    try:
        delivery_engine.process_queue(max_jobs=10)
        
        return {
            'status': 'processing',
            'message': 'Delivery queue processing started',
            'queue_size': delivery_engine.delivery_queue.qsize()
        }
    
    except Exception as e:
        logger.error(f"Error processing queue: {e}")
        raise HTTPException(status_code=500, detail=str(e))
