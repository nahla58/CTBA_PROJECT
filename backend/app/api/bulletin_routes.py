"""
Bulletin Management REST API Routes
"""
import os
import logging
from typing import Optional, List
from fastapi import APIRouter, Query, HTTPException, UploadFile, File, Depends
from fastapi.responses import FileResponse

from app.models.bulletin_models import (
    BulletinCreate, BulletinUpdate, BulletinResponse, BulletinDetailResponse,
    RegionCreate, RegionUpdate, RegionResponse,
    BulletinSendRequest, BulletinPreviewResponse, BulletinHistoryResponse,
    BulletinStatsResponse, DeliveryLogResponse
)
from app.services.bulletin_service import BulletinService, RegionService
from app.services.delivery_engine import BulletinDeliveryEngine, BulletinValidator

logger = logging.getLogger(__name__)

# Initialize services
bulletin_service = BulletinService()
region_service = RegionService()

# Routers
router = APIRouter()
region_router = APIRouter()

# Global delivery engine reference (set by main.py)
delivery_engine: Optional[BulletinDeliveryEngine] = None


# ========== REGION ENDPOINTS ==========

@region_router.post("/regions", response_model=RegionResponse, status_code=201, tags=["regions"])
async def create_region(region: RegionCreate):
    """Create a new bulletin delivery region"""
    try:
        result = region_service.create_region(
            name=region.name,
            description=region.description or '',
            recipients=region.recipients
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@region_router.get("/regions", response_model=List[RegionResponse], tags=["regions"])
async def list_regions():
    """Get all bulletin delivery regions"""
    try:
        return region_service.get_regions()
    except Exception as e:
        logger.error(f"Error listing regions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@region_router.get("/regions/{region_id}", response_model=RegionResponse, tags=["regions"])
async def get_region(region_id: int):
    """Get a specific region"""
    try:
        return region_service.get_region(region_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@region_router.put("/regions/{region_id}", response_model=RegionResponse, tags=["regions"])
async def update_region(region_id: int, region: RegionUpdate):
    """Update a region"""
    try:
        return region_service.update_region(
            region_id,
            description=region.description,
            recipients=region.recipients
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@region_router.delete("/regions/{region_id}", status_code=204, tags=["regions"])
async def delete_region(region_id: int):
    """Delete a region"""
    try:
        region_service.delete_region(region_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== BULLETIN ENDPOINTS ==========

@router.post("/bulletins", response_model=BulletinResponse, status_code=201, tags=["bulletins"])
async def create_bulletin(bulletin: BulletinCreate):
    """Create a new bulletin"""
    try:
        result = bulletin_service.create_bulletin(
            title=bulletin.title,
            body=bulletin.body,
            regions=bulletin.regions,
            cve_ids=bulletin.cve_ids,
            created_by=bulletin.created_by
        )
        return result
    except Exception as e:
        logger.error(f"Error creating bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/bulletins", tags=["bulletins"])
async def list_bulletins(
    status: Optional[str] = Query(None, description="Filter by status"),
    region: Optional[str] = Query(None, description="Filter by region"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """Get bulletins with optional filtering and pagination"""
    try:
        bulletins, total = bulletin_service.get_bulletins(
            status=status,
            region=region,
            limit=limit,
            offset=offset
        )
        return {
            "success": True,
            "bulletins": bulletins,
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total
            }
        }
    except Exception as e:
        logger.error(f"Error listing bulletins: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/bulletins/{bulletin_id}", response_model=BulletinDetailResponse, tags=["bulletins"])
async def get_bulletin(bulletin_id: int):
    """Get bulletin details"""
    try:
        return bulletin_service.get_bulletin_detail(bulletin_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/bulletins/{bulletin_id}", response_model=BulletinDetailResponse, tags=["bulletins"])
async def update_bulletin(bulletin_id: int, bulletin: BulletinUpdate):
    """Update a bulletin"""
    try:
        return bulletin_service.update_bulletin(
            bulletin_id,
            title=bulletin.title,
            body=bulletin.body,
            regions=bulletin.regions,
            status=bulletin.status
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/bulletins/{bulletin_id}", status_code=204, tags=["bulletins"])
async def delete_bulletin(bulletin_id: int):
    """Delete a bulletin"""
    try:
        bulletin_service.delete_bulletin(bulletin_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== ATTACHMENT ENDPOINTS ==========

@router.post("/bulletins/{bulletin_id}/attachments", status_code=201, tags=["attachments"])
async def upload_attachment(bulletin_id: int, file: UploadFile = File(...)):
    """Upload file attachment to bulletin"""
    try:
        # Verify bulletin exists
        bulletin_service.get_bulletin_detail(bulletin_id)
        
        # Save file
        upload_dir = os.path.join(os.path.dirname(__file__), '../../uploads/bulletin_attachments')
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, f"bulletin_{bulletin_id}_{file.filename}")
        
        with open(file_path, 'wb') as f:
            content = await file.read()
            f.write(content)
        
        # Store in database
        result = bulletin_service.add_attachment(
            bulletin_id,
            file.filename,
            file_path
        )
        
        return {
            "success": True,
            "attachment": result
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error uploading attachment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/bulletins/{bulletin_id}/attachments/{attachment_id}", status_code=204, tags=["attachments"])
async def delete_attachment(bulletin_id: int, attachment_id: int):
    """Delete file attachment"""
    try:
        # TODO: Implement attachment deletion
        logger.info(f"Deleted attachment {attachment_id}")
    except Exception as e:
        logger.error(f"Error deleting attachment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== SENDING & PREVIEW ENDPOINTS ==========

@router.post("/bulletins/{bulletin_id}/preview", response_model=BulletinPreviewResponse, tags=["bulletins"])
async def preview_bulletin(bulletin_id: int, request: BulletinSendRequest):
    """Preview bulletin before sending"""
    try:
        bulletin = bulletin_service.get_bulletin_detail(bulletin_id)
        regions_to_send = request.regions or bulletin['regions']
        
        # Validate
        is_valid, errors = BulletinValidator.validate_for_send(bulletin_id)
        
        # Count recipients per region
        all_regions = region_service.get_regions()
        region_map = {r['name']: r for r in all_regions}
        
        recipient_counts = {}
        total_recipients = 0
        for region_name in regions_to_send:
            region = region_map.get(region_name)
            count = len(region['recipients']) if region else 0
            recipient_counts[region_name] = count
            total_recipients += count
        
        # Generate preview HTML
        from app.services.email_service import EmailTemplate
        preview_html = EmailTemplate.render_bulletin(
            title=bulletin['title'],
            region=', '.join(regions_to_send),
            bulletin_id=bulletin_id,
            body=bulletin.get('body'),
            grouped_cves=bulletin.get('grouped_cves', [])
        )
        
        return {
            "bulletin_id": bulletin_id,
            "title": bulletin['title'],
            "recipient_counts": recipient_counts,
            "total_recipients": total_recipients,
            "preview_html": preview_html,
            "validation_errors": errors,
            "is_valid": is_valid
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error previewing bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bulletins/{bulletin_id}/send", status_code=202, tags=["bulletins"])
async def send_bulletin(bulletin_id: int, request: BulletinSendRequest):
    """Queue bulletin for delivery"""
    try:
        # Validate bulletin exists
        bulletin = bulletin_service.get_bulletin_detail(bulletin_id)
        
        if not delivery_engine:
            raise HTTPException(status_code=503, detail="Delivery engine not available")
        
        # Queue for delivery
        job = delivery_engine.queue_bulletin_send(
            bulletin_id=bulletin_id,
            regions=request.regions,
            test_mode=request.test_mode,
            cc_recipients=request.cc_recipients,
            bcc_recipients=request.bcc_recipients
        )
        
        return {
            "status": "QUEUED",
            "job_id": job.get('job_id'),
            "bulletin_id": bulletin_id,
            "message": f"Bulletin queued for delivery to {len(request.regions or bulletin['regions'])} region(s)"
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error sending bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== DELIVERY LOG ENDPOINTS ==========

@router.get("/bulletins/{bulletin_id}/history", response_model=BulletinHistoryResponse, tags=["bulletins"])
async def get_bulletin_history(bulletin_id: int):
    """Get bulletin delivery history"""
    try:
        bulletin = bulletin_service.get_bulletin_detail(bulletin_id)
        logs = bulletin_service.get_delivery_history(bulletin_id)
        
        # Calculate statistics
        total_sent = len([l for l in logs if l['action'] == 'SENT'])
        total_failed = len([l for l in logs if l['action'] == 'FAILED'])
        
        return {
            "bulletin": bulletin,
            "delivery_logs": logs,
            "statistics": {
                "total_sent": total_sent,
                "total_failed": total_failed,
                "success_rate": (total_sent / (total_sent + total_failed) * 100) if (total_sent + total_failed) > 0 else 0
            }
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching delivery history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== STATISTICS ENDPOINTS ==========

@router.get("/bulletins/stats/overview", response_model=BulletinStatsResponse, tags=["bulletins"])
async def get_bulletin_stats():
    """Get bulletin statistics"""
    try:
        bulletins, total = bulletin_service.get_bulletins(limit=1000, offset=0)
        
        # Count by status and region
        by_status = {}
        by_region = {}
        total_cves = 0
        total_recipients = 0
        
        all_regions = region_service.get_regions()
        
        for bulletin in bulletins:
            status = bulletin.get('status', 'UNKNOWN')
            by_status[status] = by_status.get(status, 0) + 1
            
            for region in bulletin.get('regions', []):
                by_region[region] = by_region.get(region, 0) + 1
            
            total_cves += bulletin.get('cve_count', 0)
        
        # Count total recipients
        for region in all_regions:
            total_recipients += len(region.get('recipients', []))
        
        return {
            "total_bulletins": total,
            "by_status": by_status,
            "by_region": by_region,
            "total_cves_sent": total_cves,
            "total_recipients_contacted": total_recipients
        }
    except Exception as e:
        logger.error(f"Error fetching statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== UTILITY ENDPOINTS ==========

@router.post("/bulletins/process-queue", tags=["bulletins"])
async def process_queue(max_jobs: int = Query(10, ge=1, le=100)):
    """Manually trigger queue processing"""
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
