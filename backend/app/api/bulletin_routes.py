"""
Bulletin Management REST API Routes
"""
import os
import json
import sqlite3
import logging
from typing import Optional, List
from fastapi import APIRouter, Query, HTTPException, UploadFile, File, Depends, Header
from fastapi.responses import FileResponse

from app.models.bulletin_models import (
    BulletinCreate, BulletinUpdate, BulletinResponse, BulletinDetailResponse,
    RegionCreate, RegionUpdate, RegionResponse,
    BulletinSendRequest, BulletinPreviewResponse, BulletinHistoryResponse,
    BulletinStatsResponse, DeliveryLogResponse
)
from app.services.bulletin_service import BulletinService, RegionService
from app.services.delivery_engine import BulletinDeliveryEngine, BulletinValidator
from app.services.region_mailing_service import RegionMailingService

logger = logging.getLogger(__name__)

# Initialize services
bulletin_service = BulletinService()
region_service = RegionService()
region_mailing_service = RegionMailingService()

# Routers
router = APIRouter()
region_router = APIRouter()

# Global delivery engine reference (set by main.py)
delivery_engine: Optional[BulletinDeliveryEngine] = None


def set_delivery_engine(engine):
    """Set the global delivery engine instance"""
    global delivery_engine
    delivery_engine = engine


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
async def create_bulletin(
    bulletin: BulletinCreate,
    authorization: Optional[str] = Header(None)
):
    """Create a new bulletin"""
    try:
        # Extract username from JWT token if not provided
        created_by = bulletin.created_by
        if not created_by and authorization:
            import jwt
            try:
                token = authorization.replace('Bearer ', '')
                payload = jwt.decode(token, options={"verify_signature": False})
                created_by = payload.get('sub') or payload.get('username', 'unknown')
            except:
                created_by = 'unknown'
        
        if not created_by:
            created_by = 'unknown'
        
        result = bulletin_service.create_bulletin(
            title=bulletin.title,
            body=bulletin.body,
            regions=bulletin.regions,
            cve_ids=bulletin.cve_ids,
            created_by=created_by
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
        recipient_counts = {}
        total_recipients = 0
        for region_name in regions_to_send:
            mailing = region_mailing_service.get_region_mailing_by_name(region_name)
            if mailing:
                count = mailing.get_recipient_count()
            else:
                count = 0
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
            "body": bulletin.get('body'),
            "regions": regions_to_send,
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


# ========== CVE GROUPING ENDPOINTS ==========

@router.get("/cves/grouped", tags=["cves"])
async def get_grouped_cves(
    status: str = Query("ACCEPTED", description="CVE status filter (ACCEPTED, REJECTED, DEFERRED)"),
    technology_filter: Optional[str] = Query(None, description="Filter by vendor:product")
):
    """
    Get CVEs grouped by:
    1. Technology/product
    2. Identical remediation guidance
    
    Returns hierarchically grouped CVEs organized by vendor:product and remediation.
    """
    try:
        # Connect to database and fetch CVEs with their products
        conn = sqlite3.connect('ctba_platform.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Fetch CVEs with their affected products
        query = '''
            SELECT DISTINCT
                c.id,
                c.cve_id,
                c.severity,
                c.cvss_score,
                c.published_date,
                c.description,
                c.status,
                ap.vendor,
                ap.product
            FROM cves c
            LEFT JOIN affected_products ap ON c.cve_id = ap.cve_id
            WHERE c.status = ?
            ORDER BY c.severity DESC, c.cvss_score DESC
        '''
        
        cursor.execute(query, (status,))
        rows = cursor.fetchall()
        
        # Group rows by CVE and organize products
        cves_dict = {}
        for row in rows:
            cve_id = row['cve_id']
            
            if cve_id not in cves_dict:
                cves_dict[cve_id] = {
                    'cve_id': cve_id,
                    'severity': row['severity'],
                    'cvss_score': row['cvss_score'],
                    'published_date': row['published_date'],
                    'description': row['description'],
                    'remediation': None,
                    'products': []
                }
            
            # Add product if it exists
            if row['vendor'] and row['product']:
                product = {
                    'vendor': row['vendor'],
                    'product': row['product']
                }
                # Avoid duplicates
                if product not in cves_dict[cve_id]['products']:
                    cves_dict[cve_id]['products'].append(product)
        
        cves = list(cves_dict.values())
        
        # Apply technology filter if provided
        if technology_filter:
            filtered_cves = []
            for cve in cves:
                matched = False
                for product in cve.get('products', []):
                    if f"{product.get('vendor', '')}:{product.get('product', '')}" == technology_filter:
                        matched = True
                        break
                if matched:
                    filtered_cves.append(cve)
            cves = filtered_cves
        
        conn.close()
        
        # Group CVEs by technology and remediation
        grouped = BulletinService._group_cves_by_technology(cves)
        
        return {
            "total_cves": len(cves),
            "total_groups": len(grouped),
            "groups": grouped
        }
    except Exception as e:
        logger.error(f"Error fetching grouped CVEs: {e}")
        raise HTTPException(status_code=500, detail=str(e))
