"""
Enhanced Bulletin Management REST API Routes
Supports: CVE grouping, regional delivery, attachment management, and status tracking
"""
import os
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Query, HTTPException, UploadFile, File, Form, Depends, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Dict, Any

from app.services.enhanced_bulletin_service import (
    EnhancedBulletinService,
    CVEGroupingService,
    RegionService,
    AttachmentService
)

logger = logging.getLogger(__name__)

# Initialize services
bulletin_service = EnhancedBulletinService()
cve_grouping_service = CVEGroupingService()
region_service = RegionService()
attachment_service = AttachmentService()

# Initialize routers
router = APIRouter(prefix="/api/bulletins", tags=["bulletins"])
region_router = APIRouter(prefix="/api/regions", tags=["regions"])
attachment_router = APIRouter(prefix="/api/bulletins", tags=["attachments"])

# ============================================================================
# PYDANTIC MODELS FOR REQUEST/RESPONSE
# ============================================================================

class BulletinCreateRequest(BaseModel):
    """Create bulletin with CVE grouping"""
    title: str = Field(..., min_length=5, max_length=200)
    body: Optional[str] = Field(None, max_length=5000)
    cve_ids: List[str] = Field(..., description="CVE IDs to include")
    region_ids: List[int] = Field(..., description="Region IDs to send to")
    created_by: Optional[str] = Field(None, description="Username of creator (auto-extracted from token if not provided)")
    auto_group: bool = Field(True, description="Automatically group CVEs by technology")


class BulletinStatusUpdateRequest(BaseModel):
    """Update bulletin status"""
    status: str = Field(..., description="New status: DRAFT, SENT, NOT_PROCESSED, ARCHIVED")
    updated_by: str = Field(..., description="Username of person making update")


class RegionCreateRequest(BaseModel):
    """Create a new region"""
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    recipients: Optional[str] = Field(None, description="Comma-separated email addresses")
    region_code: Optional[str] = Field(None, max_length=20)


class CVEGroupingResponse(BaseModel):
    """CVE grouping details"""
    vendor: str
    product: str
    cve_count: int
    remediation_guidance: Optional[str]
    cves: List[Dict[str, Any]]


class BulletinDetailResponse(BaseModel):
    """Detailed bulletin response"""
    id: int
    title: str
    body: Optional[str]
    status: str
    created_by: str
    created_at: str
    grouped_cves: List[CVEGroupingResponse]
    regions: List[Dict[str, Any]]
    attachments: List[Dict[str, Any]]
    grouped_by_technology: bool
    archived: bool


# ============================================================================
# BULLETIN ENDPOINTS
# ============================================================================

@router.post("/", response_model=Dict[str, Any], status_code=201)
async def create_bulletin(
    request: BulletinCreateRequest,
    authorization: str = Header(None)
):
    """
    Create a new bulletin with automatic CVE grouping
    
    Features:
    - Automatically groups CVEs by vendor/product (technology)
    - Applies remediation guidance from library
    - Supports multiple region selection
    - Sets initial status to DRAFT
    """
    try:
        # Extract username from JWT token if created_by not provided
        created_by = request.created_by
        if not created_by and authorization:
            import jwt
            try:
                token = authorization.replace('Bearer ', '')
                payload = jwt.decode(token, options={"verify_signature": False})
                created_by = payload.get('username', 'unknown')
            except:
                created_by = 'unknown'
        
        if not created_by:
            created_by = 'unknown'
        
        result = bulletin_service.create_bulletin_with_grouping(
            title=request.title,
            cve_ids=request.cve_ids,
            region_ids=request.region_ids,
            created_by=created_by,
            body=request.body or '',
            auto_group=request.auto_group
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{bulletin_id}", response_model=BulletinDetailResponse)
async def get_bulletin_detail(bulletin_id: int):
    """
    Get full bulletin details including:
    - Grouped CVEs by technology/product
    - Remediation guidance per group
    - Selected regions
    - Attachments
    - Current status
    """
    try:
        bulletin = bulletin_service.get_bulletin_detail(bulletin_id)
        return bulletin
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{bulletin_id}/status", response_model=Dict[str, Any])
async def update_bulletin_status(
    bulletin_id: int,
    request: BulletinStatusUpdateRequest
):
    """
    Update bulletin status
    
    Supported statuses:
    - DRAFT: Initial state, not yet sent
    - SENT: Sent to selected regions
    - NOT_PROCESSED: Future extension for deferred processing
    - ARCHIVED: Archived, no longer active
    """
    try:
        valid_statuses = ['DRAFT', 'SENT', 'NOT_PROCESSED', 'ARCHIVED']
        if request.status not in valid_statuses:
            raise ValueError(f"Invalid status. Must be one of: {', '.join(valid_statuses)}")
        
        bulletin_service.update_bulletin_status(
            bulletin_id=bulletin_id,
            new_status=request.status,
            updated_by=request.updated_by
        )
        
        return {
            'status': 'success',
            'bulletin_id': bulletin_id,
            'new_status': request.status
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating bulletin status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CVE GROUPING ENDPOINTS
# ============================================================================

@router.post("/analyze/group-cves", response_model=Dict[str, Any])
async def analyze_cve_grouping(cve_ids: List[str] = Query(...)):
    """
    Analyze how CVEs would be grouped by technology
    
    Returns CVEs grouped by vendor:product with suggested remediation guidance
    """
    try:
        groups = cve_grouping_service.group_cves_by_technology(cve_ids)
        
        # Add remediation guidance for each group
        for tech_key in groups:
            vendor, product = tech_key.split(':')
            severity = groups[tech_key][0].get('severity') if groups[tech_key] else None
            remediation = cve_grouping_service.get_remediation_guidance(vendor, product, severity)
            
            for cve_group in [g for g in groups[tech_key]]:
                cve_group['remediation_guidance'] = remediation
        
        return {
            'total_cves': len(cve_ids),
            'technology_groups': len(groups),
            'groups': groups
        }
    except Exception as e:
        logger.error(f"Error analyzing CVE grouping: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# REGION MANAGEMENT ENDPOINTS
# ============================================================================

@region_router.post("/", response_model=Dict[str, Any], status_code=201)
async def create_region(request: RegionCreateRequest):
    """
    Create a new delivery region
    
    Features:
    - Supports arbitrary region creation
    - Can be archived later without data loss
    - Historical bulletins preserve region data
    """
    try:
        result = region_service.create_region(
            name=request.name,
            description=request.description or '',
            recipients=request.recipients or '',
            region_code=request.region_code
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@region_router.get("/", response_model=Dict[str, Any])
async def list_active_regions():
    """
    List all active (non-archived) regions
    
    Returns available regions for bulletin selection
    """
    try:
        regions = region_service.get_active_regions()
        return {
            'count': len(regions),
            'regions': regions
        }
    except Exception as e:
        logger.error(f"Error fetching regions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@region_router.post("/{region_id}/archive", response_model=Dict[str, Any])
async def archive_region(
    region_id: int,
    reason: Optional[str] = Query(None)
):
    """
    Archive a region without deleting it
    
    Features:
    - Preserves historical data - existing bulletins still reference this region
    - Archived regions don't appear in active region list
    - Can be unarchived if needed (add separate endpoint)
    """
    try:
        region_service.archive_region(region_id, reason or '')
        return {
            'status': 'archived',
            'region_id': region_id,
            'reason': reason
        }
    except Exception as e:
        logger.error(f"Error archiving region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ATTACHMENT ENDPOINTS
# ============================================================================

@attachment_router.post("/{bulletin_id}/attachments/upload", status_code=201)
async def upload_attachment(
    bulletin_id: int,
    file: UploadFile = File(...),
    uploaded_by: str = Form(...)
):
    """
    Upload file attachment to bulletin
    
    Features:
    - File size validation (max 50 MB)
    - File type whitelist (pdf, doc, xlsx, txt, zip, etc.)
    - Automatic checksum calculation for integrity
    - Secure filename generation
    """
    try:
        file_content = await file.read()
        
        result = attachment_service.save_attachment(
            bulletin_id=bulletin_id,
            filename=file.filename,
            file_content=file_content,
            uploaded_by=uploaded_by,
            content_type=file.content_type or 'application/octet-stream'
        )
        
        return {
            'status': 'success',
            'attachment_id': result['id'],
            'filename': result['filename'],
            'size': result['file_size'],
            'uploaded_at': result['uploaded_at']
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error uploading attachment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@attachment_router.get("/{bulletin_id}/attachments", response_model=Dict[str, Any])
async def list_attachments(bulletin_id: int):
    """Get all attachments for a bulletin"""
    try:
        attachments = attachment_service.get_attachments(bulletin_id)
        return {
            'count': len(attachments),
            'attachments': attachments
        }
    except Exception as e:
        logger.error(f"Error listing attachments: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@attachment_router.get("/attachments/{attachment_id}/download")
async def download_attachment(attachment_id: int):
    """Download an attachment file"""
    try:
        result = attachment_service.download_attachment(attachment_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Attachment not found")
        
        filename, content = result
        return FileResponse(
            content=content,
            media_type='application/octet-stream',
            filename=filename
        )
    except Exception as e:
        logger.error(f"Error downloading attachment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@attachment_router.delete("/{bulletin_id}/attachments/{attachment_id}")
async def delete_attachment(bulletin_id: int, attachment_id: int):
    """Delete (archive) an attachment"""
    try:
        attachment_service.delete_attachment(attachment_id)
        return {
            'status': 'success',
            'attachment_id': attachment_id
        }
    except Exception as e:
        logger.error(f"Error deleting attachment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@router.get("/bulletins/stats/summary", response_model=Dict[str, Any])
async def get_bulletin_statistics():
    """Get summary statistics about bulletins"""
    try:
        # This would typically query bulletin_metadata table for aggregated stats
        return {
            'total_bulletins': 0,
            'by_status': {},
            'total_cves_sent': 0,
            'total_regions': 0
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# EXPORT ROUTERS
# ============================================================================

# Export routers to be used in main FastAPI app
__all__ = ['router', 'region_router', 'attachment_router']
