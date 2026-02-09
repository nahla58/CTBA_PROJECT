"""
Bulletin Models - Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class BulletinStatus(str, Enum):
    """Bulletin status workflow"""
    DRAFT = "DRAFT"
    SENT = "SENT"
    NOT_PROCESSED = "NOT_PROCESSED"
    ARCHIVED = "ARCHIVED"
    CLOSED = "CLOSED"


class RegionEnum(str, Enum):
    """Supported regions"""
    NORAM = "NORAM"
    LATAM = "LATAM"
    EUROPE = "EUROPE"
    APMEA = "APMEA"


# ============================================================================
# REGION MODELS
# ============================================================================

class RegionCreate(BaseModel):
    """Create a new region"""
    name: str = Field(..., min_length=2, max_length=50)
    description: Optional[str] = None
    recipients: str = Field(..., description="Comma-separated email list")
    
    @validator('recipients')
    def validate_recipients(cls, v):
        """Validate email list format"""
        if not v or not v.strip():
            raise ValueError("Recipients list cannot be empty")
        emails = [e.strip() for e in v.split(',')]
        for email in emails:
            if '@' not in email:
                raise ValueError(f"Invalid email format: {email}")
        return ','.join(emails)


class RegionUpdate(BaseModel):
    """Update region details"""
    description: Optional[str] = None
    recipients: Optional[str] = None


class RegionResponse(BaseModel):
    """Region response"""
    id: int
    name: str
    description: Optional[str]
    recipients: str
    created_at: str
    
    class Config:
        from_attributes = True


# ============================================================================
# MAILING LIST MODELS
# ============================================================================

class MailingListCreate(BaseModel):
    """Create mailing list entry"""
    region_id: int
    list_type: str = Field(..., description="Type: TO, CC, BCC")
    recipients: str = Field(..., description="Comma-separated emails")


class MailingListResponse(BaseModel):
    """Mailing list response"""
    id: int
    region_id: int
    region_name: str
    list_type: str
    recipients: str
    
    class Config:
        from_attributes = True


# ============================================================================
# ATTACHMENT MODELS
# ============================================================================

class AttachmentResponse(BaseModel):
    """Bulletin attachment response"""
    id: int
    bulletin_id: int
    filename: str
    path: str
    created_at: str
    
    class Config:
        from_attributes = True


# ============================================================================
# BULLETIN MODELS
# ============================================================================

class CVEGrouping(BaseModel):
    """Grouped CVEs by technology/product"""
    technology: str  # "vendor: product"
    cves: List[Dict[str, Any]] = Field(default_factory=list)
    remediation: Optional[str] = None
    count: int = 0


class BulletinCreate(BaseModel):
    """Create bulletin"""
    title: str = Field(..., min_length=5, max_length=200)
    body: Optional[str] = None
    regions: List[str] = Field(..., description="Region IDs or names")
    cve_ids: Optional[List[str]] = Field(default_factory=list, description="CVE IDs to include")
    technology_filter: Optional[str] = None  # "vendor:product" format
    status: Optional[BulletinStatus] = BulletinStatus.DRAFT
    created_by: Optional[str] = Field(None, description="Username of creator (auto-extracted from token)")
    
    @validator('regions')
    def validate_regions(cls, v):
        """Validate at least one region selected"""
        if not v or len(v) == 0:
            raise ValueError("At least one region must be selected")
        return v


class BulletinUpdate(BaseModel):
    """Update bulletin"""
    title: Optional[str] = None
    body: Optional[str] = None
    regions: Optional[List[str]] = None
    status: Optional[BulletinStatus] = None


class BulletinResponse(BaseModel):
    """Bulletin response"""
    id: int
    title: str
    body: Optional[str]
    regions: str  # JSON string of region names
    status: str
    created_by: Optional[str]
    created_at: str
    sent_at: Optional[str]
    cve_count: int = 0  # Number of associated CVEs
    attachment_count: int = 0
    
    class Config:
        from_attributes = True


class BulletinDetailResponse(BulletinResponse):
    """Detailed bulletin response with CVEs and attachments"""
    cves: List[Dict[str, Any]] = []
    attachments: List[AttachmentResponse] = []
    grouped_cves: List[CVEGrouping] = []


class BulletinSendRequest(BaseModel):
    """Request to send bulletin"""
    regions: Optional[List[str]] = None  # If none, send to all bulletin regions
    preview_mode: bool = False  # If True, don't actually send


class BulletinPreviewResponse(BaseModel):
    """Preview of bulletin before sending"""
    bulletin_id: int
    regions_to_send: List[str]
    recipient_counts: Dict[str, int]  # region -> recipient count
    preview_html: str
    total_recipients: int


# ============================================================================
# DELIVERY LOG MODELS
# ============================================================================

class DeliveryLogResponse(BaseModel):
    """Bulletin delivery log entry"""
    id: int
    bulletin_id: int
    action: str  # SENT, FAILED, RETRY, BOUNCED
    region: str
    recipients: str
    message: Optional[str]
    created_at: str
    status: str  # SUCCESS, FAILED, PENDING
    
    class Config:
        from_attributes = True


class BulletinHistoryResponse(BaseModel):
    """Complete history of bulletin"""
    bulletin: BulletinResponse
    delivery_logs: List[DeliveryLogResponse]
    total_sent: int
    total_failed: int
    total_pending: int


# ============================================================================
# STATISTICS MODELS
# ============================================================================

class BulletinStatsResponse(BaseModel):
    """Bulletin statistics"""
    total_bulletins: int
    by_status: Dict[str, int]  # status -> count
    by_region: Dict[str, int]  # region -> count
    total_cves_sent: int
    total_recipients_contacted: int
    avg_send_time_minutes: float
