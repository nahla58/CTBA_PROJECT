"""
Bulletin Management Models - Pydantic schemas for validation and serialization
"""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime


class BulletinStatus(str, Enum):
    """Bulletin workflow statuses"""
    DRAFT = "DRAFT"
    SENT = "SENT"
    NOT_PROCESSED = "NOT_PROCESSED"
    ARCHIVED = "ARCHIVED"


class RegionEnum(str, Enum):
    """Supported bulletin delivery regions"""
    NORAM = "NORAM"
    LATAM = "LATAM"
    EUROPE = "EUROPE"
    APMEA = "APMEA"


# ========== REGION MODELS ==========

class RegionCreate(BaseModel):
    """Create a new region"""
    name: str = Field(..., min_length=2, max_length=50)
    description: Optional[str] = Field(None, max_length=500)
    recipients: str = Field(..., description="Comma-separated email addresses")
    
    @field_validator('recipients')
    def validate_recipients(cls, v):
        """Validate email format"""
        if not v or v.strip() == "":
            raise ValueError("At least one recipient email required")
        emails = [e.strip() for e in v.split(',')]
        for email in emails:
            if '@' not in email:
                raise ValueError(f"Invalid email format: {email}")
        return v


class RegionUpdate(BaseModel):
    """Update an existing region"""
    description: Optional[str] = Field(None, max_length=500)
    recipients: Optional[str] = Field(None, description="Comma-separated email addresses")
    
    @field_validator('recipients')
    def validate_recipients(cls, v):
        """Validate email format if provided"""
        if v and v.strip() != "":
            emails = [e.strip() for e in v.split(',')]
            for email in emails:
                if '@' not in email:
                    raise ValueError(f"Invalid email format: {email}")
        return v


class RegionResponse(BaseModel):
    """Region response model"""
    id: int
    name: str
    description: Optional[str]
    recipients: List[str] = []
    created_at: Optional[str]
    
    class Config:
        from_attributes = True


# ========== CVE GROUPING ==========

class CVEGrouping(BaseModel):
    """CVE grouped by technology"""
    vendor: str
    product: str
    cve_count: int
    cves: List[Dict[str, Any]] = []
    remediation: Optional[str] = None


# ========== BULLETIN MODELS ==========

class BulletinCreate(BaseModel):
    """Create a new bulletin"""
    title: str = Field(..., min_length=5, max_length=200)
    body: Optional[str] = Field(None, max_length=5000)
    regions: List[str] = Field(..., description="Regions to send to (NORAM, LATAM, EUROPE, APMEA)")
    cve_ids: Optional[List[str]] = Field(None, description="Associated CVE IDs")
    technology_filter: Optional[str] = Field(None, description="Optional: Filter by technology vendor:product")
    attachments: Optional[List[str]] = Field(None, description="Base64 encoded attachments or file paths")
    status: Optional[BulletinStatus] = Field(BulletinStatus.DRAFT, description="Initial status")
    created_by: Optional[str] = Field(None, description="Analyst who created this bulletin")
    
    @field_validator('regions')
    def validate_regions(cls, v):
        """At least one region required and must be valid"""
        if not v or len(v) == 0:
            raise ValueError("At least one region required")
        valid_regions = [r.value for r in RegionEnum]
        for region in v:
            if not isinstance(region, str) or not region.strip():
                raise ValueError(f"Region must be a non-empty string")
            if region.upper() not in valid_regions:
                raise ValueError(f"Invalid region: {region}. Must be one of: {', '.join(valid_regions)}")
        return [r.upper() for r in v]  # Normalize to uppercase


class BulletinUpdate(BaseModel):
    """Update an existing bulletin"""
    title: Optional[str] = Field(None, min_length=5, max_length=200)
    body: Optional[str] = Field(None, max_length=5000)
    regions: Optional[List[str]] = None
    status: Optional[BulletinStatus] = None
    
    @field_validator('regions')
    def validate_regions(cls, v):
        """Validate regions if provided"""
        if v:
            for region in v:
                if region not in [r.value for r in RegionEnum]:
                    raise ValueError(f"Invalid region: {region}")
        return v


class BulletinResponse(BaseModel):
    """Bulletin list view response"""
    id: int
    title: str
    regions: List[str]
    status: BulletinStatus
    created_by: str
    created_at: str
    sent_at: Optional[str] = None
    cve_count: int = 0
    
    class Config:
        from_attributes = True


class BulletinDetailResponse(BaseModel):
    """Bulletin detail view response"""
    id: int
    title: str
    body: Optional[str]
    regions: List[str]
    status: BulletinStatus
    created_by: str
    created_at: str
    sent_at: Optional[str] = None
    cves: List[Dict[str, Any]] = []
    grouped_cves: List[CVEGrouping] = []
    attachments: List[Dict[str, Any]] = []
    
    class Config:
        from_attributes = True


# ========== SENDING & PREVIEW ==========

class BulletinSendRequest(BaseModel):
    """Request to send a bulletin"""
    regions: Optional[List[str]] = None  # Use all regions if not specified
    test_mode: bool = False
    cc_recipients: Optional[List[str]] = None
    bcc_recipients: Optional[List[str]] = None
    actor: Optional[str] = None  # User/system queuing the send


class BulletinPreviewResponse(BaseModel):
    """Preview response before sending"""
    bulletin_id: int
    title: str
    body: Optional[str]
    regions: List[str]
    recipient_counts: Dict[str, Any]  # Region -> {to, cc, bcc, total}
    mailing_lists: Optional[Dict[str, Any]] = None  # Actual mailing list details
    total_recipients: int
    preview_html: str
    validation_errors: List[str] = []
    is_valid: bool = True
    is_valid: bool


# ========== DELIVERY & AUDIT ==========

class DeliveryLogResponse(BaseModel):
    """Single delivery log entry"""
    id: int
    action: str  # SENT, FAILED, RETRY, BOUNCED
    region: str
    recipients: Optional[str]
    message: Optional[str]
    created_at: str
    
    class Config:
        from_attributes = True


class BulletinHistoryResponse(BaseModel):
    """Complete bulletin history"""
    bulletin: BulletinDetailResponse
    delivery_logs: List[DeliveryLogResponse] = []
    statistics: Dict[str, Any] = {}
    
    class Config:
        from_attributes = True


class BulletinStatsResponse(BaseModel):
    """Bulletin statistics overview"""
    total_bulletins: int
    by_status: Dict[str, int]
    by_region: Dict[str, int]
    total_cves_sent: int
    total_recipients_contacted: int
    success_rate: float = 100.0


# ========== ATTACHMENT ==========

class AttachmentResponse(BaseModel):
    """File attachment response"""
    id: int
    bulletin_id: int
    filename: str
    size: int
    created_at: str
    
    class Config:
        from_attributes = True
