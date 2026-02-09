"""
API endpoints for multi-source CVE ingestion
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
import logging

from app.ingestion.multi_source_manager import (
    MultiSourceIngestionManager,
    IngestionSource,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ingestion", tags=["ingestion"])

# Pydantic models for API
class ManualCVEInput(BaseModel):
    """Manual CVE entry input"""
    id: str = Field(..., description="CVE ID (e.g., CVE-2024-12345)")
    description: str = Field(..., description="Vulnerability description")
    published: Optional[str] = Field(None, description="Publication date ISO format")
    cvss: Optional[float] = Field(None, ge=0, le=10, description="CVSS score 0-10")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")
    cwe_id: Optional[str] = Field(None, description="CWE ID")
    affected_products: Optional[List[dict]] = Field(None, description="List of affected products")
    references: Optional[List[str]] = Field(None, description="Reference URLs")
    source_url: Optional[str] = Field(None, description="Source URL")
    status: Optional[str] = Field("IMPORTED", description="CVE status")
    notes: Optional[str] = Field(None, description="Analyst notes")


class IngestionResponse(BaseModel):
    """Ingestion operation response"""
    source: str
    imported_count: int
    duplicate_count: int
    error_count: int
    total_processed: int
    errors: List[str]
    cve_ids: List[str]
    timestamp: str


class ManualEntryResponse(BaseModel):
    """Manual entry response"""
    success: bool
    cve_id: Optional[str]
    errors: List[str]


# Manager instance (would be injected in real app)
ingestion_manager = MultiSourceIngestionManager()


@router.post("/nvd")
async def ingest_from_nvd(days: int = Query(7, ge=1, le=365)) -> IngestionResponse:
    """
    Import CVEs from NVD (National Vulnerability Database)
    
    Queries the NVD API for recently modified or published CVEs
    and imports them into the system with deduplication.
    """
    try:
        result = ingestion_manager.ingest_from_nvd(days)
        return IngestionResponse(**result.to_dict())
    except Exception as e:
        logger.error(f"NVD ingestion endpoint error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"NVD ingestion failed: {str(e)}"
        )


@router.post("/cvedetails")
async def ingest_from_cvedetails(
    keyword: str = Query(..., description="Search keyword"),
    limit: int = Query(100, ge=1, le=1000)
) -> IngestionResponse:
    """
    Import CVEs from CVE Details
    
    Searches CVE Details database for CVEs matching the keyword
    (vendor name, product name, or CVE ID)
    """
    try:
        result = ingestion_manager.ingest_from_cvedetails(keyword, limit)
        return IngestionResponse(**result.to_dict())
    except Exception as e:
        logger.error(f"CVE Details ingestion endpoint error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"CVE Details ingestion failed: {str(e)}"
        )


@router.post("/msrc")
async def ingest_from_msrc(
    year: int = Query(..., ge=1999, le=2100),
    month: int = Query(..., ge=1, le=12)
) -> IngestionResponse:
    """
    Import CVEs from Microsoft Security Response Center
    
    Retrieves CVEs from MSRC monthly bulletins for the specified month
    """
    try:
        result = ingestion_manager.ingest_from_msrc(year, month)
        return IngestionResponse(**result.to_dict())
    except Exception as e:
        logger.error(f"MSRC ingestion endpoint error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"MSRC ingestion failed: {str(e)}"
        )


@router.post("/hackuity")
async def ingest_from_hackuity(
    filter_type: str = Query(
        "recent",
        description="Filter: 'recent', 'exploitable', or search query"
    ),
    limit: int = Query(50, ge=1, le=500)
) -> IngestionResponse:
    """
    Import CVEs from Hackuity threat intelligence
    
    Retrieves CVEs from Hackuity's threat intelligence feed with filters:
    - 'recent': Recently discovered CVEs
    - 'exploitable': Currently exploited CVEs
    - Or any search query for targeted import
    """
    try:
        result = ingestion_manager.ingest_from_hackuity(filter_type, limit)
        return IngestionResponse(**result.to_dict())
    except Exception as e:
        logger.error(f"Hackuity ingestion endpoint error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Hackuity ingestion failed: {str(e)}"
        )


@router.post("/manual")
async def ingest_manual_entry(cve_data: ManualCVEInput) -> ManualEntryResponse:
    """
    Manually enter a CVE into the system
    
    Validates and imports manually entered CVE data with comprehensive
    field validation and normalization.
    
    Returns 400 Bad Request if validation fails with error details.
    """
    try:
        success, normalized, errors = ingestion_manager.ingest_manual_entry(
            cve_data.dict()
        )
        
        if not success:
            raise HTTPException(
                status_code=400,
                detail={
                    "success": False,
                    "errors": errors
                }
            )
        
        return ManualEntryResponse(
            success=True,
            cve_id=normalized.get('id'),
            errors=[]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Manual entry endpoint error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Manual entry failed: {str(e)}"
        )


@router.get("/manual/template")
async def get_manual_entry_template() -> dict:
    """
    Get template for manual CVE entry
    
    Returns a JSON template showing all available fields and their formats
    """
    return ingestion_manager.get_manual_entry_template()


@router.get("/status")
async def get_ingestion_status() -> dict:
    """
    Get current ingestion status and statistics
    
    Returns summary of imported CVEs and available sources
    """
    return ingestion_manager.get_ingestion_status()


@router.get("/sources")
async def list_available_sources() -> dict:
    """
    List all available CVE sources
    
    Returns supported ingestion sources and their characteristics
    """
    return {
        "sources": [
            {
                "id": "nvd",
                "name": "National Vulnerability Database",
                "description": "Official NVD database with comprehensive CVE data",
                "endpoint": "POST /api/ingestion/nvd",
                "requires_auth": False,
                "rate_limit": "6 requests per 30 seconds"
            },
            {
                "id": "cvedetails",
                "name": "CVE Details",
                "description": "CVE Details database with CVSS and product information",
                "endpoint": "POST /api/ingestion/cvedetails",
                "requires_auth": False,
                "rate_limit": "No official limit"
            },
            {
                "id": "msrc",
                "name": "Microsoft Security Response Center",
                "description": "Microsoft security bulletins and CVEs",
                "endpoint": "POST /api/ingestion/msrc",
                "requires_auth": False,
                "rate_limit": "No official limit"
            },
            {
                "id": "hackuity",
                "name": "Hackuity",
                "description": "Threat intelligence with exploitability data",
                "endpoint": "POST /api/ingestion/hackuity",
                "requires_auth": True,
                "rate_limit": "API key dependent"
            },
            {
                "id": "manual",
                "name": "Manual Entry",
                "description": "Manually enter CVEs with validation",
                "endpoint": "POST /api/ingestion/manual",
                "requires_auth": True,
                "rate_limit": "No limit"
            }
        ]
    }
