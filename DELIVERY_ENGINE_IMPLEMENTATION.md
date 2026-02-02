# Bulletin Delivery Engine - Complete Implementation Guide

## 2.4 Requirement Implementation: Bulletin Delivery Engine

This document describes the complete implementation of the Bulletin Delivery Engine system, fulfilling requirement 2.4:

**System Requirements:**
- ✅ Send bulletins through standardized HTML email template
- ✅ Automatically resolve To and Cc mailing lists for each region
- ✅ Log sending actions for traceability and audits

---

## Architecture Overview

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React)                          │
│                  BulletinManagement.js                       │
└──────────────────┬──────────────────────────────────────────┘
                   │ HTTP Requests
┌──────────────────▼──────────────────────────────────────────┐
│              FastAPI Backend (main.py)                       │
├──────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────┐  │
│  │         Delivery Routes (delivery_routes.py)           │  │
│  │  - POST /bulletins/{id}/send                           │  │
│  │  - POST /bulletins/{id}/preview                        │  │
│  │  - GET /bulletins/{id}/delivery-audit                  │  │
│  │  - GET /audit-logs                                     │  │
│  │  - GET /regions/{id}/mailing-list                      │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │      Enhanced Delivery Engine                          │  │
│  │  (enhanced_delivery_engine.py)                         │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │ EnhancedBulletinDeliveryEngine                  │ │  │
│  │  │ - Queue bulletin for sending                    │ │  │
│  │  │ - Process queue with retry logic                │ │  │
│  │  │ - Render bulletins to HTML                      │ │  │
│  │  │ - Trigger background processor                  │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │ BulletinValidator                               │ │  │
│  │  │ - Validate region config                        │ │  │
│  │  │ - Check mailing list exists                     │ │  │
│  │  │ - Validate recipient lists                      │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │      Region Mailing Service                           │  │
│  │  (region_mailing_service.py)                          │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │ RegionMailingService                            │ │  │
│  │  │ - Resolve To/Cc/Bcc addresses                   │ │  │
│  │  │ - Get mailing lists by region                   │ │  │
│  │  │ - Validate email addresses                      │ │  │
│  │  │ - Track mailing list changes (audit)            │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  │                                                        │  │
│  │  Database Tables:                                    │  │
│  │  - region_mailing_lists (To/Cc/Bcc per region)      │  │
│  │  - mailing_list_audit (change tracking)             │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │      Email Service                                     │  │
│  │  (services/email_service.py)                          │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │ EmailTemplate                                   │ │  │
│  │  │ - Professional HTML template                    │ │  │
│  │  │ - CVE grouping display                          │ │  │
│  │  │ - Severity color coding                         │ │  │
│  │  │ - Region-aware metadata                         │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │ EmailService                                    │ │  │
│  │  │ - SMTP integration                              │ │  │
│  │  │ - Attachment support                            │ │  │
│  │  │ - Test mode (logging only)                      │ │  │
│  │  │ - Send to To/Cc/Bcc recipients                  │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │      Audit Logger                                      │  │
│  │  (services/audit_logger.py)                           │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │ AuditLogger                                     │ │  │
│  │  │ - Log all delivery actions                      │ │  │
│  │  │ - Track success/failure per region              │ │  │
│  │  │ - Record recipient counts                       │ │  │
│  │  │ - Export compliance reports                     │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  │                                                        │  │
│  │  Database Tables:                                    │  │
│  │  - audit_logs (all delivery actions)                 │  │
│  │  - Full traceability for compliance                  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                   │ SQLite Database
┌──────────────────▼──────────────────────────────────────────┐
│           ctba_platform.db                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ regions                                              │ │
│  │ region_mailing_lists                                 │ │
│  │ mailing_list_audit                                   │ │
│  │ bulletins                                            │ │
│  │ audit_logs (actions & delivery tracking)             │ │
│  │ bulletin_logs (legacy, kept for compatibility)       │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## Key Features

### 1. HTML Email Templates

**Template Features:**
- Professional gradient header with region branding
- CVE grouping with severity color coding
- Technology/Product organization
- Remediation guidance display
- Summary statistics table
- Region-specific metadata
- Confidentiality notices

**Template Rendering:**
```python
html = EmailTemplate.render_bulletin(
    title="Critical Vulnerabilities in Active Systems",
    region="NORAM",
    bulletin_id=123,
    grouped_cves=[
        {
            "vendor": "Microsoft",
            "product": "Windows Server",
            "cve_count": 5,
            "severity_levels": {"CRITICAL": 2, "HIGH": 3},
            "cves": [...]
        }
    ],
    total_cves=5,
    critical_count=2,
    high_count=3,
    medium_count=0
)
```

### 2. Region-Based Mailing Lists

**Multi-Level Recipients:**
- **To**: Primary recipients (security team members)
- **Cc**: Optional secondary recipients (managers, compliance)
- **Bcc**: Optional hidden recipients (audit trail, archives)

**Automatic Resolution:**
```python
# System automatically resolves recipients by region
mailing_list = mailing_service.get_region_mailing_by_name("NORAM")
# Returns: RegionMailingLists with to_recipients, cc_recipients, bcc_recipients
```

**Mailing List Structure:**
```
NORAM Region:
├── To: admin@noram.local, security@noram.local, incident@noram.local
├── Cc: manager@noram.local, compliance@noram.local
└── Bcc: audit-archive@noram.local

LATAM Region:
├── To: admin@latam.local, security@latam.local
├── Cc: []
└── Bcc: []

EUROPE Region:
├── To: admin@europe.local, security@europe.local, dpo@europe.local
├── Cc: gdpr-compliance@europe.local
└── Bcc: gdpr-archive@europe.local

APMEA Region:
├── To: admin@apmea.local, security@apmea.local
├── Cc: management@apmea.local
└── Bcc: []
```

### 3. Comprehensive Audit Logging

**Audit Trail Captures:**
- Action type (BULLETIN_QUEUED, EMAIL_SENT, EMAIL_FAILED, etc.)
- Actor (user/system initiating action)
- Recipient counts and email addresses
- Region information
- Success/failure status with error messages
- Operation duration in milliseconds
- Attachment counts
- All To/Cc/Bcc recipients for compliance

**Audit Table Structure:**
```sql
audit_logs (
    id INTEGER PRIMARY KEY,
    action TEXT,                    -- BULLETIN_SENT, EMAIL_FAILED, etc.
    actor TEXT,                     -- Who performed the action
    resource_type TEXT,             -- 'bulletin', 'region', 'email'
    resource_id INTEGER,            -- Bulletin ID, Region ID, etc.
    details TEXT,                   -- JSON with additional context
    status TEXT,                    -- SUCCESS, FAILURE, PARTIAL
    recipient_count INTEGER,        -- How many recipients
    region TEXT,                    -- Region name (NORAM, LATAM, etc.)
    email_addresses TEXT,           -- CSV of To addresses
    cc_addresses TEXT,              -- CSV of Cc addresses
    bcc_addresses TEXT,             -- CSV of Bcc addresses
    attachment_count INTEGER,       -- Number of attachments
    error_message TEXT,             -- Error details if failed
    duration_ms INTEGER,            -- Operation duration
    created_at TIMESTAMP            -- When the action occurred
)
```

---

## API Endpoints

### Sending Bulletins

#### POST /api/bulletins/{bulletin_id}/send
**Send bulletin to regions**

Request:
```json
{
    "regions": ["NORAM", "LATAM"],
    "test_mode": false,
    "cc_recipients": ["security-review@company.com"],
    "bcc_recipients": null,
    "actor": "john.doe@company.com"
}
```

Response (202 Accepted):
```json
{
    "status": "QUEUED",
    "job_id": "123_1705075200",
    "bulletin_id": 123,
    "regions": ["NORAM", "LATAM"],
    "test_mode": false,
    "message": "Bulletin queued for delivery (Job: 123_1705075200)"
}
```

#### POST /api/bulletins/{bulletin_id}/preview
**Preview bulletin before sending**

Request:
```json
{
    "regions": ["NORAM"],
    "test_mode": false
}
```

Response:
```json
{
    "bulletin_id": 123,
    "title": "Critical Vulnerabilities in Active Systems",
    "regions": ["NORAM"],
    "recipient_counts": {
        "NORAM": {
            "to": 3,
            "cc": 2,
            "bcc": 1,
            "total": 6
        }
    },
    "mailing_lists": {
        "NORAM": {
            "region_id": 1,
            "region_name": "NORAM",
            "to": ["admin@noram.local", "security@noram.local"],
            "cc": ["manager@noram.local"],
            "bcc": []
        }
    },
    "total_recipients": 6,
    "preview_html": "<html>...</html>",
    "validation_errors": [],
    "is_valid": true
}
```

### Audit Logging

#### GET /api/bulletins/{bulletin_id}/delivery-audit
**Get complete audit trail for bulletin delivery**

Response:
```json
{
    "bulletin_id": 123,
    "audit_trail": [
        {
            "id": 1,
            "action": "BULLETIN_QUEUED",
            "actor": "john.doe@company.com",
            "resource_type": "bulletin",
            "resource_id": 123,
            "status": "SUCCESS",
            "recipient_count": 0,
            "region": null,
            "created_at": "2026-01-27T10:00:00"
        },
        {
            "id": 2,
            "action": "EMAIL_SENT",
            "actor": "SYSTEM",
            "resource_type": "bulletin",
            "resource_id": 123,
            "region": "NORAM",
            "status": "SUCCESS",
            "recipient_count": 6,
            "email_addresses": "admin@noram.local,security@noram.local",
            "cc_addresses": "manager@noram.local",
            "duration_ms": 2350,
            "created_at": "2026-01-27T10:00:05"
        }
    ],
    "statistics": {
        "total_sent": 1,
        "total_failed": 0,
        "total_retries": 0,
        "regions_affected": ["NORAM"],
        "total_recipients": 6
    }
}
```

#### GET /api/audit-logs
**Query audit logs with filters**

Parameters:
- `resource_type`: 'bulletin', 'region', 'email'
- `resource_id`: Filter by resource ID
- `action`: Filter by action type
- `limit`: Maximum results (default 100)
- `offset`: Pagination offset

Example: `/api/audit-logs?action=EMAIL_SENT&region=NORAM&limit=50`

Response:
```json
{
    "logs": [
        {
            "id": 2,
            "action": "EMAIL_SENT",
            "region": "NORAM",
            "recipient_count": 6,
            "status": "SUCCESS",
            "created_at": "2026-01-27T10:00:05"
        }
    ],
    "pagination": {
        "total": 1,
        "limit": 50,
        "offset": 0,
        "has_more": false
    }
}
```

#### GET /api/audit-report
**Export compliance audit report**

Parameters:
- `start_date`: ISO format date (optional)
- `end_date`: ISO format date (optional)
- `resource_type`: Filter by type (optional)

Response:
```json
{
    "export_date": "2026-01-27T10:30:00",
    "filters": {
        "start_date": "2026-01-01",
        "end_date": "2026-01-31",
        "resource_type": "bulletin"
    },
    "summary": {
        "total_entries": 25,
        "by_action": {
            "BULLETIN_QUEUED": 10,
            "EMAIL_SENT": 8,
            "EMAIL_FAILED": 2
        },
        "by_status": {
            "SUCCESS": 20,
            "FAILURE": 2,
            "PARTIAL": 3
        },
        "total_recipients_affected": 1250
    },
    "entries": [...]
}
```

### Mailing List Management

#### GET /api/regions/{region_id}/mailing-list
**Get mailing lists for region**

Response:
```json
{
    "region_id": 1,
    "region_name": "NORAM",
    "to": ["admin@noram.local", "security@noram.local"],
    "cc": ["manager@noram.local"],
    "bcc": [],
    "total_recipients": 3
}
```

#### PUT /api/regions/{region_id}/mailing-list
**Update mailing lists for region**

Request:
```json
{
    "to_recipients": ["new-admin@noram.local", "new-security@noram.local"],
    "cc_recipients": ["new-manager@noram.local"],
    "bcc_recipients": [],
    "changed_by": "admin@company.com"
}
```

#### GET /api/regions/mailing-lists/all
**Get all mailing lists**

Response:
```json
{
    "mailing_lists": [
        {
            "region_id": 1,
            "region_name": "NORAM",
            "to": [...],
            "cc": [...],
            "total_recipients": 6
        },
        {
            "region_id": 2,
            "region_name": "LATAM",
            "to": [...],
            "cc": [...],
            "total_recipients": 4
        }
    ],
    "total": 4
}
```

#### GET /api/regions/{region_id}/mailing-audit
**Get mailing list change history**

Response:
```json
{
    "region_id": 1,
    "audit_history": [
        {
            "id": 1,
            "action": "CREATED",
            "old_to_list": null,
            "new_to_list": "admin@noram.local,security@noram.local",
            "changed_by": "SYSTEM",
            "reason": null,
            "created_at": "2026-01-27T08:00:00"
        },
        {
            "id": 2,
            "action": "UPDATED",
            "old_to_list": "admin@noram.local,security@noram.local",
            "new_to_list": "admin@noram.local,security@noram.local,incident@noram.local",
            "changed_by": "admin@company.com",
            "reason": "Added incident response team",
            "created_at": "2026-01-27T09:00:00"
        }
    ]
}
```

### Queue Management

#### POST /api/delivery-queue/process
**Manually trigger queue processing**

Query: `?max_jobs=10`

Response:
```json
{
    "success": true,
    "result": {
        "processed": 5,
        "successful": 5,
        "failed": 0,
        "remaining": 0
    }
}
```

#### GET /api/delivery-queue/status
**Get queue status**

Response:
```json
{
    "queue_size": 3,
    "engine_status": "RUNNING",
    "max_retries": 3,
    "retry_delay": 60
}
```

---

## Bulletin Delivery Flow

### Step 1: Create Bulletin
User creates bulletin with title, body, CVEs, and regions.

### Step 2: Preview
User previews bulletin to see:
- HTML rendering
- Recipient counts by region and type
- Validation warnings

### Step 3: Send
User clicks "Send" button:
1. Bulletin queued in delivery engine
2. Audit log entry created (BULLETIN_QUEUED)
3. Job assigned unique ID

### Step 4: Background Processing
Every 60 seconds (configurable), background processor:
1. Gets next job from queue
2. Resolves mailing lists for each region
3. Renders bulletin to HTML
4. Sends via SMTP
5. Logs delivery attempt (EMAIL_SENT or EMAIL_FAILED)
6. On success, updates bulletin status to SENT
7. On failure, retries up to 3 times

### Step 5: User Views Audit Trail
User can view complete delivery history:
- When bullet was queued
- Which regions received it
- How many recipients per region
- Success/failure details
- Duration of each operation

---

## Initialization & Configuration

### 1. Initialize Database
```bash
python main.py  # Runs init_database() which creates all tables
```

### 2. Initialize Region Mailing Lists
Automatically runs on startup:
```python
# In main.py __main__ block
# For each region, create mailing list from region.recipients
```

Or manually:
```bash
python init_region_mailing.py
```

### 3. Configure SMTP
Environment variables:
```bash
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_FROM_EMAIL=bulletins@company.com
SMTP_PASSWORD=your_app_password
```

### 4. Configure Region Mailing
Use API or manually set mailing lists:
```bash
PUT /api/regions/1/mailing-list
{
    "to_recipients": ["admin@company.com", "security@company.com"],
    "cc_recipients": ["compliance@company.com"],
    "bcc_recipients": []
}
```

---

## Testing the System

### Test Mode (No Actual Sending)
```json
POST /api/bulletins/123/send
{
    "regions": ["NORAM"],
    "test_mode": true
}
```

In test mode:
- Email is NOT actually sent
- Logged as if sent (for testing audit log)
- Useful for development/testing

### Manual Queue Processing
```bash
POST /api/delivery-queue/process?max_jobs=5
```

### View Audit Trail
```bash
GET /api/bulletins/123/delivery-audit
```

---

## Database Schema

### region_mailing_lists
```sql
CREATE TABLE region_mailing_lists (
    id INTEGER PRIMARY KEY,
    region_id INTEGER UNIQUE,
    to_recipients TEXT NOT NULL,         -- CSV of To addresses
    cc_recipients TEXT,                  -- CSV of Cc addresses
    bcc_recipients TEXT,                 -- CSV of Bcc addresses
    active INTEGER DEFAULT 1,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)
```

### mailing_list_audit
```sql
CREATE TABLE mailing_list_audit (
    id INTEGER PRIMARY KEY,
    region_id INTEGER,
    action TEXT,                        -- CREATED, UPDATED, DELETED
    old_to_list TEXT,
    new_to_list TEXT,
    changed_by TEXT,
    reason TEXT,
    created_at TIMESTAMP
)
```

### audit_logs
```sql
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY,
    action TEXT,                        -- Action type
    actor TEXT,                         -- User/system
    resource_type TEXT,                 -- 'bulletin', 'region', etc.
    resource_id INTEGER,
    details TEXT,                       -- JSON context
    status TEXT,                        -- SUCCESS, FAILURE, PARTIAL
    recipient_count INTEGER,
    region TEXT,
    email_addresses TEXT,               -- CSV of To
    cc_addresses TEXT,                  -- CSV of Cc
    bcc_addresses TEXT,                 -- CSV of Bcc
    attachment_count INTEGER,
    error_message TEXT,
    duration_ms INTEGER,
    created_at TIMESTAMP
)
```

---

## Files Created/Modified

### New Files
- `services/enhanced_delivery_engine.py` - Enhanced delivery with audit logging
- `services/region_mailing_service.py` - Region mailing list management
- `services/audit_logger.py` - Comprehensive audit logging
- `app/api/delivery_routes.py` - Delivery API endpoints
- `init_region_mailing.py` - Initialize region mailing lists

### Modified Files
- `services/email_service.py` - Enhanced HTML template, medium count support
- `main.py` - Integrated enhanced delivery engine and audit logging
- `app/models/bulletin_models.py` - Added actor field, updated preview response
- `requirements.txt` - Added Jinja2 for template rendering

---

## Compliance & Traceability

The delivery engine provides:

1. **Complete Audit Trail**: Every action logged with timestamps
2. **Recipient Tracking**: All To/Cc/Bcc addresses recorded
3. **Success/Failure Reporting**: Clear status for each send
4. **Compliance Reports**: Export audit logs for review
5. **Duration Tracking**: Performance metrics for SLA monitoring
6. **Actor Tracking**: Who initiated each action
7. **Change History**: Track mailing list modifications

---

## Future Enhancements

1. **Scheduling**: Recurring bulletins (daily, weekly, monthly)
2. **Templates**: Multiple email templates per region
3. **Webhooks**: Delivery status callbacks
4. **Email Tracking**: Open/click tracking integration
5. **Distribution Lists**: Dynamic recipient resolution
6. **Encryption**: PGP/S/MIME support
7. **Localization**: Region-specific languages
8. **Delivery Confirmations**: Read receipts

---

## Troubleshooting

### Emails Not Sending
1. Check SMTP configuration
2. Verify mailing lists configured: `GET /api/regions/mailing-lists/all`
3. Check audit logs: `GET /api/audit-logs?action=EMAIL_FAILED`
4. Test mode: Set `test_mode: true` to see what would happen

### Queue Not Processing
1. Check queue status: `GET /api/delivery-queue/status`
2. Manually process: `POST /api/delivery-queue/process`
3. Check logs for engine errors

### Missing Recipients
1. Verify region mailing list: `GET /api/regions/{id}/mailing-list`
2. Check region exists and has recipients
3. Validate email addresses in mailing list

---

## Quick Start

1. **Backend Running**: `python main.py` (port 8000)

2. **Create Bulletin**:
   - Frontend: Fill form and select CVEs
   - API: `POST /api/bulletins` with title, body, regions

3. **Preview**:
   - API: `POST /api/bulletins/{id}/preview`
   - Review HTML and recipient counts

4. **Send**:
   - API: `POST /api/bulletins/{id}/send`
   - Gets job ID for tracking

5. **Monitor**:
   - API: `GET /api/bulletins/{id}/delivery-audit`
   - View complete delivery history

6. **Audit**:
   - API: `GET /api/audit-logs`
   - Export reports for compliance

---

## Version Information

- **Requirement**: 2.4 Bulletin Delivery Engine
- **Implementation Date**: January 27, 2026
- **Database**: SQLite with audit tables
- **Email**: SMTP with HTML templates
- **Authentication**: Per-region mailing lists
- **Logging**: Comprehensive audit trail
