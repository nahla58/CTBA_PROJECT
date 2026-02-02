-- ============================================================================
-- Enhanced Bulletin Management System
-- Automatic CVE Grouping, Region Management, and Attachment Support
-- ============================================================================

-- ============================================================================
-- REGIONS TABLE (Support for dynamic regions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS bulletin_regions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,          -- NORAM, LATAM, EUROPE, APMEA
    description TEXT,
    recipients TEXT NOT NULL,                   -- JSON array of emails
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    archived_at TIMESTAMP NULL,                 -- Support archiving without deleting
    created_by VARCHAR(100),
    notes TEXT
);

-- ============================================================================
-- BULLETINS TABLE (Core bulletin storage)
-- ============================================================================
CREATE TABLE IF NOT EXISTS bulletins (
    id SERIAL PRIMARY KEY,
    title VARCHAR(300) NOT NULL,
    body TEXT,
    
    -- Content & Status
    status VARCHAR(50) NOT NULL DEFAULT 'DRAFT',  -- DRAFT, SENT, NOT_PROCESSED, ARCHIVED
    
    -- CVE Association
    cve_ids TEXT,                                  -- JSON array of CVE IDs
    
    -- Region & Delivery
    regions TEXT NOT NULL,                         -- JSON array of region names
    delivery_method VARCHAR(50) DEFAULT 'EMAIL',   -- EMAIL, API, BOTH
    
    -- Metadata
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(100),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP NULL,
    sent_by VARCHAR(100),
    
    -- Statistics & Tracking
    cve_count INTEGER DEFAULT 0,
    recipient_count INTEGER DEFAULT 0,
    delivery_status VARCHAR(50) DEFAULT 'PENDING',  -- PENDING, IN_PROGRESS, COMPLETED, FAILED
    
    -- Version Control
    version INTEGER DEFAULT 1,
    parent_bulletin_id INTEGER REFERENCES bulletins(id),  -- For revisions
    
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    INDEX idx_created_by (created_by)
);

-- ============================================================================
-- BULLETIN_CVE_GROUPING TABLE (Store automatic groupings)
-- ============================================================================
CREATE TABLE IF NOT EXISTS bulletin_cve_groupings (
    id SERIAL PRIMARY KEY,
    bulletin_id INTEGER NOT NULL REFERENCES bulletins(id) ON DELETE CASCADE,
    
    -- Grouping criteria
    vendor VARCHAR(200) NOT NULL,
    product VARCHAR(200) NOT NULL,
    
    -- CVE Information
    cve_ids TEXT NOT NULL,                 -- JSON array of CVE IDs in this group
    cve_count INTEGER NOT NULL DEFAULT 0,
    
    -- Remediation guidance (same for all CVEs in group)
    remediation_guidance TEXT,
    remediation_priority VARCHAR(50),      -- CRITICAL, HIGH, MEDIUM, LOW
    
    -- Group metadata
    group_order INTEGER,                   -- Order in bulletin
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(bulletin_id, vendor, product),
    INDEX idx_bulletin_id (bulletin_id),
    INDEX idx_vendor_product (vendor, product)
);

-- ============================================================================
-- BULLETIN_ATTACHMENTS TABLE (Support file attachments)
-- ============================================================================
CREATE TABLE IF NOT EXISTS bulletin_attachments (
    id SERIAL PRIMARY KEY,
    bulletin_id INTEGER NOT NULL REFERENCES bulletins(id) ON DELETE CASCADE,
    
    -- File information
    filename VARCHAR(500) NOT NULL,              -- Original filename
    file_path VARCHAR(1000) NOT NULL,            -- Full path to stored file
    file_size BIGINT,                            -- Size in bytes
    file_type VARCHAR(50),                       -- pdf, doc, zip, etc
    checksum VARCHAR(64),                        -- SHA-256 hash for integrity
    
    -- Metadata
    attachment_type VARCHAR(100),                -- PATCH, GUIDE, CONFIG, EVIDENCE, OTHER
    description TEXT,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    uploaded_by VARCHAR(100),
    
    -- Download tracking
    download_count INTEGER DEFAULT 0,
    last_downloaded TIMESTAMP,
    
    -- Archive support
    is_archived BOOLEAN DEFAULT FALSE,
    archived_at TIMESTAMP NULL,
    archived_by VARCHAR(100),
    
    INDEX idx_bulletin_id (bulletin_id),
    INDEX idx_file_type (file_type),
    INDEX idx_attachment_type (attachment_type)
);

-- ============================================================================
-- BULLETIN_DELIVERY_LOG TABLE (Track delivery to regions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS bulletin_delivery_log (
    id SERIAL PRIMARY KEY,
    bulletin_id INTEGER NOT NULL REFERENCES bulletins(id) ON DELETE CASCADE,
    region_id INTEGER NOT NULL REFERENCES bulletin_regions(id),
    
    -- Delivery details
    recipient_email VARCHAR(255),
    delivery_status VARCHAR(50),           -- PENDING, SENT, FAILED, BOUNCED
    delivery_method VARCHAR(50),           -- EMAIL, API, MANUAL
    
    -- Timestamps
    scheduled_time TIMESTAMP,
    sent_time TIMESTAMP,
    delivery_timestamp TIMESTAMP,
    
    -- Error tracking
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    
    -- Read tracking (if available)
    opened_at TIMESTAMP NULL,
    clicked_links INTEGER DEFAULT 0,
    
    INDEX idx_bulletin_id (bulletin_id),
    INDEX idx_region_id (region_id),
    INDEX idx_delivery_status (delivery_status)
);

-- ============================================================================
-- BULLETIN_TEMPLATES TABLE (Pre-built templates)
-- ============================================================================
CREATE TABLE IF NOT EXISTS bulletin_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL UNIQUE,
    description TEXT,
    body_template TEXT,                    -- Template with {{placeholders}}
    regions TEXT,                          -- Default regions
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    usage_count INTEGER DEFAULT 0,
    
    INDEX idx_is_active (is_active),
    INDEX idx_created_by (created_by)
);

-- ============================================================================
-- BULLETIN_VERSION_HISTORY TABLE (Track all changes)
-- ============================================================================
CREATE TABLE IF NOT EXISTS bulletin_version_history (
    id SERIAL PRIMARY KEY,
    bulletin_id INTEGER NOT NULL REFERENCES bulletins(id) ON DELETE CASCADE,
    
    -- Change tracking
    version_number INTEGER NOT NULL,
    change_type VARCHAR(50),                -- CREATED, UPDATED, SENT, ARCHIVED
    changed_by VARCHAR(100),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Previous values (JSON)
    previous_state TEXT,                    -- JSON snapshot of previous state
    new_state TEXT,                         -- JSON snapshot of new state
    change_reason TEXT,
    
    INDEX idx_bulletin_id (bulletin_id),
    INDEX idx_version_number (bulletin_id, version_number)
);

-- ============================================================================
-- INSERT DEFAULT REGIONS
-- ============================================================================
INSERT INTO bulletin_regions (name, description, recipients, created_by)
VALUES 
    ('NORAM', 'North America region', '[]', 'system'),
    ('LATAM', 'Latin America region', '[]', 'system'),
    ('EUROPE', 'European region', '[]', 'system'),
    ('APMEA', 'Asia Pacific Middle East Africa region', '[]', 'system')
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_bulletins_status_created ON bulletins(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bulletins_regions ON bulletins USING GIN((regions::jsonb));
CREATE INDEX IF NOT EXISTS idx_bulletins_cves ON bulletins USING GIN((cve_ids::jsonb));
CREATE INDEX IF NOT EXISTS idx_grouping_bulletin_vendor ON bulletin_cve_groupings(bulletin_id, vendor, product);

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- View: Bulletins with delivery status
CREATE OR REPLACE VIEW vw_bulletin_status AS
SELECT 
    b.id,
    b.title,
    b.status,
    b.created_at,
    b.sent_at,
    COUNT(DISTINCT bdl.id) as delivery_count,
    SUM(CASE WHEN bdl.delivery_status = 'SENT' THEN 1 ELSE 0 END) as sent_count,
    SUM(CASE WHEN bdl.delivery_status = 'FAILED' THEN 1 ELSE 0 END) as failed_count
FROM bulletins b
LEFT JOIN bulletin_delivery_log bdl ON b.id = bdl.bulletin_id
GROUP BY b.id, b.title, b.status, b.created_at, b.sent_at;

-- View: CVE grouping summary
CREATE OR REPLACE VIEW vw_cve_grouping_summary AS
SELECT 
    bcg.bulletin_id,
    COUNT(*) as group_count,
    SUM(bcg.cve_count) as total_cves,
    STRING_AGG(DISTINCT bcg.vendor || '/' || bcg.product, ', ') as technologies
FROM bulletin_cve_groupings bcg
GROUP BY bcg.bulletin_id;

-- ============================================================================
-- GRANT PERMISSIONS (Uncomment if needed)
-- ============================================================================
-- GRANT SELECT, INSERT, UPDATE ON bulletins TO ctba_user;
-- GRANT SELECT, INSERT, UPDATE ON bulletin_regions TO ctba_user;
-- GRANT SELECT, INSERT ON bulletin_attachments TO ctba_user;
-- GRANT SELECT ON vw_bulletin_status TO ctba_user;
-- GRANT SELECT ON vw_cve_grouping_summary TO ctba_user;
