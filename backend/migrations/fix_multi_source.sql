-- Migration: Fix Multi-Source CVE Deduplication
-- Date: 2024-01-26
-- Description: Separate source_primary from sources_secondary to avoid confusion
--              when CVEs are enriched by multiple sources (NVD, CVE.org, etc.)

-- ============================================================================
-- STEP 1: Add new columns for structured source tracking
-- ============================================================================

ALTER TABLE cves ADD COLUMN source_primary TEXT DEFAULT 'NVD';
ALTER TABLE cves ADD COLUMN sources_secondary JSON DEFAULT '[]';

-- ============================================================================
-- STEP 2: Migrate existing data from 'source' column
-- ============================================================================

-- Extract primary source from the 'source' column
-- If source contains comma, take the first one as primary
UPDATE cves 
SET source_primary = CASE 
  -- If source already contains multiple sources separated by comma
  WHEN source LIKE '%,%' THEN 
    CASE 
      WHEN LOWER(SUBSTR(source, 1, INSTR(source, ',') - 1)) LIKE '%nvd%' THEN 'NVD'
      WHEN LOWER(SUBSTR(source, 1, INSTR(source, ',') - 1)) LIKE '%cvedetails%' THEN 'cvedetails'
      WHEN LOWER(SUBSTR(source, 1, INSTR(source, ',') - 1)) LIKE '%cveorg%' THEN 'cveorg'
      WHEN LOWER(SUBSTR(source, 1, INSTR(source, ',') - 1)) LIKE '%msrc%' THEN 'msrc'
      WHEN LOWER(SUBSTR(source, 1, INSTR(source, ',') - 1)) LIKE '%hackuity%' THEN 'hackuity'
      WHEN LOWER(SUBSTR(source, 1, INSTR(source, ',') - 1)) LIKE '%manual%' THEN 'manual'
      ELSE SUBSTR(source, 1, INSTR(source, ',') - 1)
    END
  -- Single source
  WHEN LOWER(source) LIKE '%nvd%' THEN 'NVD'
  WHEN LOWER(source) LIKE '%cvedetails%' THEN 'cvedetails'
  WHEN LOWER(source) LIKE '%cveorg%' THEN 'cveorg'
  WHEN LOWER(source) LIKE '%msrc%' THEN 'msrc'
  WHEN LOWER(source) LIKE '%hackuity%' THEN 'hackuity'
  WHEN LOWER(source) LIKE '%manual%' THEN 'manual'
  WHEN source IS NOT NULL AND source != '' THEN source
  ELSE 'NVD'
END;

-- ============================================================================
-- STEP 3: Build secondary sources from the 'source' column
-- ============================================================================

-- For CVEs with multiple sources, populate sources_secondary
UPDATE cves
SET sources_secondary = CASE
  WHEN source LIKE '%,%' THEN
    -- Build JSON array of secondary sources
    json('['
      || CASE WHEN LOWER(source) LIKE '%cveorg%' AND source_primary != 'cveorg' 
              THEN '{"name":"cveorg","added_at":"' || datetime('now') || '","data_enrichment":"vendor,product"},'
              ELSE '' END
      || CASE WHEN LOWER(source) LIKE '%nvd%' AND source_primary != 'NVD'
              THEN '{"name":"nvd","added_at":"' || datetime('now') || '","data_enrichment":"severity,cvss"},'
              ELSE '' END
      || CASE WHEN LOWER(source) LIKE '%cvedetails%' AND source_primary != 'cvedetails'
              THEN '{"name":"cvedetails","added_at":"' || datetime('now') || '","data_enrichment":"products"},'
              ELSE '' END
      || CASE WHEN LOWER(source) LIKE '%msrc%' AND source_primary != 'msrc'
              THEN '{"name":"msrc","added_at":"' || datetime('now') || '","data_enrichment":"products"},'
              ELSE '' END
      || CASE WHEN LOWER(source) LIKE '%hackuity%' AND source_primary != 'hackuity'
              THEN '{"name":"hackuity","added_at":"' || datetime('now') || '","data_enrichment":"exploitability"},'
              ELSE '' END
      || '{"name":""}]'
    )
  ELSE '[]'
END;

-- Clean up malformed JSON (remove the last empty object)
UPDATE cves
SET sources_secondary = '[]'
WHERE sources_secondary = '[{"name":""}]' OR sources_secondary LIKE '%,"name":""}%';

-- ============================================================================
-- STEP 4: Create indexes for performance
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_cves_source_primary ON cves(source_primary);
CREATE INDEX IF NOT EXISTS idx_cves_sources_secondary ON cves(sources_secondary);

-- ============================================================================
-- STEP 5: Create backward compatibility view
-- ============================================================================

DROP VIEW IF EXISTS v_cves_sources;

CREATE VIEW v_cves_sources AS
SELECT 
  cve_id,
  source_primary as source,
  sources_secondary,
  CASE 
    WHEN json_array_length(sources_secondary) > 0 THEN
      source_primary || ',' || group_concat(json_extract(sources_secondary, '$[' || rownum || '].name'))
    ELSE source_primary
  END as source_combined
FROM cves
LEFT JOIN (
  SELECT rownum FROM (SELECT 0 as rownum UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4)
) ON 1=1
WHERE rownum < json_array_length(sources_secondary) OR json_array_length(sources_secondary) = 0;

-- ============================================================================
-- STEP 6: Create helper function for adding secondary sources
-- ============================================================================

-- SQLite doesn't support stored procedures/functions, so we document the logic
-- in Python instead. See: add_secondary_source() in the import functions

-- ============================================================================
-- STEP 7: Verify migration
-- ============================================================================

-- Show stats
SELECT 
  COUNT(*) as total_cves,
  COUNT(DISTINCT source_primary) as unique_primary_sources,
  SUM(CASE WHEN sources_secondary != '[]' THEN 1 ELSE 0 END) as cves_with_secondary_sources
FROM cves;

-- Show breakdown by primary source
SELECT 
  source_primary,
  COUNT(*) as count,
  SUM(CASE WHEN sources_secondary != '[]' THEN 1 ELSE 0 END) as enriched_count
FROM cves
GROUP BY source_primary
ORDER BY count DESC;

-- ============================================================================
-- STEP 8: Create audit log table for source changes
-- ============================================================================

CREATE TABLE IF NOT EXISTS cve_source_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  old_source_primary TEXT,
  new_source_primary TEXT,
  secondary_source_added TEXT,
  changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  reason TEXT,
  FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cve_source_history_cve_id ON cve_source_history(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_source_history_changed_at ON cve_source_history(changed_at DESC);

-- ============================================================================
-- Done! The migration is complete.
-- ============================================================================
