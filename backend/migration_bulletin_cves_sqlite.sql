-- Migration SQLite pour bulletin_cves
-- Simplifié pour SQLite (pas de ALTER TABLE IF NOT EXISTS, pas de SERIAL)

-- Créer la table bulletin_cves
CREATE TABLE IF NOT EXISTS bulletin_cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bulletin_id INTEGER NOT NULL,
    cve_id VARCHAR(20) NOT NULL,
    group_id VARCHAR(50),
    vendor VARCHAR(100),
    product VARCHAR(100),
    remediation_guidance TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bulletin_id) REFERENCES bulletins(id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    UNIQUE(bulletin_id, cve_id)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_bulletin_cves_bulletin ON bulletin_cves(bulletin_id);
CREATE INDEX IF NOT EXISTS idx_bulletin_cves_cve ON bulletin_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_bulletin_cves_group ON bulletin_cves(group_id);
CREATE INDEX IF NOT EXISTS idx_bulletin_cves_technology ON bulletin_cves(vendor, product);
