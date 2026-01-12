# reset_database.py
import sqlite3
import os

def reset_database():
    print("🔄 RÉINITIALISATION COMPLÈTE DE LA BASE DE DONNÉES")
    
    # 1. Fermer toutes les connexions
    try:
        import sqlite3
        sqlite3.connect("ctba.db").close()
    except:
        pass
    
    # 2. Supprimer l'ancien fichier
    if os.path.exists("ctba.db"):
        os.remove("ctba.db")
        print("🗑️  Ancienne base supprimée")
    
    # 3. Recréer avec le bon schéma
    conn = sqlite3.connect("ctba.db")
    cursor = conn.cursor()
    
    # Table CVE (CORRECTE - sans last_modified)
    cursor.execute('''
        CREATE TABLE cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
            cvss_score REAL,
            published_date TEXT,
            status TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'VALIDATED', 'REJECTED', 'REVIEWED')),
            imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            analyst TEXT
        )
    ''')
    
    # Table Technologies
    cursor.execute('''
        CREATE TABLE technologies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('OUT_OF_SCOPE', 'PRIORITY', 'NORMAL')),
            added_by TEXT DEFAULT 'system',
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(vendor, product)
        )
    ''')
    
    # Table Produits affectés
    cursor.execute('''
        CREATE TABLE affected_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            cpe_uri TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
        )
    ''')
    
    # Table Décisions
    cursor.execute('''
        CREATE TABLE decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            decision TEXT NOT NULL CHECK(decision IN ('VALIDATED', 'REJECTED')),
            analyst TEXT NOT NULL,
            comments TEXT,
            decision_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
        )
    ''')
    
    # Table Audit des imports (CORRECTE - avec source)
    cursor.execute('''
        CREATE TABLE imports_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source TEXT DEFAULT 'NVD',
            cves_found INTEGER,
            cves_added INTEGER,
            cves_skipped INTEGER,
            duration_seconds REAL
        )
    ''')
    
    # Index
    cursor.execute('CREATE INDEX idx_cve_status ON cves(status)')
    cursor.execute('CREATE INDEX idx_cve_severity ON cves(severity)')
    cursor.execute('CREATE INDEX idx_tech_status ON technologies(status)')
    cursor.execute('CREATE INDEX idx_cve_imported ON cves(imported_at DESC)')
    
    # Données par défaut
    default_technologies = [
        ('Oracle', 'Java SE', 'OUT_OF_SCOPE', 'system', 'Pas utilisé'),
        ('Adobe', 'Flash Player', 'OUT_OF_SCOPE', 'system', 'Déprécié'),
        ('Microsoft', 'Windows Server', 'PRIORITY', 'system', 'Serveurs critiques'),
        ('Linux', 'Kernel', 'PRIORITY', 'system', 'Infrastructure cœur'),
        ('Apache', 'HTTP Server', 'PRIORITY', 'system', 'Serveurs web'),
        ('Nginx', 'Nginx', 'PRIORITY', 'system', 'Reverse proxy'),
        ('Microsoft', 'Windows 10', 'NORMAL', 'system', 'Postes travail'),
        ('Microsoft', 'Windows 11', 'NORMAL', 'system', 'Postes travail'),
        ('Microsoft', 'Office', 'NORMAL', 'system', 'Suite bureautique'),
        ('Mozilla', 'Firefox', 'NORMAL', 'system', 'Navigateur'),
        ('Google', 'Chrome', 'NORMAL', 'system', 'Navigateur'),
        ('Docker', 'Docker', 'NORMAL', 'system', 'Conteneurisation'),
        ('Kubernetes', 'Kubernetes', 'NORMAL', 'system', 'Orchestration'),
    ]
    
    for vendor, product, status, added_by, reason in default_technologies:
        cursor.execute('''
            INSERT INTO technologies (vendor, product, status, added_by, reason)
            VALUES (?, ?, ?, ?, ?)
        ''', (vendor, product, status, added_by, reason))
    
    # CVE de test
    from datetime import datetime, timezone
    test_date = datetime.now(timezone.utc).isoformat()
    cursor.execute('''
        INSERT INTO cves (cve_id, description, severity, cvss_score, published_date, status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        "CVE-2024-99999",
        "CVE de test pour démonstration",
        "HIGH",
        7.5,
        test_date,
        "PENDING"
    ))
    
    conn.commit()
    conn.close()
    
    print("✅ Base recréée avec succès!")
    print("📊 Contenu initial:")
    print("   • 13 technologies (OUT_OF_SCOPE/PRIORITY/NORMAL)")
    print("   • 1 CVE de test")
    print("   • Schéma complet et correct")

if __name__ == "__main__":
    reset_database()