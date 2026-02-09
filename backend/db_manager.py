#!/usr/bin/env python3
"""
Database Connection Manager
Supporte SQLite ET PostgreSQL avec la même interface
"""

import os
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

load_dotenv()

# Configuration
DB_TYPE = os.getenv('DB_TYPE', 'sqlite').lower()
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///ctba_platform.db')

def get_db_connection():
    """
    Retourne une connexion à la base de données.
    Supporte SQLite et PostgreSQL automatiquement.
    """
    
    if DB_TYPE == 'postgresql' or 'postgresql://' in DATABASE_URL:
        return get_postgres_connection()
    else:
        return get_sqlite_connection()

def get_sqlite_connection():
    """Connexion SQLite (développement local)"""
    import sqlite3
    
    db_path = 'ctba_platform.db'
    logger.info(f"📁 Connexion SQLite: {db_path}")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    
    return conn

def get_postgres_connection():
    """Connexion PostgreSQL (production cloud)"""
    import psycopg2
    from psycopg2.extras import RealDictCursor
    
    # Parser DATABASE_URL ou utiliser les variables séparées
    if DATABASE_URL and DATABASE_URL.startswith('postgresql://'):
        # Format: postgresql://user:password@host:port/database
        try:
            conn = psycopg2.connect(DATABASE_URL)
        except Exception as e:
            logger.error(f"❌ Erreur connexion PostgreSQL avec DATABASE_URL: {e}")
            raise
    else:
        # Variables séparées
        host = os.getenv('DB_HOST', 'localhost')
        port = os.getenv('DB_PORT', '5432')
        database = os.getenv('DB_NAME', 'ctba_platform')
        user = os.getenv('DB_USER', 'ctba_user')
        password = os.getenv('DB_PASSWORD', 'ctba_password123')
        
        logger.info(f"🐘 Connexion PostgreSQL: {user}@{host}:{port}/{database}")
        
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password
            )
        except Exception as e:
            logger.error(f"❌ Erreur connexion PostgreSQL: {e}")
            raise
    
    # Utiliser RealDictCursor pour une interface similaire à sqlite3.Row
    conn.cursor_factory = RealDictCursor
    
    return conn

def init_database():
    """
    Initialise la base de données.
    Compatible SQLite ET PostgreSQL.
    """
    
    logger.info(f"🗄️ Initialisation database ({DB_TYPE})...")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Table users
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'analyst',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 2. Table technologies
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS technologies (
                id SERIAL PRIMARY KEY,
                vendor VARCHAR(100) NOT NULL,
                product VARCHAR(100) NOT NULL,
                version VARCHAR(50),
                status VARCHAR(50) DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(vendor, product)
            )
        """)
        
        # 3. Table cves
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(20) UNIQUE NOT NULL,
                description TEXT,
                severity VARCHAR(20),
                cvss_score DECIMAL(4,1),
                cvss_version VARCHAR(10),
                published_date TIMESTAMP,
                status VARCHAR(20) DEFAULT 'PENDING',
                imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                analyst VARCHAR(100),
                source VARCHAR(100),
                CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))
            )
        """)
        
        # 4. Table affected_products
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS affected_products (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(20) NOT NULL,
                vendor VARCHAR(100) NOT NULL,
                product VARCHAR(100) NOT NULL,
                confidence DECIMAL(3,2) DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
            )
        """)
        
        # 5. Table imports_audit
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS imports_audit (
                id SERIAL PRIMARY KEY,
                import_source VARCHAR(50) NOT NULL,
                imported_count INTEGER DEFAULT 0,
                imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(20),
                details TEXT
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("✅ Database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print(f"\n{'='*70}")
    print(f"DATABASE CONFIGURATION")
    print(f"{'='*70}")
    print(f"Type: {DB_TYPE.upper()}")
    print(f"URL: {DATABASE_URL if 'password' not in DATABASE_URL else DATABASE_URL.replace(':password', ':***')}")
    print(f"{'='*70}\n")
    
    # Test connexion
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        print("✅ Database connection successful!")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
