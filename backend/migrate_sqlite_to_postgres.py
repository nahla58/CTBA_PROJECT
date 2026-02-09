#!/usr/bin/env python3
"""
Script d'export SQLite vers PostgreSQL
Exporte toutes les tables et données de SQLite en format SQL compatible PostgreSQL
"""

import sqlite3
import json
from pathlib import Path

def export_sqlite_to_postgres():
    """Exporte SQLite → SQL PostgreSQL"""
    
    sqlite_db = "ctba_platform.db"
    output_file = "migration_to_postgres.sql"
    
    print(f"\n{'='*70}")
    print("EXPORT SQLite → PostgreSQL SQL")
    print(f"{'='*70}\n")
    
    try:
        # Connecter à SQLite
        conn_sqlite = sqlite3.connect(sqlite_db)
        conn_sqlite.row_factory = sqlite3.Row
        cursor_sqlite = conn_sqlite.cursor()
        
        # Récupérer tous les CREATE TABLE statements
        cursor_sqlite.execute("""
            SELECT name, sql FROM sqlite_master 
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        """)
        
        tables = cursor_sqlite.fetchall()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("-- Migration SQLite to PostgreSQL\n")
            f.write(f"-- Generated from: {sqlite_db}\n")
            f.write("-- Drop existing tables first (if needed)\n\n")
            
            # Drop tables dans l'ordre inverse des dépendances
            f.write("-- DROP TABLE IF EXISTS affected_products CASCADE;\n")
            f.write("-- DROP TABLE IF EXISTS imports_audit CASCADE;\n")
            f.write("-- DROP TABLE IF EXISTS cves CASCADE;\n")
            f.write("-- DROP TABLE IF EXISTS technologies CASCADE;\n")
            f.write("-- DROP TABLE IF EXISTS users CASCADE;\n\n")
            
            # Create tables
            f.write("-- CREATE TABLES\n")
            f.write("-- "+"="*68 + "\n\n")
            
            for table in tables:
                table_name = table['name']
                create_sql = table['sql']
                
                # Adapter le SQL pour PostgreSQL
                adapted_sql = adapt_sqlite_to_postgres(create_sql, table_name)
                f.write(f"-- Table: {table_name}\n")
                f.write(adapted_sql + ";\n\n")
            
            # Export des données
            f.write("\n-- INSERT DATA\n")
            f.write("-- "+"="*68 + "\n\n")
            
            for table in tables:
                table_name = table['name']
                print(f"📊 Exporting {table_name}...", end=" ")
                
                cursor_sqlite.execute(f"SELECT * FROM {table_name}")
                rows = cursor_sqlite.fetchall()
                
                if rows:
                    # Récupérer les noms de colonnes
                    cursor_sqlite.execute(f"PRAGMA table_info({table_name})")
                    columns_info = cursor_sqlite.fetchall()
                    columns = [col[1] for col in columns_info]
                    
                    # Générer INSERT statements
                    for row in rows:
                        values = []
                        for i, col in enumerate(columns):
                            val = row[col]
                            if val is None:
                                values.append("NULL")
                            elif isinstance(val, str):
                                # Échapper les quotes
                                escaped = val.replace("'", "''")
                                values.append(f"'{escaped}'")
                            elif isinstance(val, bool):
                                values.append("TRUE" if val else "FALSE")
                            elif isinstance(val, (int, float)):
                                values.append(str(val))
                            else:
                                # JSON ou autres types
                                escaped = str(val).replace("'", "''")
                                values.append(f"'{escaped}'")
                        
                        cols_str = ", ".join(columns)
                        vals_str = ", ".join(values)
                        f.write(f"INSERT INTO {table_name} ({cols_str}) VALUES ({vals_str});\n")
                    
                    print(f"✅ {len(rows)} rows")
                else:
                    print("(empty)")
            
            f.write("\n-- Migration completed\n")
        
        conn_sqlite.close()
        
        print(f"\n✅ Export réussi: {output_file}")
        print(f"📁 Fichier créé avec succès")
        print(f"\n{'='*70}")
        print("PROCHAINES ÉTAPES:")
        print("1. Installer PostgreSQL")
        print("2. Créer database: createdb ctba_platform")
        print("3. Importer le SQL: psql ctba_platform < migration_to_postgres.sql")
        print(f"{'='*70}\n")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        return False

def adapt_sqlite_to_postgres(sql, table_name):
    """Adapte le SQL SQLite pour PostgreSQL"""
    
    # Cas spéciaux par table
    if table_name == "users":
        return """CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)"""
    
    elif table_name == "technologies":
        return """CREATE TABLE technologies (
    id SERIAL PRIMARY KEY,
    vendor VARCHAR(100) NOT NULL,
    product VARCHAR(100) NOT NULL,
    version VARCHAR(50),
    status VARCHAR(50) DEFAULT 'PENDING',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vendor, product)
)"""
    
    elif table_name == "cves":
        return """CREATE TABLE cves (
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
)"""
    
    elif table_name == "affected_products":
        return """CREATE TABLE affected_products (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    vendor VARCHAR(100) NOT NULL,
    product VARCHAR(100) NOT NULL,
    confidence DECIMAL(3,2) DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
)"""
    
    elif table_name == "imports_audit":
        return """CREATE TABLE imports_audit (
    id SERIAL PRIMARY KEY,
    import_source VARCHAR(50) NOT NULL,
    imported_count INTEGER DEFAULT 0,
    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20),
    details TEXT
)"""
    
    # Fallback: conversion basique
    sql = sql.replace("AUTOINCREMENT", "")
    sql = sql.replace("INTEGER PRIMARY KEY", "SERIAL PRIMARY KEY")
    return sql

if __name__ == "__main__":
    export_sqlite_to_postgres()
