"""
Database connection module
Provides centralized database connection for all services
"""
import sqlite3
import os

# Database file path
DB_FILE = "ctba_platform.db"

def get_db_connection():
    """
    Get database connection with proper configuration
    
    Returns:
        sqlite3.Connection: Configured database connection
    """
    # Allow longer timeout and multithreaded access since importers run in background
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    
    try:
        # Set busy timeout to reduce 'database is locked' errors
        conn.execute('PRAGMA busy_timeout = 30000')
        # Enable WAL journal mode to improve concurrency
        conn.execute('PRAGMA journal_mode = WAL')
    except Exception:
        pass
    
    return conn