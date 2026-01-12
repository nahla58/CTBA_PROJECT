"""
CTBA Platform - Backend API
Compatible avec CVElist.js React frontend - INTELLIGENT PRODUCT EXTRACTION
"""
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query, Header
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import sqlite3
import requests
import schedule
import time
import threading
import uvicorn
import logging
import json
import re
import os
import hashlib
import binascii
import jwt

# ========== CONFIGURATION ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DB_FILE = "ctba_platform.db"

# Authentication / JWT configuration
SECRET_KEY = os.environ.get('CTBA_SECRET') or 'change-me-please'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

def _hash_password(password: str) -> tuple:
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

def _verify_password(stored_salt_hex: str, stored_hash_hex: str, password: str) -> bool:
    salt = binascii.unhexlify(stored_salt_hex.encode())
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(dk).decode() == stored_hash_hex

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid token')

# Importer configuration per source
SOURCE_CONFIG = {
    'NVD': {
        'min_severity': ['MEDIUM', 'HIGH', 'CRITICAL']
    },
    'CVE_DETAILS': {
        'min_severity': ['HIGH', 'CRITICAL']
    }
}

# Simple import metrics
IMPORT_METRICS = {
    'nvd_imported': 0,
    'nvd_skipped_blacklist': 0,
    'cved_imported': 0,
    'cved_skipped_blacklist': 0
}
# ========== DATA MODELS ==========
class CVESeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class CVEStatus(str, Enum):
   
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    

class TechnologyStatus(str, Enum):
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    PRIORITY = "PRIORITY"
    NORMAL = "NORMAL"

class CVEActionRequest(BaseModel):
    action: CVEStatus
    analyst: str
    comments: str = ""
    priority: str = "NORMAL"
    assign_to: Optional[str] = None

class TechnologyCreate(BaseModel):
    vendor: str
    product: str
    status: TechnologyStatus
    reason: str = ""
    added_by: str = "analyst"

# ========== DATABASE MANAGER ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager pour FastAPI"""
    # Startup
    logger.info("Starting CTBA Platform API...")
    init_database()
    # Start import immediately
    threading.Thread(target=import_from_nvd, daemon=True).start()
    start_import_scheduler()
    logger.info("CTBA Platform API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down CTBA Platform API...")

app = FastAPI(
    title="CTBA Platform API",
    description="CVE Management System with Dynamic Blacklist",
    version="7.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# CORS configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db_connection():
    """Database connection"""
    # Allow longer timeout and multithreaded access since importers run in background
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        # Set busy timeout to reduce 'database is locked' errors
        conn.execute('PRAGMA busy_timeout = 30000')
    except Exception:
        pass
    return conn

def init_database():
    """Initialize database with all required tables"""
    logger.info("Initializing database...")
    
    conn = get_db_connection()
    # Enable WAL journal mode to improve concurrency (readers won't block writers)
    try:
        conn.execute('PRAGMA journal_mode = WAL')
    except Exception:
        pass
    cursor = conn.cursor()
    
    # Technologies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS technologies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('OUT_OF_SCOPE', 'PRIORITY', 'NORMAL')),
            added_by TEXT DEFAULT 'system',
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            UNIQUE(vendor, product)
        )
    ''')
    
    # CVEs main table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
            cvss_score REAL,
            published_date TEXT,
            status TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'DEFERRED')),
            analyst TEXT,
            decision_date TIMESTAMP,
            decision_comments TEXT,
            imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source TEXT DEFAULT 'NVD'
        )
    ''')
    
    # Affected products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS affected_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            confidence REAL DEFAULT 0.0,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ap_cve_id ON affected_products(cve_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_status ON cves(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date DESC)')
    
    # CVE actions log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            action TEXT CHECK(action IN ('ACCEPTED', 'REJECTED', 'DEFERRED')),
            analyst TEXT NOT NULL,
            comments TEXT,
            action_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
        )
    ''')

    # Regions table (mailing lists per region)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS regions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            recipients TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Bulletins table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bulletins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT,
            regions TEXT,
            status TEXT DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','SENT','NOT_PROCESSED')),
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sent_at TIMESTAMP,
            last_reminder INTEGER DEFAULT 0
        )
    ''')

    # Bulletin attachments
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bulletin_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bulletin_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            path TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (bulletin_id) REFERENCES bulletins(id) ON DELETE CASCADE
        )
    ''')

    # Bulletin logs (send, reminder, escalation)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bulletin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bulletin_id INTEGER NOT NULL,
            action TEXT,
            region TEXT,
            recipients TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (bulletin_id) REFERENCES bulletins(id) ON DELETE CASCADE
        )
    ''')

    # Users table for simple role enforcement
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT,
            password_salt TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed default users (if none exist)
    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    cnt = cursor.fetchone()[0]
    if cnt == 0:
        # Seed default users with generated password hashes
        salt, h = _hash_password('adminpass')
        cursor.execute("INSERT INTO users (username, role, password_hash, password_salt) VALUES (?, ?, ?, ?)", ('admin', 'ADMIN', h, salt))
        salt2, h2 = _hash_password('l1pass')
        cursor.execute("INSERT INTO users (username, role, password_hash, password_salt) VALUES (?, ?, ?, ?)", ('l1_analyst', 'VOC_L1', h2, salt2))
        conn.commit()
    
    conn.commit()
    conn.close()
    
    logger.info("Database initialized successfully")

    # Ensure new columns exist for older DBs
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(affected_products)")
        cols = [r[1] for r in cur.fetchall()]
        if 'confidence' not in cols:
            cur.execute('ALTER TABLE affected_products ADD COLUMN confidence REAL DEFAULT 0.0')
            conn.commit()
        conn.close()
    except Exception:
        pass

# ========== INTELLIGENT PRODUCT EXTRACTION ==========
def extract_vendor_product_from_cpe(cpe_uri: str):
    """Extract vendor and product from CPE URI"""
    try:
        if not cpe_uri or not isinstance(cpe_uri, str):
            return None, None

        # Common forms: cpe:2.3:<part>:<vendor>:<product>:...  OR cpe:/<part>:<vendor>:<product>
        if cpe_uri.startswith('cpe:'):
            parts = cpe_uri.split(':')
            # cpe:2.3:a:vendor:product:...
            if len(parts) >= 5:
                vendor_raw = parts[3]
                product_raw = parts[4]
            elif len(parts) >= 4:
                vendor_raw = parts[2]
                product_raw = parts[3]
            else:
                return None, None

            vendor = re.sub(r'[^A-Za-z0-9\-_\. ]', ' ', vendor_raw).replace('_', ' ').strip()
            product = re.sub(r'[^A-Za-z0-9\-_\. ]', ' ', product_raw).replace('_', ' ').strip()

            if not vendor or vendor in ['-', '*', '', '~'] or not product or product in ['-', '*', '', '~']:
                return None, None

            return vendor.title(), product.title()

        # Fallback: try to extract last two path segments
        m = re.search(r'([^/]+)/([^/]+)$', cpe_uri)
        if m:
            vendor = m.group(1).replace('_', ' ').strip()
            product = m.group(2).replace('_', ' ').strip()
            return vendor.title(), product.title()
    except Exception:
        pass
    return None, None

def is_valid_product_name(text: str) -> bool:
    """Check if text looks like a valid product name"""
    if not text or len(text) < 2:
        return False
    
    text_lower = text.lower()
    
    # Common words that are NOT product names
    not_product_words = [
        'the', 'a', 'an', 'in', 'of', 'for', 'and', 'or', 'but', 'with', 'from',
        'to', 'by', 'on', 'at', 'as', 'is', 'was', 'are', 'were', 'be', 'been',
        'being', 'have', 'has', 'had', 'do', 'does', 'did', 'can', 'could',
        'will', 'would', 'shall', 'should', 'may', 'might', 'must', 'that',
        'this', 'these', 'those', 'which', 'what', 'who', 'whom', 'whose',
        'where', 'when', 'why', 'how', 'all', 'any', 'some', 'no', 'none',
        'every', 'each', 'both', 'either', 'neither', 'such', 'same', 'other',
        'another', 'only', 'very', 'just', 'also', 'even', 'still', 'already',
        'yet', 'so', 'too', 'then', 'now', 'here', 'there', 'when', 'why',
        'how', 'up', 'down', 'out', 'off', 'over', 'under', 'again', 'further',
        'then', 'once', 'here', 'there', 'when', 'always', 'never', 'often',
        'sometimes', 'usually', 'rarely', 'seldom', 'just', 'only', 'also',
        'even', 'especially', 'particularly', 'specifically', 'generally',
        'usually', 'normally', 'typically', 'commonly', 'frequently',
        'occasionally', 'rarely', 'seldom', 'never', 'always', 'constantly',
        'continuously', 'permanently', 'temporarily', 'briefly', 'suddenly',
        'immediately', 'instantly', 'quickly', 'slowly', 'rapidly', 'gradually',
        'eventually', 'finally', 'ultimately', 'initially', 'originally',
        'previously', 'formerly', 'currently', 'presently', 'recently',
        'lately', 'soon', 'later', 'earlier', 'before', 'after', 'during',
        'while', 'since', 'until', 'till', 'because', 'although', 'though',
        'unless', 'except', 'besides', 'despite', 'regardless', 'otherwise',
        'therefore', 'thus', 'hence', 'consequently', 'accordingly',
        'however', 'nevertheless', 'nonetheless', 'meanwhile', 'furthermore',
        'moreover', 'besides', 'additionally', 'also', 'too', 'as well',
        'instead', 'rather', 'alternatively', 'likewise', 'similarly',
        'conversely', 'oppositely', 'contrarily', 'otherwise', 'else',
        'somewhere', 'anywhere', 'everywhere', 'nowhere', 'somehow',
        'anyhow', 'everyhow', 'nohow', 'somewhat', 'anywhat', 'everywhat',
        'nowhat', 'someone', 'anyone', 'everyone', 'no one', 'something',
        'anything', 'everything', 'nothing', 'somebody', 'anybody',
        'everybody', 'nobody', 'somewhere', 'anywhere', 'everywhere',
        'nowhere', 'sometime', 'anytime', 'every time', 'no time',
        'somehow', 'anyhow', 'everyhow', 'nohow', 'somewhat', 'anywhat',
        'everywhat', 'nowhat', 'someway', 'anyway', 'everyway', 'noway'
    ]
    
    # Check if text contains any of the not-product words
    words = text_lower.split()
    for word in words:
        if word in not_product_words:
            return False
    
    # Check for common patterns that are NOT product names
    bad_patterns = [
        r'^[a-z]\s+',
        r'\s+[a-z]\s+',
        r'\b(?:vulnerability|vulnerable|security|flaw|issue|problem|bug|exploit|attack|threat|risk)\b',
        r'\b(?:allows|enables|permits|lets|causes|leads|results|triggers)\b',
        r'\b(?:before|after|during|when|while|since|until)\b',
        r'\b(?:version|v\d+|\.\d+|\d+\.\d+)\b',
        r'\b(?:up to|through|before|after|from|to)\b',
    ]
    
    for pattern in bad_patterns:
        if re.search(pattern, text_lower):
            return False
    
    # Check for product-like patterns
    good_patterns = [
        r'^[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*$',  # Capitalized words
        r'\b(?:UI|API|CMS|LLM|IoT|PDF|SQL|SSL|TLS|HTTP|HTTPS|HCI|SDK|IDE|CLI|GUI)\b',
        r'\b(?:Windows|Linux|Apache|WordPress|Java|Python|Ruby|Go|Rust|MySQL|PostgreSQL)\b',
        r'\b(?:Chrome|Firefox|Safari|Edge|Android|iOS|macOS|Windows)\b',
        r'\b(?:Docker|Kubernetes|Node\.js|React|Angular|Vue|Nginx|IIS)\b',
        r'^[A-Za-z]+(?:-[A-Za-z]+)+$',  # Hyphenated names
    ]
    
    for pattern in good_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    # Minimum length and character requirements
    if len(text) < 3 or len(text) > 50:
        return False
    
    # Should contain at least one letter
    if not re.search(r'[A-Za-z]', text):
        return False
    
    return True

def extract_product_from_description(description: str) -> tuple:
    """
    Intelligently extract vendor and product from description
    Returns: (vendor, product) or (None, None)
    """
    if not description:
        return None, None
    
    # Common vendor-product mappings
    vendor_product_map = {
        'wordpress': ('WordPress', 'Plugin'),
        'apache': ('Apache', 'HTTP Server'),
        'linux': ('Linux', 'Kernel'),
        'windows': ('Microsoft', 'Windows'),
        'android': ('Google', 'Android'),
        'ios': ('Apple', 'iOS'),
        'macos': ('Apple', 'macOS'),
        'java': ('Oracle', 'Java'),
        'python': ('Python', 'Software'),
        'docker': ('Docker', 'Engine'),
        'kubernetes': ('Kubernetes', 'Cluster'),
        'nginx': ('Nginx', 'Web Server'),
        'mysql': ('Oracle', 'MySQL'),
        'postgresql': ('PostgreSQL', 'Database'),
        'mongodb': ('MongoDB', 'Database'),
        'redis': ('Redis', 'Database'),
        'node.js': ('Node.js', 'Runtime'),
        'react': ('Facebook', 'React'),
        'angular': ('Google', 'Angular'),
        'vue': ('Vue.js', 'Framework'),
        'rustcrypto': ('RustCrypto', 'Elliptic Curves'),
        'rustcrypto: elliptic curves': ('RustCrypto', 'Elliptic Curves'),
        'aws sdk': ('Amazon', 'AWS SDK for .NET'),
        'aws sdk for .net': ('Amazon', 'AWS SDK for .NET'),
    }
    
    # Check for known software in description
    description_lower = description.lower()
    for keyword, (vendor, product) in vendor_product_map.items():
        if keyword in description_lower:
            return vendor, product
    
    # Pattern 1: Look for "in [software]" pattern
    pattern1 = r'\bin\s+([A-Z][A-Za-z0-9\s&\.\-]+?)\s+(?:before|through|up\s+to|version|v\d+|\.\d+|plugin|extension|tool|framework|library|system|software|application)'
    match1 = re.search(pattern1, description, re.IGNORECASE)
    if match1:
        software = match1.group(1).strip()
        if is_valid_product_name(software):
            # Try to split into vendor and product
            words = software.split()
            if len(words) >= 2:
                vendor = words[0]
                product = ' '.join(words[1:])
            else:
                vendor = "Unknown"
                product = software
            return vendor, product

    # New Pattern: Look for 'Vendor: Product' or 'Vendor - Product' style mentions
    pattern_vp = r'([A-Za-z0-9& ]{2,60})\s*[:\-]\s*([A-Za-z0-9&\.\- ]{2,80})'
    match_vp = re.search(pattern_vp, description)
    if match_vp:
        vendor_candidate = match_vp.group(1).strip()
        product_candidate = match_vp.group(2).strip()
        # Filter out cases where left side is generic words and ensure product_candidate looks like a product
        if is_valid_product_name(product_candidate) and not re.search(r'\b(issue|vulnerability|vulnerable|attack|exploit|CVE|CPE|this|that|there)\b', vendor_candidate, re.IGNORECASE):
            vendor_lower = vendor_candidate.lower()
            # If vendor part matches a known mapping, use mapping
            if vendor_lower in vendor_product_map:
                return vendor_product_map[vendor_lower]
            # If product_candidate looks like a sentence (has verbs), reject
            if re.search(r'\b(allows|enables|introduces|causes|leads|results|allows)\b', product_candidate, re.IGNORECASE):
                pass
            else:
                return vendor_candidate, product_candidate
    
    # Pattern 2: Look for "[software] plugin/extension/tool"
    pattern2 = r'\b([A-Z][A-Za-z0-9\s&\.\-]+?)\s+(?:plugin|extension|tool|framework|library|system|software|application|driver|module|package|component)'
    match2 = re.search(pattern2, description, re.IGNORECASE)
    if match2:
        software = match2.group(1).strip()
        if is_valid_product_name(software):
            words = software.split()
            if len(words) >= 2:
                vendor = words[0]
                product = ' '.join(words[1:])
            else:
                vendor = "Unknown"
                product = software
            return vendor, product
    
    # Pattern 3: Look for specific product mentions
    products_to_find = [
        'QuestDB', 'QuickJS', 'LIEF', 'NimBLE', 'Sangfor', 'HAX', 'ComfyUI',
        'vLLM', 'Cosign', 'virtualenv', 'HarfBuzz', 'filelock', 'DevToys',
        'Mailpit', 'pypdf', 'XWiki', 'WeKnora', 'Spree', 'Angular', 'October',
        'Ghost', 'React Router', 'WooCommerce'
    ]
    
    for product_name in products_to_find:
        if product_name.lower() in description_lower:
            # Try to determine vendor
            vendor = "Unknown"
            if product_name == 'QuestDB':
                vendor = 'QuestDB'
            elif product_name == 'QuickJS':
                vendor = 'QuickJS'
            elif product_name == 'LIEF':
                vendor = 'LIEF Project'
            elif product_name == 'NimBLE':
                vendor = 'Apache'
            elif product_name == 'Sangfor':
                vendor = 'Sangfor'
            elif product_name == 'HAX':
                vendor = 'HAX'
            elif product_name == 'ComfyUI':
                vendor = 'ComfyUI'
            elif product_name == 'vLLM':
                vendor = 'vLLM'
            elif product_name == 'Cosign':
                vendor = 'Sigstore'
            elif product_name == 'virtualenv':
                vendor = 'Python'
            elif product_name == 'HarfBuzz':
                vendor = 'HarfBuzz'
            elif product_name == 'filelock':
                vendor = 'Python'
            elif product_name == 'DevToys':
                vendor = 'DevToys'
            elif product_name == 'Mailpit':
                vendor = 'Mailpit'
            elif product_name == 'pypdf':
                vendor = 'PyPDF'
            elif product_name == 'XWiki':
                vendor = 'XWiki'
            elif product_name == 'WeKnora':
                vendor = 'Tencent'
            elif product_name == 'Spree':
                vendor = 'Spree Commerce'
            elif product_name == 'Angular':
                vendor = 'Google'
            elif product_name == 'October':
                vendor = 'OctoberCMS'
            elif product_name == 'Ghost':
                vendor = 'Ghost'
            elif product_name == 'React Router':
                vendor = 'React Router'
            elif product_name == 'WooCommerce':
                vendor = 'WooCommerce'
            
            return vendor, product_name
    
    return None, None

def clean_vendor_product(vendor: str, product: str) -> tuple:
    """Clean and format vendor and product names"""
    if not vendor or vendor.lower() == 'unknown':
        vendor = "Unknown"
    
    if not product or product.lower() == 'unknown':
        product = "Multiple Products"
    
    # Remove version numbers and common suffixes from product
    product = re.sub(r'\s+v\d+\.?\d*.*$', '', product, flags=re.IGNORECASE)
    product = re.sub(r'\s+\d+\.\d+.*$', '', product)
    product = re.sub(r'\s+(?:before|through|up\s+to|version|vulnerability|vulnerable|allows|enables|plugin|extension|tool|framework|library|system|software|application|driver|component|feature|module|package).*$', '', product, flags=re.IGNORECASE)
    
    # Clean up whitespace
    vendor = re.sub(r'\s+', ' ', vendor).strip()
    product = re.sub(r'\s+', ' ', product).strip()
    
    # Format vendor
    if vendor and vendor != "Unknown":
        if vendor.isupper() or vendor.islower():
            vendor = vendor.title()
        if vendor.lower() == 'the':
            vendor = "Unknown"
    
    # Format product
    if product and product != "Multiple Products":
        if product.isupper() or product.islower():
            product = product.title()
        
        # Handle special cases
        if product.lower() == 'ui':
            product = 'UI'
        elif product.lower() == 'api':
            product = 'API'
        elif product.lower() == 'cms':
            product = 'CMS'
        elif product.lower() == 'llm':
            product = 'LLM'
        
        # Shorten if too long
        if len(product) > 40:
            product = product[:37] + "..."
    
    return vendor, product

def get_products_for_cve(cve_data: Dict) -> List[Dict[str, str]]:
    """
    Extract a list of affected products (vendor/product) from CVE data.
    Prioritizes CPE data (walks nodes recursively) and falls back to description.
    Returns list of unique {'vendor':..., 'product':...} dicts.
    """
    products = set()

    def walk_nodes(nodes):
        for node in nodes:
            # cpeMatch entries
            for match in node.get('cpeMatch', []) or []:
                uri = match.get('cpe23Uri') or match.get('criteria') or match.get('criteria')
                if uri:
                    vendor, product = extract_vendor_product_from_cpe(uri)
                    if vendor and product:
                        vendor, product = clean_vendor_product(vendor, product)
                        if product and product != 'Multiple Products':
                            products.add((vendor, product))

            # sometimes node itself has a criteria
            crit = node.get('criteria')
            if crit and (crit.startswith('cpe:') or 'cpe:' in crit):
                vendor, product = extract_vendor_product_from_cpe(crit)
                if vendor and product:
                    vendor, product = clean_vendor_product(vendor, product)
                    if product and product != 'Multiple Products':
                        products.add((vendor, product))

            # recurse children
            children = node.get('children', [])
            if children:
                walk_nodes(children)

    # Extract from configurations
    configurations = cve_data.get('configurations', []) or []
    for config in configurations:
        nodes = config.get('nodes', []) or []
        walk_nodes(nodes)

    # If none found, try description-based heuristic (single fallback)
    if not products:
        description = ""
        for desc in cve_data.get('descriptions', []) or []:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        if description:
            vendor, product = extract_product_from_description(description)
            # be stricter: only accept if product looks like a valid product name
            if vendor and product and is_valid_product_name(product):
                vendor, product = clean_vendor_product(vendor, product)
                if product and product != 'Multiple Products':
                    products.add((vendor, product))

    # Final fallback to Unknown if still empty
    if not products:
        products.add(('Unknown', 'Multiple Products'))

    result = []
    # Assign a simple confidence score heuristic: prefer CPE matches (1.0), description matches (0.6)
    for v, p in products:
        confidence = 0.5
        # Heuristic: if vendor not Unknown and product not 'Multiple Products'
        if v and v != 'Unknown' and p and p != 'Multiple Products':
            confidence = 1.0
        result.append({'vendor': v, 'product': p, 'confidence': confidence})
    return result

# ========== IMPORT SERVICES ==========
def import_from_nvd():
    """Import CVEs from NVD API"""
    logger.info("🚀 Starting NVD import with intelligent product extraction...")
    start_time = time.time()
    
    try:
        # Import from last 24 hours
        start_date = datetime.now() - timedelta(hours=24)
        end_date = datetime.now()
        
        logger.info(f"📅 Import period: {start_date} to {end_date}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "resultsPerPage": 50
        }
        
        logger.info("📡 Fetching CVEs from NVD...")
        response = requests.get(base_url, params=params, timeout=60)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get('vulnerabilities', [])
        logger.info(f"📊 Found {len(vulnerabilities)} vulnerabilities")
        
        imported = 0
        for vuln in vulnerabilities:
            try:
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                if not cve_id:
                    continue
                
                # Skip if already exists
                cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
                if cursor.fetchone():
                    continue
                
                # Extract description
                description = ""
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Extract severity and CVSS
                severity = "MEDIUM"
                score = 5.0
                
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    score = cvss_data.get('baseScore', 5.0)
                    base_severity = cvss_data.get('baseSeverity', 'MEDIUM')
                    if base_severity:
                        severity = base_severity.upper()
                elif 'cvssMetricV30' in metrics:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    score = cvss_data.get('baseScore', 5.0)
                    base_severity = cvss_data.get('baseSeverity', 'MEDIUM')
                    if base_severity:
                        severity = base_severity.upper()
                elif 'cvssMetricV2' in metrics:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    score = cvss_data.get('baseScore', 5.0)
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                
                # Extract published date
                published_date = cve_data.get('published', '')
                if published_date:
                    published_date = published_date.replace('T', ' ').split('.')[0]
                
                # Get products list (may contain multiple vendor/product tuples)
                product_list = get_products_for_cve(cve_data)

                # Check blacklist (technologies with status OUT_OF_SCOPE) before inserting
                is_blacklisted = False
                for p in product_list:
                    vendor_val = (p.get('vendor') or 'Unknown').strip()[:50]
                    product_val = (p.get('product') or 'Multiple Products').strip()[:50]
                    # validate product looks reasonable; otherwise skip this product for matching
                    if not product_val or product_val == 'Multiple Products':
                        continue
                    if not is_valid_product_name(product_val):
                        continue
                    cursor.execute('''
                        SELECT status FROM technologies WHERE LOWER(vendor) = ? AND LOWER(product) = ? LIMIT 1
                    ''', (vendor_val.lower(), product_val.lower()))
                    tech_row = cursor.fetchone()
                    if tech_row and tech_row['status'] == 'OUT_OF_SCOPE':
                        is_blacklisted = True
                        break

                if is_blacklisted:
                    IMPORT_METRICS['nvd_skipped_blacklist'] += 1
                    logger.info(f"⛔ Skipping CVE {cve_id} due to OUT_OF_SCOPE technology match")
                    continue

                # Insert CVE (not blacklisted)
                imported_at = datetime.now().isoformat()
                cursor.execute('''
                    INSERT INTO cves 
                    (cve_id, description, severity, cvss_score, published_date, 
                     imported_at, last_updated, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    description[:2000],
                    severity,
                    score,
                    published_date,
                    imported_at,
                    imported_at,
                    'NVD'
                ))

                # Insert each unique product for this CVE (avoid duplicates)
                for p in product_list:
                    vendor_val = (p.get('vendor') or 'Unknown').strip()[:50]
                    product_val = (p.get('product') or 'Multiple Products').strip()[:50]
                    confidence_val = float(p.get('confidence', 0.0))
                    # validate product looks reasonable; otherwise skip
                    if product_val and product_val != 'Multiple Products' and not is_valid_product_name(product_val):
                        # skip noisy/description-like product values
                        continue
                    # Check for existing
                    cursor.execute('''
                        SELECT 1 FROM affected_products WHERE cve_id = ? AND vendor = ? AND product = ?
                    ''', (cve_id, vendor_val, product_val))
                    if not cursor.fetchone():
                        cursor.execute('''
                            INSERT INTO affected_products (cve_id, vendor, product, confidence)
                            VALUES (?, ?, ?, ?)
                        ''', (cve_id, vendor_val, product_val, confidence_val))
                
                imported += 1
                if imported % 10 == 0:
                    logger.info(f"  📊 Imported {imported} CVEs...")
                
            except Exception as e:
                logger.warning(f"⚠️ Warning processing CVE: {str(e)[:100]}")
                continue
        
        conn.commit()
        conn.close()
        
        IMPORT_METRICS['nvd_imported'] += imported
        duration = time.time() - start_time
        logger.info(f"✅ NVD import completed in {duration:.2f}s")
        logger.info(f"📊 Imported {imported} CVEs (skipped due blacklist: {IMPORT_METRICS['nvd_skipped_blacklist']})")
        
        return {'imported': imported}
        
    except Exception as e:
        error_msg = f"❌ NVD import failed: {str(e)}"
        logger.error(error_msg)
        return {'error': str(e)}


def import_from_cvedetails():
    """Stub importer for CVE Details (modular importer). Currently acts as a placeholder.
    Implement scraping or API access here in future. It should follow the same normalization
    and blacklist-checking rules as the NVD importer.
    """
    logger.info("🔧 CVE Details importer stub called (no-op)")
    # Placeholder: no external CVE Details API implemented. In future:
    # - fetch data
    # - normalize to same shape as NVD `cve_data`
    # - reuse get_products_for_cve and blacklist checking
    return {'imported': 0}

def start_import_scheduler():
    """Start background scheduler for automatic imports"""
    logger.info("Starting import scheduler (every 30 minutes)...")
    
    # Run import immediately
    # Use orchestrator to run all importers
    def run_importers():
        try:
            import_from_nvd()
        except Exception as e:
            logger.error(f"Error running NVD importer: {e}")
        try:
            import_from_cvedetails()
        except Exception as e:
            logger.warning(f"CVE Details importer not available or failed: {e}")

    run_importers()
    
    # Schedule future imports
    schedule.every(30).minutes.do(run_importers)
    
    def scheduler_loop():
        while True:
            schedule.run_pending()
            time.sleep(60)
    
    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()


# ========== BULLETIN & DELIVERY HELPERS ==========
def ensure_uploads_dir():
    import os
    up = os.path.join(os.path.dirname(__file__), 'uploads')
    if not os.path.exists(up):
        os.makedirs(up, exist_ok=True)
    return up

def send_email(subject: str, html_body: str, to_list: List[str], cc_list: List[str] = None, attachments: List[str] = None):
    """Send an HTML email using SMTP. SMTP config is read from environment variables.
    If SMTP not configured, fallback to logging and return False.
    Returns True if sent (or logged), False on error.
    """
    import os
    import smtplib
    from email.message import EmailMessage

    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    from_addr = os.environ.get('SMTP_FROM', smtp_user or 'noreply@example.com')

    if not smtp_host or not smtp_user or not smtp_pass:
        logger.warning('SMTP not configured; email will be logged instead of sent')
        logger.info('Email would be sent to %s cc=%s subject=%s', to_list, cc_list, subject)
        return True

    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = ', '.join(to_list)
        if cc_list:
            msg['Cc'] = ', '.join(cc_list)
        msg.set_content('This email contains HTML content. If you see this, your client does not support HTML.')
        msg.add_alternative(html_body, subtype='html')

        # Attach files
        if attachments:
            for path in attachments:
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                    import mimetypes
                    ctype, encoding = mimetypes.guess_type(path)
                    if ctype is None:
                        ctype = 'application/octet-stream'
                    maintype, subtype = ctype.split('/', 1)
                    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=os.path.basename(path))
                except Exception as e:
                    logger.warning('Failed to attach %s: %s', path, e)

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info('Email sent to %s', to_list)
        return True
    except Exception as e:
        logger.error('Error sending email: %s', e)
        return False


def render_bulletin_html(title: str, body: str, cves: List[Dict[str, Any]]):
    """Produce a simple HTML template for bulletins."""
    rows = ''
    for c in cves:
        rows += f"<tr><td><code>{c.get('cve_id')}</code></td><td>{c.get('severity')}</td><td>{c.get('short_description','')[:200]}</td></tr>"
    html = f"""
    <html>
    <body>
      <h2>{title}</h2>
      <div>{body}</div>
      <h3>Affected CVEs</h3>
      <table border=1 cellpadding=6 cellspacing=0>
        <thead><tr><th>CVE</th><th>Severity</th><th>Summary</th></tr></thead>
        <tbody>
          {rows}
        </tbody>
      </table>
      <p>Regards,<br/>CTBA Platform</p>
    </body>
    </html>
    """
    return html


# ========== API ENDPOINTS ==========
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the dashboard HTML as the main page."""
    try:
        tpl_path = os.path.join(os.path.dirname(__file__), 'templates', 'dashboard.html')
        with open(tpl_path, 'r', encoding='utf-8') as f:
            html = f.read()
        return HTMLResponse(content=html)
    except Exception as e:
        logger.error(f"Error serving dashboard at /: {e}")
        raise HTTPException(status_code=500, detail='Dashboard not available')


@app.get("/api/info")
async def api_info():
    """API information endpoint (JSON)"""
    return {
        "service": "CTBA Platform API",
        "version": "7.0.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "endpoints": [
            {"path": "/api/cves", "method": "GET", "description": "Get CVEs with filtering"},
            {"path": "/api/cves/{cve_id}", "method": "GET", "description": "Get CVE details"},
            {"path": "/api/cves/{cve_id}/action", "method": "POST", "description": "Accept/Reject CVE"},
            {"path": "/api/technologies", "method": "POST", "description": "Add a technology/product with status"},
            {"path": "/api/technologies", "method": "GET", "description": "List technologies"},
            {"path": "/api/stats", "method": "GET", "description": "Get system statistics"},
            {"path": "/api/import/trigger", "method": "POST", "description": "Trigger manual import"}
        ]
    }

@app.get("/api/cves")
async def get_cves(
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    product: Optional[str] = Query(None, description="Filter by product"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """
    Get CVEs with filtering options
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build query
        query = "SELECT * FROM cves WHERE 1=1"
        params = []

        # Status filter (default to PENDING if not provided)
        if status and status in ['PENDING', 'ACCEPTED', 'REJECTED', 'DEFERRED']:
            query += " AND status = ?"
            params.append(status)
        else:
            # Default: only show HIGH and MEDIUM if no severity provided
            if severity and severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                query += " AND severity = ?"
                params.append(severity)
            elif not severity:
                query += " AND severity IN ('HIGH','MEDIUM')"
        if severity and severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            query += " AND severity = ?"
            params.append(severity)
        else:
            query += " AND severity IN ('HIGH','MEDIUM')"

        # Vendor/Product filtering via affected_products existence
        if vendor:
            query += " AND EXISTS (SELECT 1 FROM affected_products ap WHERE ap.cve_id = cves.cve_id AND LOWER(ap.vendor) LIKE ? )"
            params.append(f"%{vendor.lower()}%")
        if product:
            query += " AND EXISTS (SELECT 1 FROM affected_products ap2 WHERE ap2.cve_id = cves.cve_id AND LOWER(ap2.product) LIKE ? )"
            params.append(f"%{product.lower()}%")

        query += " ORDER BY published_date DESC, cvss_score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        cves = []
        
        for row in cursor.fetchall():
            cve = dict(row)
            cve_id = cve['cve_id']
            
            # Get affected products (all) including confidence and matched technology status
            cursor.execute('''
                SELECT vendor, product, confidence 
                FROM affected_products 
                WHERE cve_id = ?
            ''', (cve_id,))
            rows = cursor.fetchall()
            products_list = []
            tech_statuses = []
            if rows:
                for r in rows:
                    vendor_p = r['vendor']
                    product_p = r['product']
                    confidence_p = float(r['confidence'] or 0.0)
                    # Lookup technology status if analyst has added it
                    cursor.execute('SELECT status FROM technologies WHERE LOWER(vendor) = ? AND LOWER(product) = ? LIMIT 1', (vendor_p.lower(), product_p.lower()))
                    tech_row = cursor.fetchone()
                    tech_status = tech_row['status'] if tech_row else None
                    if tech_status:
                        tech_statuses.append(tech_status)
                    products_list.append({'vendor': vendor_p, 'product': product_p, 'confidence': confidence_p, 'tech_status': tech_status})
                cve['affected_products'] = products_list
            else:
                cve['affected_products'] = [{'vendor': 'Unknown', 'product': 'Multiple Products', 'confidence': 0.0, 'tech_status': None}]

            # Determine matched_technology_status for the CVE (priority: OUT_OF_SCOPE > PRIORITY > NORMAL)
            matched_status = None
            if tech_statuses:
                if any(s == 'OUT_OF_SCOPE' for s in tech_statuses):
                    matched_status = 'OUT_OF_SCOPE'
                elif any(s == 'PRIORITY' for s in tech_statuses):
                    matched_status = 'PRIORITY'
                elif any(s == 'NORMAL' for s in tech_statuses):
                    matched_status = 'NORMAL'
            cve['matched_technology_status'] = matched_status

            # Add a short summary (for display above the CVE)
            cve['short_description'] = (cve.get('description') or '')[:300]
            
            # Format date
            if cve['published_date']:
                cve['published_date_formatted'] = cve['published_date'].replace('T', ' ')
            
            cves.append(cve)
        
        # Get total count (use DISTINCT to avoid duplicates when joining via EXISTS)
        count_query = "SELECT COUNT(*) FROM cves WHERE 1=1"
        count_params = []
        if status and status in ['PENDING', 'ACCEPTED', 'REJECTED', 'DEFERRED']:
            # Default severity filter in count as well
            if severity and severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count_query += " AND severity = ?"
                count_params.append(severity)
            elif not severity:
                count_query += " AND severity IN ('HIGH','MEDIUM')"
            count_query += " AND status = 'PENDING'"

        if severity and severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count_query += " AND severity = ?"
            count_params.append(severity)
        else:
            count_query += " AND severity IN ('HIGH','MEDIUM')"

        if vendor:
            count_query += " AND EXISTS (SELECT 1 FROM affected_products ap WHERE ap.cve_id = cves.cve_id AND LOWER(ap.vendor) LIKE ? )"
            count_params.append(f"%{vendor.lower()}%")
        if product:
            count_query += " AND EXISTS (SELECT 1 FROM affected_products ap2 WHERE ap2.cve_id = cves.cve_id AND LOWER(ap2.product) LIKE ? )"
            count_params.append(f"%{product.lower()}%")

        cursor.execute(count_query, count_params)
        total = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "success": True,
            "cves": cves,
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Error fetching CVEs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/stats')
async def api_stats():
    """Return basic statistics for dashboard: total, pending, accepted, rejected, by severity."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cves WHERE status = 'PENDING'")
        pending = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cves WHERE status = 'ACCEPTED'")
        accepted = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cves WHERE status = 'REJECTED'")
        rejected = cursor.fetchone()[0]
        # severities
        cursor.execute("SELECT severity, COUNT(*) as cnt FROM cves GROUP BY severity")
        rows = cursor.fetchall()
        cves_by_severity = {r['severity']: r['cnt'] for r in rows}
        conn.close()
        return {
            'success': True,
            'summary': {
                'total_cves': total,
                'pending_cves': pending,
                'accepted_cves': accepted,
                'rejected_cves': rejected,
                'cves_by_severity': {
                    'CRITICAL': cves_by_severity.get('CRITICAL', 0),
                    'HIGH': cves_by_severity.get('HIGH', 0),
                    'MEDIUM': cves_by_severity.get('MEDIUM', 0),
                    'LOW': cves_by_severity.get('LOW', 0),
                }
            }
        }
    except Exception as e:
        logger.error('Error computing stats: %s', e)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/import/trigger")
async def trigger_import(background_tasks: BackgroundTasks):
    """Trigger a manual import"""
    background_tasks.add_task(import_from_nvd)
    return {
        "success": True,
        "message": "Import triggered in background",
        "timestamp": datetime.now().isoformat()
    }


class AuthRequest(BaseModel):
    username: str
    password: str


@app.post('/api/auth/login')
async def auth_login(req: AuthRequest):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ? LIMIT 1', (req.username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    if not _verify_password(row['password_salt'], row['password_hash'], req.password):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token = create_access_token({'sub': row['username'], 'role': row['role']}, expires_delta=timedelta(hours=8))
    return {'access_token': token, 'token_type': 'bearer', 'username': row['username'], 'role': row['role']}


@app.post('/api/auth/register')
async def auth_register(req: AuthRequest, role: str = 'VOC_L1', current_user: dict = Depends(lambda: None)):
    # Simple registration endpoint - should be protected in real deployments
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM users WHERE username = ?', (req.username,))
    if cur.fetchone()[0] > 0:
        conn.close()
        raise HTTPException(status_code=400, detail='User already exists')
    salt, h = _hash_password(req.password)
    cur.execute('INSERT INTO users (username, role, password_hash, password_salt) VALUES (?, ?, ?, ?)', (req.username, role, h, salt))
    conn.commit()
    conn.close()
    return {'success': True, 'username': req.username, 'role': role}


async def get_current_user(authorization: Optional[str] = Header(None)):
    """Dependency to read the `Authorization` header and return the current user.
    Uses FastAPI `Header` injection so the standard `Authorization: Bearer <token>`
    header is correctly provided to this dependency.
    """
    auth_header = authorization
    if not auth_header:
        raise HTTPException(status_code=401, detail='Authorization header missing')
    if auth_header.lower().startswith('bearer '):
        token = auth_header.split(None, 1)[1]
    else:
        token = auth_header
    payload = decode_access_token(token)
    username = payload.get('sub') or payload.get('username')
    if not username:
        raise HTTPException(status_code=401, detail='Invalid token payload')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, role FROM users WHERE username = ? LIMIT 1', (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail='User not found')
    return {'id': row['id'], 'username': row['username'], 'role': row['role']}



@app.post("/api/cves/{cve_id}/action")
async def cve_action(cve_id: str, action_request: CVEActionRequest, current_user: dict = Depends(get_current_user)):
    """Allow an analyst to accept/reject/defer a CVE and log the action"""
    try:
        # Role enforcement: only VOC_L1 analysts may perform validation actions
        if current_user.get('role') != 'VOC_L1':
            raise HTTPException(status_code=403, detail='Only VOC_L1 analysts can validate/reject CVEs')

        # Validate action: only ACCEPTED or REJECTED are allowed via this endpoint
        if action_request.action not in [CVEStatus.ACCEPTED, CVEStatus.REJECTED]:
            raise HTTPException(status_code=400, detail='Invalid action - only ACCEPTED or REJECTED allowed')

        # Update cve status
        decision_date = datetime.now().isoformat()
        # Use a small retry/backoff loop for transient 'database is locked' errors
        max_attempts = 5
        success = False
        last_err = None
        # Ensure we write the raw enum value (e.g. 'ACCEPTED') to the DB, not the Python Enum repr
        try:
            action_str = action_request.action.value if hasattr(action_request.action, 'value') else str(action_request.action)
        except Exception:
            action_str = str(action_request.action)
        for attempt in range(1, max_attempts + 1):
            conn = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE cves SET status = ?, analyst = ?, decision_date = ?, decision_comments = ?, last_updated = ?
                    WHERE cve_id = ?
                ''', (
                    action_str,
                    current_user.get('username'),
                    decision_date,
                    action_request.comments,
                    decision_date,
                    cve_id
                ))

                # Log action (use raw enum value)
                cursor.execute('''
                    INSERT INTO cve_actions (cve_id, action, analyst, comments)
                    VALUES (?, ?, ?, ?)
                ''', (cve_id, action_str, current_user.get('username'), action_request.comments))

                conn.commit()
                success = True
                break
            except sqlite3.OperationalError as oe:
                last_err = oe
                msg = str(oe).lower()
                if 'database is locked' in msg:
                    logger.warning('Database locked on attempt %d for cve_action %s; retrying...', attempt, cve_id)
                    # exponential backoff
                    sleep_for = 0.1 * (2 ** (attempt - 1))
                    time.sleep(sleep_for)
                    continue
                else:
                    logger.error('OperationalError in cve_action: %s', oe)
                    raise
            except Exception as e:
                last_err = e
                logger.error('Unexpected error in cve_action: %s', e)
                raise
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

        if not success:
            logger.error('Failed to perform cve_action for %s after %d attempts: %s', cve_id, max_attempts, last_err)
            raise HTTPException(status_code=500, detail='Database busy; please retry the action')

        return {'success': True, 'cve_id': cve_id, 'action': action_str}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing action on CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/technologies")
async def add_technology(tech: TechnologyCreate, current_user: dict = Depends(get_current_user)):
    """Add a technology/product to the tracked list with a status"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Enforce: adding OUT_OF_SCOPE (blacklist) must be done by VOC_L1 analyst
        if tech.status == 'OUT_OF_SCOPE' and current_user.get('role') != 'VOC_L1':
            conn.close()
            raise HTTPException(status_code=403, detail='Only VOC_L1 analysts can add OUT_OF_SCOPE technologies')

        # Insert or ignore if exists
        cursor.execute('''
            INSERT OR IGNORE INTO technologies (vendor, product, status, added_by, reason)
            VALUES (?, ?, ?, ?, ?)
        ''', (tech.vendor[:50], tech.product[:50], tech.status, current_user.get('username'), tech.reason[:200]))

        # If insert ignored, update status/reason
        cursor.execute('''
            UPDATE technologies SET status = ?, reason = ?, updated_at = CURRENT_TIMESTAMP WHERE vendor = ? AND product = ?
        ''', (tech.status, tech.reason[:200], tech.vendor[:50], tech.product[:50]))

        conn.commit()
        # If added as OUT_OF_SCOPE, mark matching CVEs as DEFERRED and log action
        try:
            if tech.status == 'OUT_OF_SCOPE':
                v = tech.vendor[:50].lower()
                p = tech.product[:50].lower()
                now = datetime.now().isoformat()
                # Find matching CVEs
                cursor.execute('SELECT DISTINCT cve_id FROM affected_products WHERE LOWER(vendor) = ? AND LOWER(product) = ?', (v, p))
                rows = cursor.fetchall()
                for r in rows:
                    cve_id = r['cve_id']
                    # Update CVE status to DEFERRED so it won't appear in default PENDING list
                    cursor.execute('UPDATE cves SET status = ?, analyst = ?, decision_date = ?, decision_comments = ?, last_updated = ? WHERE cve_id = ?', (
                        'DEFERRED', current_user.get('username'), now, f'Marked OUT_OF_SCOPE due to technology {tech.vendor}/{tech.product}', now, cve_id
                    ))
                    # Log action for audit
                    cursor.execute('INSERT INTO cve_actions (cve_id, action, analyst, comments) VALUES (?, ?, ?, ?)', (cve_id, 'DEFERRED', current_user.get('username'), f'Auto-deferred due to OUT_OF_SCOPE technology {tech.vendor}/{tech.product}'))
                conn.commit()
        except Exception as e:
            logger.warning('Error deferring CVEs after OUT_OF_SCOPE add: %s', e)

        conn.close()

        return {'success': True, 'vendor': tech.vendor, 'product': tech.product, 'status': tech.status}
    except Exception as e:
        logger.error(f"Error adding technology: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/technologies")
async def list_technologies(limit: int = 200):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT vendor, product, status, reason, added_by, created_at FROM technologies ORDER BY created_at DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return {"success": True, "technologies": [dict(r) for r in rows]}
    except Exception as e:
        logger.error(f"Error listing technologies: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Frontend-friendly endpoints (no /api prefix) to support existing UI code
@app.get("/technologies")
async def frontend_list_technologies(status: Optional[str] = None, vendor: Optional[str] = None, product: Optional[str] = None, limit: int = 200):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "SELECT id, vendor, product, status, reason, added_by, created_at FROM technologies WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if vendor:
            query += " AND LOWER(vendor) LIKE ?"
            params.append(f"%{vendor.lower()}%")
        if product:
            query += " AND LOWER(product) LIKE ?"
            params.append(f"%{product.lower()}%")
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        # Return plain array for older frontend
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error listing frontend technologies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/technologies")
async def frontend_add_technology(tech: TechnologyCreate, current_user: dict = Depends(get_current_user)):
    try:
        # reuse logic from add_technology
        conn = get_db_connection()
        cursor = conn.cursor()
        # Enforce OUT_OF_SCOPE additions
        if tech.status == 'OUT_OF_SCOPE' and current_user.get('role') != 'VOC_L1':
            conn.close()
            raise HTTPException(status_code=403, detail='Only VOC_L1 analysts can add OUT_OF_SCOPE technologies')

        cursor.execute('''
            INSERT OR IGNORE INTO technologies (vendor, product, status, added_by, reason)
            VALUES (?, ?, ?, ?, ?)
        ''', (tech.vendor[:50], tech.product[:50], tech.status, current_user.get('username'), tech.reason[:200]))
        cursor.execute('''
            UPDATE technologies SET status = ?, reason = ?, updated_at = CURRENT_TIMESTAMP WHERE vendor = ? AND product = ?
        ''', (tech.status, tech.reason[:200], tech.vendor[:50], tech.product[:50]))
        conn.commit()
        # return the inserted/updated row
        cursor.execute('SELECT id, vendor, product, status, reason, added_by, created_at FROM technologies WHERE vendor = ? AND product = ? LIMIT 1', (tech.vendor[:50], tech.product[:50]))
        row = cursor.fetchone()
        # If added as OUT_OF_SCOPE, mark matching CVEs as DEFERRED and log action
        try:
            if tech.status == 'OUT_OF_SCOPE':
                v = tech.vendor[:50].lower()
                p = tech.product[:50].lower()
                now = datetime.now().isoformat()
                cursor.execute('SELECT DISTINCT cve_id FROM affected_products WHERE LOWER(vendor) = ? AND LOWER(product) = ?', (v, p))
                rows = cursor.fetchall()
                for r in rows:
                    cve_id = r['cve_id']
                    cursor.execute('UPDATE cves SET status = ?, analyst = ?, decision_date = ?, decision_comments = ?, last_updated = ? WHERE cve_id = ?', (
                        'DEFERRED', current_user.get('username'), now, f'Marked OUT_OF_SCOPE due to technology {tech.vendor}/{tech.product}', now, cve_id
                    ))
                    cursor.execute('INSERT INTO cve_actions (cve_id, action, analyst, comments) VALUES (?, ?, ?, ?)', (cve_id, 'DEFERRED', current_user.get('username'), f'Auto-deferred due to OUT_OF_SCOPE technology {tech.vendor}/{tech.product}'))
                conn.commit()
        except Exception as e:
            logger.warning('Error deferring CVEs after OUT_OF_SCOPE add (frontend): %s', e)

        conn.close()
        return dict(row) if row else {}
    except Exception as e:
        logger.error(f"Error adding frontend technology: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.put('/technologies/{tech_id}')
async def update_technology(tech_id: int, payload: dict):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        fields = []
        params = []
        if 'status' in payload:
            fields.append('status = ?')
            params.append(payload['status'])
        if 'reason' in payload:
            fields.append('reason = ?')
            params.append(payload['reason'][:200])
        if 'vendor' in payload:
            fields.append('vendor = ?')
            params.append(payload['vendor'][:50])
        if 'product' in payload:
            fields.append('product = ?')
            params.append(payload['product'][:50])
        if not fields:
            raise HTTPException(status_code=400, detail='No fields to update')
        params.append(tech_id)
        query = f"UPDATE technologies SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()
        cursor.execute('SELECT id, vendor, product, status, reason, added_by, created_at FROM technologies WHERE id = ?', (tech_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail='Technology not found')
        return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating technology: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete('/technologies/{tech_id}')
async def delete_technology(tech_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT vendor, product FROM technologies WHERE id = ?', (tech_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail='Technology not found')
        cursor.execute('DELETE FROM technologies WHERE id = ?', (tech_id,))
        conn.commit()
        conn.close()
        return {'success': True, 'vendor': row['vendor'], 'product': row['product']}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting technology: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/technologies/stats')
async def frontend_technologies_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM technologies")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT status, COUNT(*) as count FROM technologies GROUP BY status")
        rows = cursor.fetchall()
        conn.close()
        by_status = [{'status': r['status'], 'count': r['count']} for r in rows]
        return {'total_tracked': total, 'by_status': by_status}
    except Exception as e:
        logger.error(f"Error computing technology stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
        

# ========== MAIN ENTRY POINT ==========
if __name__ == "__main__":
    # Initialize database
    init_database()
    
    # Start import scheduler
    start_import_scheduler()
    
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )