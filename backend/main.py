"""
CTBA Platform - Backend API
Compatible avec CVElist.js React frontend - INTELLIGENT PRODUCT EXTRACTION
"""
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query, Header
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from nlp_extractor import nlp_extractor
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import sqlite3
import requests
import schedule
import spacy
from typing import List, Tuple, Dict, Any
import time
import pytz
import threading
import uvicorn
import logging
import json
import re
import os
import hashlib
import binascii
import jwt



class NLPTestRequest(BaseModel):
    description: str
    cve_id: Optional[str] = None

def format_date_for_display(date_str: str) -> Dict[str, str]:
    """Convert UTC date to local time (UTC+1) for display"""
    if not date_str:
        return {
            'formatted': 'N/A',
            'utc': 'N/A',
            'local': 'N/A',
            'timezone': 'UTC'
        }
        
    try:
        # Parse UTC date
        if 'T' in date_str and 'Z' in date_str:
            utc_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        elif 'T' in date_str:
            # ISO format without Z
            utc_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        else:
            # Simple format
            utc_date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        
        # Convert to Europe/Paris (UTC+1)
        paris_tz = pytz.timezone('Europe/Paris')
        local_date = utc_date.astimezone(paris_tz)
        
        return {
            'formatted': local_date.strftime('%d/%m/%Y %H:%M'),
            'utc': utc_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'local': local_date.strftime('%Y-%m-%d %H:%M:%S'),
            'timezone': 'Europe/Paris (UTC+1)',
            'iso_local': local_date.isoformat(),
            'iso_utc': utc_date.isoformat()
        }
    except Exception as e:
        logger.warning(f"Error formatting date {date_str}: {e}")
        return {
            'formatted': date_str.replace('T', ' '),
            'utc': date_str,
            'local': date_str,
            'timezone': 'UTC'
        }


def get_current_local_time() -> Dict[str, str]:
    """Get current time in both UTC and UTC+1"""
    utc_now = datetime.now(pytz.UTC)
    paris_tz = pytz.timezone('Europe/Paris')
    local_now = utc_now.astimezone(paris_tz)
    
    return {
        'utc': utc_now.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'local': local_now.strftime('%Y-%m-%d %H:%M:%S UTC+1'),
        'formatted_local': local_now.strftime('%d/%m/%Y %H:%M'),
        'timezone': 'Europe/Paris',
        'timestamp': utc_now.isoformat()
    }

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
#@asynccontextmanager

#async def lifespan(app: FastAPI):
    #"""Lifespan context manager pour FastAPI"""
    # Startup
    #logger.info("Starting CTBA Platform API...")
    #init_database()
    # Start import immediately
    #threading.Thread(target=import_from_nvd, daemon=True).start()
    #start_import_scheduler()
    #logger.info("CTBA Platform API started successfully")
    
    #yield
    
    
    # Shutdown
    #logger.info("Shutting down CTBA Platform API...")
    # CORRIGEZ COMME ÇA :
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager pour FastAPI"""
    # Startup
    logger.info("Starting CTBA Platform API...")
    
    # Initialiser NLP extractor (en parallèle)
    nlp_extractor.initialize()
    
    init_database()
    # Start import immediately
    threading.Thread(target=import_from_nvd, daemon=True).start()
    start_import_scheduler()
    logger.info("CTBA Platform API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down CTBA Platform API...")
app = FastAPI(
    #title="CTBA Platform API",
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
    
        # CVEs main table - AJOUTEZ cvss_version
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
            cvss_score REAL,
            cvss_version TEXT DEFAULT 'N/A',
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

            # Ensure new columns exist for older DBs
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check and add missing columns to cves table
        cur.execute("PRAGMA table_info(cves)")
        cols = {r[1] for r in cur.fetchall()}
        if 'cvss_version' not in cols:
            cur.execute('ALTER TABLE cves ADD COLUMN cvss_version TEXT DEFAULT "N/A"')
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Error updating database schema: {e}")

# ========== INTELLIGENT PRODUCT EXTRACTION ==========
def extract_vendor_product_from_cpe(cpe_uri: str):
    """Extract vendor and product from CPE URI avec plus de précision"""
    try:
        if not cpe_uri or not isinstance(cpe_uri, str):
            return None, None
        
        # Normaliser le CPE URI
        cpe_uri = cpe_uri.strip()
        
        # Pattern complet pour CPE 2.3: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
        if cpe_uri.startswith('cpe:2.3:'):
            parts = cpe_uri.split(':')
            if len(parts) >= 6:  # cpe:2.3:a:vendor:product:version:...
                # Part type: a=application, o=OS, h=hardware
                part_type = parts[2]
                if part_type not in ['a', 'o', 'h']:
                    return None, None
                
                vendor_raw = parts[3]
                product_raw = parts[4]
                
                # Valider les valeurs
                if vendor_raw in ['-', '*', '', '~'] or product_raw in ['-', '*', '', '~']:
                    return None, None
                
                # Nettoyer et formater
                vendor = clean_cpe_value(vendor_raw)
                product = clean_cpe_value(product_raw)
                
                # Vérifier que le produit a au moins 2 caractères
                if len(product) < 2:
                    return None, None
                
                return vendor, product
        
        # Pattern pour CPE 2.2: cpe:/a:microsoft:windows:10
        elif cpe_uri.startswith('cpe:/'):
            parts = cpe_uri.split(':')
            if len(parts) >= 4:
                vendor_raw = parts[2]
                product_raw = parts[3]
                
                if vendor_raw in ['-', '*', '', '~'] or product_raw in ['-', '*', '', '~']:
                    return None, None
                
                vendor = clean_cpe_value(vendor_raw)
                product = clean_cpe_value(product_raw)
                
                if len(product) < 2:
                    return None, None
                
                return vendor, product
        
        # Dernier recours: expression régulière
        patterns = [
            r'cpe:[^:]+:[^:]+:([^:]+):([^:]+)',
            r'cpe:/[^:]+:([^:]+):([^:]+)',
            r'([^/\s]+)\s*/\s*([^/\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, cpe_uri)
            if match:
                vendor = clean_cpe_value(match.group(1))
                product = clean_cpe_value(match.group(2))
                
                if vendor and product and vendor not in ['-', '*', '~'] and product not in ['-', '*', '~']:
                    return vendor, product
        
    except Exception as e:
        logger.debug(f"Error extracting from CPE {cpe_uri[:50]}: {e}")
    
    return None, None

def extract_products_with_nlp(description: str) -> List[Dict[str, Any]]:
    """
    Extract products using NLP (spaCy) with advanced heuristics
    Returns list of products with confidence scores
    """
    if not description or not nlp:
        return []
    
    try:
        doc = nlp(description)
        products = []
        
        # 1. ENTITY RECOGNITION (NER)
        for ent in doc.ents:
            if ent.label_ in ['ORG', 'PRODUCT', 'GPE']:
                # Filtrer les entités trop génériques
                entity_text = ent.text.strip()
                if is_valid_product_name(entity_text):
                    confidence = calculate_ner_confidence(ent)
                    products.append({
                        'text': entity_text,
                        'type': ent.label_,
                        'confidence': confidence,
                        'source': 'ner',
                        'start': ent.start_char,
                        'end': ent.end_char
                    })
        
        # 2. NOUN PHRASE EXTRACTION
        for chunk in doc.noun_chunks:
            chunk_text = chunk.text.strip()
            if len(chunk_text.split()) >= 2:  # Au moins 2 mots
                if is_product_like_noun_phrase(chunk_text, chunk):
                    confidence = calculate_np_confidence(chunk)
                    if confidence > 0.5:
                        products.append({
                            'text': chunk_text,
                            'type': 'NOUN_PHRASE',
                            'confidence': confidence,
                            'source': 'noun_chunk',
                            'start': chunk.start_char,
                            'end': chunk.end_char
                        })
        
        # 3. DEPENDENCY PARSING pour trouver "product of vendor"
        product_patterns = extract_with_dependency_patterns(doc)
        products.extend(product_patterns)
        
        # 4. DÉDUPICATION et fusion
        merged_products = merge_overlapping_products(products)
        
        # 5. EXTRACTION VENDOR/PRODUCT
        vendor_product_pairs = []
        for prod in merged_products:
            vendor, product = extract_vendor_product_from_entity(prod['text'], doc)
            if vendor and product:
                vendor_product_pairs.append({
                    'vendor': vendor,
                    'product': product,
                    'confidence': prod['confidence'] * 0.9,
                    'source': prod['source'] + '_nlp'
                })
        
        return vendor_product_pairs[:3]  # Limiter à 3 meilleurs résultats
        
    except Exception as e:
        logger.error(f"NLP extraction error: {e}")
        return []

def clean_cpe_value(value: str) -> str:
    """Nettoyer une valeur CPE"""
    if not value:
        return ""
    
    # Remplacer les underscores et caractères spéciaux
    value = value.replace('_', ' ').replace('\\', '').strip()
    
    # Supprimer les caractères non alphanumériques (sauf espaces, tirets, points)
    value = re.sub(r'[^\w\s\-\.]', ' ', value)
    
    # Supprimer les espaces multiples
    value = re.sub(r'\s+', ' ', value)
    
    # Titre case sauf pour les acronymes connus
    if value.isupper() or value.islower():
        value = value.title()
    
    # Liste d'acronymes à garder en majuscules
    acronyms = ['UI', 'API', 'CMS', 'LLM', 'IoT', 'PDF', 'SQL', 'SSL', 'TLS', 
                'HTTP', 'HTTPS', 'SDK', 'IDE', 'CLI', 'GUI', 'OS', 'CPU', 'GPU',
                'RAM', 'ROM', 'BIOS', 'UEFI', 'DNS', 'DHCP', 'FTP', 'SSH', 'VPN',
                'JSON', 'XML', 'YAML', 'HTML', 'CSS', 'JS', 'PHP', 'ASP', 'JSP',
                'REST', 'SOAP', 'API', 'AWS', 'GCP', 'Azure', 'IBM', 'SAP', 'CRM',
                'ERP', 'CMS', 'CDN', 'DNS', 'IP', 'MAC', 'TCP', 'UDP', 'ICMP']
    
    for acronym in acronyms:
        pattern = r'\b' + re.escape(acronym.lower()) + r'\b'
        value = re.sub(pattern, acronym, value, flags=re.IGNORECASE)
    
    return value.strip()

def is_valid_product_name(text: str) -> bool:
    """Vérifier si le texte ressemble à un nom de produit valide - version améliorée"""
    if not text or len(text.strip()) < 2:
        return False
    
    text = text.strip()
    text_lower = text.lower()
    
    # 1. Vérifier les longueurs
    if len(text) > 80:  # Trop long pour un nom de produit
        return False
    
    # 2. Liste de mots interdits (plus précise)
    not_product_words = {
        'vulnerability', 'vulnerable', 'security', 'flaw', 'issue', 'problem',
        'bug', 'exploit', 'attack', 'threat', 'risk', 'allows', 'enables',
        'permits', 'lets', 'could', 'would', 'might', 'may', 'can', 'should',
        'this', 'that', 'these', 'those', 'which', 'what', 'when', 'where',
        'why', 'how', 'there', 'here', 'thus', 'hence', 'therefore', 'however',
        'although', 'because', 'since', 'while', 'during', 'before', 'after',
        'through', 'until', 'unless', 'except', 'besides', 'despite', 'regardless'
    }
    
    words = text_lower.split()
    for word in words:
        if word in not_product_words:
            return False
    
    # 3. Vérifier les patterns non-valides
    invalid_patterns = [
        r'^\d+$',  # Uniquement des chiffres
        r'^[a-z]\s*$',  # Une seule lettre
        r'\b(vuln|cve|cpe|id|ref|refs)\b',  # Termes techniques
        r'^.*\b(?:allows|enables|permits)\b.*$',  # Contient des verbes d'action
        r'^.*\b(?:before|after|when|while)\b.*$',  # Contient des mots temporels
    ]
    
    for pattern in invalid_patterns:
        if re.match(pattern, text_lower):
            return False
    
    # 4. Vérifier les patterns valides (signes d'un vrai produit)
    valid_patterns = [
        r'^[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*$',  # Mots capitalisés
        r'^[A-Z]+(?:\s+[A-Z]+)*$',  # Tous majuscules (acronymes)
        r'^[A-Z][a-z]+\d+$',  # Nom suivi de chiffres (Product2023)
        r'^\w+-\w+$',  # Avec tiret
        r'^\w+\.\w+$',  # Avec point
        r'\b(?:Pro|Enterprise|Business|Standard|Professional|Ultimate)\b',
        r'\b(?:Server|Client|Desktop|Mobile|Cloud|Web)\b',
        r'\b(?:Studio|Suite|Pack|Bundle|Edition|Version)\b',
    ]
    
    for pattern in valid_patterns:
        if re.match(pattern, text):
            return True
    
    # 5. Vérifier la présence de marques connues
    known_product_indicators = [
        'Windows', 'Linux', 'Android', 'iOS', 'macOS', 'Chrome', 'Firefox',
        'WordPress', 'Apache', 'Nginx', 'MySQL', 'PostgreSQL', 'MongoDB',
        'Docker', 'Kubernetes', 'Java', 'Python', 'PHP', 'Ruby', 'Node',
        'React', 'Angular', 'Vue', 'Django', 'Flask', 'Spring', '.NET'
    ]
    
    for indicator in known_product_indicators:
        if indicator.lower() in text_lower:
            return True
    
    # 6. Vérifier la composition du texte
    # Doit contenir au moins une lettre
    if not re.search(r'[A-Za-z]', text):
        return False
    
    # Doit contenir principalement des caractères alphanumériques
    alpha_ratio = sum(1 for c in text if c.isalnum()) / len(text)
    if alpha_ratio < 0.6:  # Trop de caractères spéciaux
        return False
    
    return True
def extract_product_from_description(description: str) -> tuple:
    """
    Intelligently extract vendor and product from description with improved accuracy
    """
    if not description:
        return None, None
    
    description_lower = description.lower()
    
    # 1. DICTIONNAIRE ÉTENDU DE PRODUITS CONNUS
    vendor_product_map = {
        # Microsoft
        'microsoft windows': ('Microsoft', 'Windows'),
        'windows server': ('Microsoft', 'Windows Server'),
        'microsoft office': ('Microsoft', 'Office'),
        'microsoft excel': ('Microsoft', 'Excel'),
        'microsoft word': ('Microsoft', 'Word'),
        'microsoft outlook': ('Microsoft', 'Outlook'),
        'microsoft edge': ('Microsoft', 'Edge'),
        'internet explorer': ('Microsoft', 'Internet Explorer'),
        '.net framework': ('Microsoft', '.NET Framework'),
        'microsoft azure': ('Microsoft', 'Azure'),
        
        # Google
        'google chrome': ('Google', 'Chrome'),
        'android': ('Google', 'Android'),
        'google play': ('Google', 'Play Store'),
        'google drive': ('Google', 'Drive'),
        'google docs': ('Google', 'Docs'),
        
        # Apple
        'macos': ('Apple', 'macOS'),
        'mac os': ('Apple', 'macOS'),
        'ios': ('Apple', 'iOS'),
        'iphone os': ('Apple', 'iOS'),
        'safari': ('Apple', 'Safari'),
        
        # Adobe
        'adobe reader': ('Adobe', 'Acrobat Reader'),
        'adobe acrobat': ('Adobe', 'Acrobat'),
        'adobe flash': ('Adobe', 'Flash Player'),
        'adobe photoshop': ('Adobe', 'Photoshop'),
        
        # Linux/Open Source
        'linux kernel': ('Linux', 'Kernel'),
        'ubuntu': ('Canonical', 'Ubuntu'),
        'debian': ('Debian', 'Linux'),
        'red hat': ('Red Hat', 'Enterprise Linux'),
        'centos': ('CentOS', 'Linux'),
        'fedora': ('Fedora', 'Linux'),
        
        # Web Servers
        'apache http server': ('Apache', 'HTTP Server'),
        'apache tomcat': ('Apache', 'Tomcat'),
        'nginx': ('Nginx', 'Web Server'),
        'iis': ('Microsoft', 'Internet Information Services'),
        
        # Databases
        'mysql': ('Oracle', 'MySQL'),
        'postgresql': ('PostgreSQL', 'Database'),
        'mongodb': ('MongoDB', 'Database'),
        'oracle database': ('Oracle', 'Database'),
        'microsoft sql server': ('Microsoft', 'SQL Server'),
        # Siemens Industrial
    'simatic et 200al': ('Siemens', 'SIMATIC ET 200AL'),
    'simatic et 200mp': ('Siemens', 'SIMATIC ET 200MP'),
    'simatic et 200sp': ('Siemens', 'SIMATIC ET 200SP'),
    'telecontrol server basic': ('Siemens', 'TeleControl Server Basic'),
    'simatic': ('Siemens', 'SIMATIC Industrial Control'),
    'siemens': ('Siemens', 'Industrial Products'),
    
    # Hikvision
    'hikvision': ('Hikvision', 'Surveillance Products'),
    'hikvision nvr': ('Hikvision', 'NVR'),
    'hikvision dvr': ('Hikvision', 'DVR'),
    'hikvision cvr': ('Hikvision', 'CVR'),
    'hikvision ipc': ('Hikvision', 'IP Camera'),
    'hikvision access control': ('Hikvision', 'Access Control'),
    
    # SAP
    'sap business connector': ('SAP', 'Business Connector'),
    'sap supplier relationship management': ('SAP', 'Supplier Relationship Management'),
    'sap fiori': ('SAP', 'Fiori'),
    'sap s/4hana': ('SAP', 'S/4HANA'),
    'sap netweaver': ('SAP', 'NetWeaver'),
    'sap hana': ('SAP', 'HANA Database'),
    'sap erp': ('SAP', 'ERP'),
    'sap ecc': ('SAP', 'ERP Central Component'),
    
    # WordPress
    'wordpress plugin': ('WordPress', 'Plugin'),
    'wordpress theme': ('WordPress', 'Theme'),
    'woocommerce': ('WooCommerce', 'E-commerce Plugin'),
    'exact hosted payment': ('E-xact', 'Hosted Payment Plugin'),
    'dreamer blog': ('Dreamer Blog', 'WordPress Theme'),
    
    # Autres
    'oracle java': ('Oracle', 'Java'),
    'java network launch protocol': ('Oracle', 'Java'),
    'jnlp': ('Oracle', 'Java Network Launch Protocol'),
        
        # Programming Languages/Frameworks
        'node.js': ('Node.js', 'Runtime'),
        'python': ('Python', 'Programming Language'),
        'java': ('Oracle', 'Java'),
        'php': ('PHP', 'Programming Language'),
        'ruby on rails': ('Ruby', 'Rails Framework'),
        'django': ('Django', 'Web Framework'),
        'react': ('Facebook', 'React'),
        'angular': ('Google', 'Angular'),
        'vue.js': ('Vue.js', 'Framework'),
        
        # WordPress
        'wordpress': ('WordPress', 'CMS'),
        'wordpress plugin': ('WordPress', 'Plugin'),
        'woocommerce': ('WooCommerce', 'E-commerce'),
        
        # Cloud/Containers
        'docker': ('Docker', 'Container Platform'),
        'kubernetes': ('Kubernetes', 'Container Orchestrator'),
        'aws': ('Amazon', 'AWS'),
        'amazon web services': ('Amazon', 'AWS'),
        'google cloud': ('Google', 'Cloud Platform'),
        
        # Network Equipment
        'cisco ios': ('Cisco', 'IOS'),
        'cisco asa': ('Cisco', 'ASA'),
        'fortinet fortios': ('Fortinet', 'FortiOS'),
        'palo alto networks': ('Palo Alto Networks', 'PAN-OS'),
        
        # Security Products
        'mcafee': ('McAfee', 'Security Software'),
        'symantec': ('Symantec', 'Security Software'),
        'kaspersky': ('Kaspersky', 'Security Software'),
        'bitdefender': ('Bitdefender', 'Security Software'),
    }
    
    # Vérifier les correspondances exactes d'abord
    for keyword, (vendor, product) in vendor_product_map.items():
        if keyword in description_lower:
            return vendor, product
    
    # 2. PATTERNS AMÉLIORÉS POUR L'EXTRACTION
    patterns = [
        # Pattern: "in [Vendor] [Product]" 
        (r'\b(?:in|of|for|on|in the)\s+([A-Z][A-Za-z0-9&\.\-]+\s+[A-Za-z0-9&\.\-]+)\s+(?:software|application|system|tool|framework|library|plugin|extension|driver|component|module|package|service)', 1),
        
        # Pattern: "[Vendor]'s [Product]"
        (r'([A-Z][A-Za-z0-9&\.\-]+)\'s\s+([A-Za-z0-9&\.\-]+(?:\s+[A-Za-z0-9&\.\-]+)*)', (1, 2)),
        
        # Pattern: "[Vendor] [Product] [version]" 
        (r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+([A-Z][A-Za-z0-9]+(?:\s+[A-Za-z0-9]+)*)\s+(?:v\d+|version\s+\d+|release\s+\d+)', (1, 2)),
        
        # Pattern: "the [Product] [component] in [Vendor]"
        (r'the\s+([A-Z][A-Za-z0-9&\.\-]+)\s+(?:component|feature|module|plugin)\s+(?:in|of)\s+([A-Z][A-Za-z0-9&\.\-]+)', (2, 1)),
        
        # Pattern: "[Product] from [Vendor]"
        (r'([A-Z][A-Za-z0-9&\.\-]+(?:\s+[A-Za-z0-9&\.\-]+)*)\s+from\s+([A-Z][A-Za-z0-9&\.\-]+)', (2, 1)),
        
        # Pattern: CVE style: "Vendor:Product:Version"
        (r'([A-Za-z0-9]+)\s*:\s*([A-Za-z0-9]+)', (1, 2)),
    ]
    
    for pattern, groups in patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            if isinstance(groups, tuple):
                vendor_idx, product_idx = groups
                vendor = match.group(vendor_idx).strip()
                product = match.group(product_idx).strip()
            else:
                full_match = match.group(groups).strip()
                # Essayer de séparer vendor et product
                parts = full_match.split()
                if len(parts) >= 2:
                    vendor = parts[0]
                    product = ' '.join(parts[1:])
                else:
                    vendor = "Unknown"
                    product = full_match
            
            # Valider l'extraction
            if is_valid_product_extraction(vendor, product):
                return clean_extracted_names(vendor, product)
    
    # 3. FALLBACK: Rechercher des marques connues
    known_vendors = ['Microsoft', 'Google', 'Apple', 'Adobe', 'Oracle', 'IBM', 
                     'Cisco', 'Intel', 'AMD', 'NVIDIA', 'Dell', 'HP', 'Lenovo',
                     'VMware', 'Red Hat', 'Canonical', 'Apache', 'Mozilla',
                     'Facebook', 'Twitter', 'LinkedIn', 'Salesforce', 'SAP','Siemens','Hikvision','WordPress']
    
    for vendor in known_vendors:
        if vendor.lower() in description_lower:
            # Chercher un produit associé
            product_pattern = rf'{re.escape(vendor)}\s+([A-Z][A-Za-z0-9\s&\.\-]+)'
            product_match = re.search(product_pattern, description, re.IGNORECASE)
            if product_match:
                product = product_match.group(1).strip()
                if is_valid_product_name(product):
                    return vendor, clean_product_name(product)
            else:
                # Juste le vendeur
                return vendor, "Various Products"
    
    return None, None
def extract_product_from_description_improved(description: str) -> tuple:
    """Version améliorée avec reconnaissance spécifique des patterns industriels"""
    if not description:
        return None, None
    
    # NE PAS tronquer la description ici - c'est le travail d'une autre fonction
    description_lower = description.lower()
    
    # 1. Reconnaissance des produits Siemens (patterns exacts)
    siemens_patterns = [
        (r'SIMATIC ET 200AL IM 157-1 PN', ('Siemens', 'SIMATIC ET 200AL')),
        (r'SIMATIC ET 200MP IM 155-5 PN HF', ('Siemens', 'SIMATIC ET 200MP')),
        (r'SIMATIC ET 200SP IM 155-6 MF HF', ('Siemens', 'SIMATIC ET 200SP')),
        (r'SIMATIC ET 200SP IM 155-6 PN HA', ('Siemens', 'SIMATIC ET 200SP')),
        (r'TeleControl Server Basic', ('Siemens', 'TeleControl Server Basic')),
        (r'Cert Portal\.Siemens', ('Siemens', 'Product Certification')),
    ]
    
    for pattern, (vendor, product) in siemens_patterns:
        if re.search(pattern, description, re.IGNORECASE):
            return vendor, product
    
    # 2. Reconnaissance SAP (plus spécifique)
    sap_patterns = [
        (r'SAP (Business Connector)', ('SAP', 'Business Connector')),
        (r'SAP (Supplier Relationship Management)', ('SAP', 'Supplier Relationship Management')),
        (r'SAP (Fiori App Intercompany Balance Reconciliation)', ('SAP', 'Fiori App Intercompany Balance Reconciliation')),
        (r'SAP (S/4HANA)', ('SAP', 'S/4HANA')),
        (r'SAP (NetWeaver [A-Za-z ]+)', ('SAP', r'\1')),
        (r'SAP (HANA [Dd]atabase)', ('SAP', 'HANA Database')),
        (r'SAP (ERP [Cc]entral [Cc]omponent)', ('SAP', 'ERP Central Component')),
        (r'SAP (Application Server for ABAP)', ('SAP', 'Application Server for ABAP')),
        (r'Application Server (ABAP)', ('SAP', 'Application Server ABAP')),
        (r'SAP (Wily Introscope [A-Za-z ]+)', ('SAP', r'\1')),
        (r'SAP (Landscape Transformation)', ('SAP', 'Landscape Transformation')),
        (r'SAP (Product Designer [A-Za-z ]+)', ('SAP', 'Product Designer')),
    ]
    
    for pattern, (vendor, product_template) in sap_patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            if isinstance(product_template, str) and '\\1' in product_template:
                product = match.expand(product_template)
            else:
                product = product_template
            return vendor, product
    
    # 3. Reconnaissance ABAP spécifique
    if re.search(r'\bABAP\b', description, re.IGNORECASE):
        if re.search(r'\bSAP\b', description, re.IGNORECASE) or re.search(r'Application Server', description, re.IGNORECASE):
            return ('SAP', 'ABAP Platform')
    
    # 4. Reconnaissance WordPress (plus spécifique)
    if 'wordpress' in description_lower:
        if 'plugin' in description_lower:
            # Essayer d'extraire le nom du plugin
            plugin_match = re.search(r'The ([A-Za-z0-9\s&|\-]+) WordPress plugin', description, re.IGNORECASE)
            if plugin_match:
                plugin_name = plugin_match.group(1).strip()
                return ('WordPress', f'{plugin_name} Plugin')
            return ('WordPress', 'Plugin')
        elif 'theme' in description_lower:
            theme_match = re.search(r'The ([A-Za-z0-9\s&|\-]+) WordPress theme', description, re.IGNORECASE)
            if theme_match:
                theme_name = theme_match.group(1).strip()
                return ('WordPress', f'{theme_name} Theme')
            return ('WordPress', 'Theme')
        return ('WordPress', 'CMS')
    
    # 5. Reconnaissance Hikvision
    if 'hikvision' in description_lower:
        if 'nvr' in description_lower or 'dvr' in description_lower or 'cvr' in description_lower or 'ipc' in description_lower:
            return ('Hikvision', 'NVR/DVR/CVR/IPC')
        elif 'access control' in description_lower:
            return ('Hikvision', 'Access Control Products')
        return ('Hikvision', 'Surveillance Products')
    
    # 6. Reconnaissance Oracle/Java
    if 'java network launch protocol' in description_lower or 'jnlp' in description_lower:
        return ('Oracle', 'Java Network Launch Protocol')
    elif 'oracle java' in description_lower or ('java' in description_lower and 'oracle' in description_lower):
        return ('Oracle', 'Java')
    
    # 7. Reconnaissance langages/frameworks spécifiques
    lang_patterns = [
        (r'\bLIBPNG\b', ('LIBPNG', 'PNG Library')),
        (r'\bRIOT OS\b', ('RIOT', 'Operating System')),
        (r'\bTinyOS\b', ('TinyOS', 'Operating System')),
        (r'\bOllama\b', ('Ollama', 'AI Framework')),
        (r'\bLangChain\b', ('LangChain', 'AI Framework')),
        (r'\bLlamaIndex\b', ('LlamaIndex', 'AI Framework')),
        (r'\bEmlog\b', ('Emlog', 'CMS')),
        (r'\bAppsmith\b', ('Appsmith', 'Dashboard Platform')),
        (r'\bTermix\b', ('Termix', 'Server Management Platform')),
        (r'\bOpenCode\b', ('OpenCode', 'AI Coding Agent')),
        (r'\bhermes\b', ('Hermes', 'Workflow Automation')),
        (r'\bWebErpMesv2\b', ('WebErpMes', 'ERP System')),
    ]
    
    for pattern, (vendor, product) in lang_patterns:
        if re.search(pattern, description, re.IGNORECASE):
            return vendor, product
    
    # 8. Fallback à l'ancienne méthode
    return extract_product_from_description(description)

def clean_extracted_names(vendor: str, product: str) -> tuple:
    """Nettoyer les noms extraits"""
    # Nettoyer le vendor
    vendor = re.sub(r'\s+(?:corporation|corp|inc|llc|ltd|gmbh|s\.a\.?|s\.p\.a\.?)$', '', vendor, flags=re.IGNORECASE)
    vendor = vendor.strip()
    
    # Nettoyer le produit
    product = re.sub(r'\s+(?:software|application|system|tool|framework|library|version|v\d+|\.\d+).*$', '', product, flags=re.IGNORECASE)
    product = product.strip()
    
    # Formater
    if vendor and not vendor[0].isupper():
        vendor = vendor.title()
    
    if product and not product[0].isupper():
        product = product.title()
    
    return vendor, product

def clean_vendor_product(vendor: str, product: str) -> tuple:
    """Clean and format vendor and product names with better preservation"""
    if not vendor or vendor.lower() == 'unknown':
        vendor = "Unknown"
    
    if not product or product.lower() == 'unknown':
        product = "Multiple Products"
    
    # NE PAS formater les noms industriels qui ont une casse spécifique
    is_industrial_name = any(pattern in product.upper() for pattern in 
                           ['SIMATIC', 'IM ', 'PN ', 'HF ', 'HA ', 'MF ', 'SIPLUS',
                            'ET 200', 'ABAP', 'HANA', 'S/4HANA', 'ECC', 'ERP'])
    
    # Remove version numbers and common suffixes from product
    if not is_industrial_name:
        product = re.sub(r'\s+v\d+\.?\d*.*$', '', product, flags=re.IGNORECASE)
        product = re.sub(r'\s+\d+\.\d+.*$', '', product)
        product = re.sub(r'\s+(?:before|through|up\s+to|version|vulnerability|vulnerable|allows|enables|plugin|extension|tool|framework|library|system|software|application|driver|component|feature|module|package).*$', '', product, flags=re.IGNORECASE)
    
    # Clean up whitespace
    vendor = re.sub(r'\s+', ' ', vendor).strip()
    product = re.sub(r'\s+', ' ', product).strip()
    
    # Format vendor (toujours en format propre)
    if vendor and vendor != "Unknown":
        # Nettoyer les suffixes corporatifs
        vendor = re.sub(r'\s+(?:corporation|corp|inc|llc|ltd|gmbh|s\.a\.?|s\.p\.a\.?)$', '', vendor, flags=re.IGNORECASE)
        # Formater proprement
        if vendor.isupper() or vendor.islower():
            vendor = vendor.title()
    
    # Format product (seulement si pas industriel)
    if product and product != "Multiple Products" and not is_industrial_name:
        if product.isupper() or product.islower():
            product = product.title()
        
        # Handle special cases
        special_cases = {
            'ui': 'UI', 'api': 'API', 'cms': 'CMS', 'llm': 'LLM',
            'abap': 'ABAP', 'hana': 'HANA', 'ecc': 'ECC', 'erp': 'ERP',
            'sap': 'SAP'
        }
        
        for lowercase, proper in special_cases.items():
            if product.lower() == lowercase:
                product = proper
                break
        
        # Shorten if too long
        if len(product) > 40:
            product = product[:37] + "..."
    
    return vendor, product

def get_products_for_cve(cve_data: Dict) -> List[Dict[str, Any]]:
    """
    Extract a list of affected products with improved accuracy and confidence scoring
    """
    products_dict = {}
    
    def walk_nodes_with_confidence(nodes, parent_confidence=1.0):
        for node in nodes:
            node_confidence = parent_confidence * 0.9 if parent_confidence < 1.0 else 1.0
            
            for match in node.get('cpeMatch', []):
                uri = match.get('cpe23Uri') or match.get('criteria')
                if uri:
                    vendor, product = extract_vendor_product_from_cpe(uri)
                    if vendor and product:
                        vendor, product = clean_vendor_product(vendor, product)
                        if product and product != 'Multiple Products':
                            cpe_confidence = node_confidence * 1.0
                            key = f"{vendor.lower()}|{product.lower()}"
                            if key not in products_dict or cpe_confidence > products_dict[key]['confidence']:
                                products_dict[key] = {
                                    'vendor': vendor,
                                    'product': product,
                                    'confidence': cpe_confidence,
                                    'source': 'cpe'
                                }
            
            children = node.get('children', [])
            if children:
                walk_nodes_with_confidence(children, node_confidence * 0.8)
    
    # 1. Extraction depuis les CPEs
    configurations = cve_data.get('configurations', []) or []
    for config in configurations:
        nodes = config.get('nodes', []) or []
        walk_nodes_with_confidence(nodes)
    
    # 2. Extraction depuis la description (TOUJOURS essayer, pas seulement si < 2 CPEs)
    description = ""
    for desc in cve_data.get('descriptions', []) or []:
        if desc.get('lang') == 'en':
            description = desc.get('value', '')
            break
    
    if description:
        # Essayer d'abord la méthode améliorée
        vendor, product = extract_product_from_description_improved(description)
        
        # Si pas trouvé ou trop générique, essayer l'ancienne méthode
        if not vendor or not product or product in ['Multiple Products', 'Various Products']:
            vendor, product = extract_product_from_description(description)
        
        if vendor and product:
            vendor, product = clean_vendor_product(vendor, product)
            if product and product != 'Multiple Products':
                key = f"{vendor.lower()}|{product.lower()}"
                # Donner une confiance plus élevée si trouvé par la méthode améliorée
                confidence = 0.8 if vendor != 'Unknown' else 0.5
                if key not in products_dict:
                    products_dict[key] = {
                        'vendor': vendor,
                        'product': product,
                        'confidence': confidence,
                        'source': 'description'
                    }
                elif confidence > products_dict[key]['confidence']:
                    products_dict[key]['confidence'] = confidence
                    products_dict[key]['source'] = 'description_improved'
    
    # 3. Si toujours rien, chercher dans les références
    if not products_dict:
        references = cve_data.get('references', []) or []
        for ref in references:
            url = ref.get('url', '')
            if url:
                vendor_product = extract_from_reference_url(url)
                if vendor_product:
                    vendor, product = vendor_product
                    key = f"{vendor.lower()}|{product.lower()}"
                    products_dict[key] = {
                        'vendor': vendor,
                        'product': product,
                        'confidence': 0.6,
                        'source': 'reference'
                    }
    
    # 4. Final fallback
    if not products_dict:
        products_dict['unknown|multiple'] = {
            'vendor': 'Unknown',
            'product': 'Multiple Products',
            'confidence': 0.1,
            'source': 'fallback'
        }
    
    # Trier par confidence
    sorted_products = sorted(products_dict.values(), key=lambda x: x['confidence'], reverse=True)
    
    # Limiter à 3 produits maximum pour éviter le bruit
    return sorted_products[:3]

def extract_from_reference_url(url: str):
    """Extraire vendor/product depuis les URLs de référence"""
    try:
        # Patterns communs dans les URLs
        patterns = [
            r'github\.com/([^/]+)/([^/]+)',
            r'([^/]+)\.com/([^/]+)',
            r'/([^/]+)-([^/]+)-',
            r'product=([^&]+).*vendor=([^&]+)',
            r'vendor=([^&]+).*product=([^&]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                vendor = match.group(1).replace('-', ' ').title()
                product = match.group(2).replace('-', ' ').title()
                
                if is_valid_product_name(product):
                    return vendor, product
    except:
        pass
    return None
    # ========== FONCTION UTILITAIRE CVSS ==========
def extract_cvss_metrics(cve_data):
    """
    Extract CVSS metrics with priority: 4.0 > 4.1 > 3.1 > 3.0 > 2.0
    Returns: (severity, score, cvss_version)
    """
    severity = "MEDIUM"
    score = 5.0
    cvss_version = None
    
    metrics = cve_data.get('metrics', {})
    
    # 1. PRIORITÉ MAX: CVSS 4.0
    if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
        try:
            cvss_data = metrics['cvssMetricV40'][0]['cvssData']
            score = cvss_data.get('baseScore', 5.0)
            base_severity = cvss_data.get('baseSeverity', 'MEDIUM')
            if base_severity:
                severity = base_severity.upper()
            cvss_version = '4.0'
            logger.info(f"✅ Using CVSS 4.0 for CVE: score={score}, severity={severity}")
        except Exception as e:
            logger.warning(f"Error parsing CVSS 4.0: {e}")
    
    # 2. PRIORITÉ: CVSS 4.1 (si disponible)
    elif 'cvssMetricV41' in metrics and metrics['cvssMetricV41']:
        try:
            cvss_data = metrics['cvssMetricV41'][0]['cvssData']
            score = cvss_data.get('baseScore', 5.0)
            base_severity = cvss_data.get('baseSeverity', 'MEDIUM')
            if base_severity:
                severity = base_severity.upper()
            cvss_version = '4.1'
            logger.info(f"✅ Using CVSS 4.1 for CVE: score={score}, severity={severity}")
        except Exception as e:
            logger.warning(f"Error parsing CVSS 4.1: {e}")
    
    # 3. PRIORITÉ: CVSS 3.1
    elif 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        try:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            score = cvss_data.get('baseScore', 5.0)
            base_severity = cvss_data.get('baseSeverity', 'MEDIUM')
            if base_severity:
                severity = base_severity.upper()
            cvss_version = '3.1'
            logger.info(f"⚠️ Using CVSS 3.1 for CVE (no 4.x available): score={score}, severity={severity}")
        except Exception as e:
            logger.warning(f"Error parsing CVSS 3.1: {e}")
    
    # 4. PRIORITÉ: CVSS 3.0
    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
        try:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            score = cvss_data.get('baseScore', 5.0)
            base_severity = cvss_data.get('baseSeverity', 'MEDIUM')
            if base_severity:
                severity = base_severity.upper()
            cvss_version = '3.0'
            logger.info(f"⚠️ Using CVSS 3.0 for CVE: score={score}, severity={severity}")
        except Exception as e:
            logger.warning(f"Error parsing CVSS 3.0: {e}")
    
    # 5. DERNIER RECOURS: CVSS 2.0
    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        try:
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            score = cvss_data.get('baseScore', 5.0)
            # Convertir score CVSS 2.0 en sévérité
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            cvss_version = '2.0'
            logger.info(f"⚠️ Using CVSS 2.0 for CVE: score={score}, severity={severity}")
        except Exception as e:
            logger.warning(f"Error parsing CVSS 2.0: {e}")
    
    # Si aucune métrique trouvée
    if cvss_version is None:
        cvss_version = 'N/A'
        logger.warning(f"❌ No CVSS metrics found for CVE")
    
    return severity, score, cvss_version

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
                
                                
                                # ⚡ EXTRACTION DES MÉTRIQUES AVEC PRIORITÉ: 4.0 > 4.1 > 3.1 > 3.0 > 2.0
                severity, score, cvss_version = extract_cvss_metrics(cve_data)
                # Extract published date
                published_date_raw = cve_data.get('published', '')
                if published_date_raw:
                    try:
                        # NVD dates are in UTC with Z suffix
                        if published_date_raw.endswith('Z'):
                            # Format: 2026-01-10T00:00:00Z
                            dt = datetime.fromisoformat(published_date_raw.replace('Z', '+00:00'))
                            # Store in consistent format
                            published_date = dt.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            # Fallback
                            published_date = published_date_raw.replace('T', ' ').split('.')[0]
                    except Exception:
                        published_date = published_date_raw.replace('T', ' ').split('.')[0]
                else:
                    published_date = None
                
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
                    (cve_id, description, severity, cvss_score, cvss_version, published_date, 
                     imported_at, last_updated, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    description[:2000],
                    severity,
                    score,
                    cvss_version,
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


@app.get("/api/timezone")
async def get_timezone_info():
    """Get timezone information for the dashboard"""
    return {
        "server_timezone": "UTC",
        "display_timezone": "Europe/Paris (UTC+1)",
        "current_time": get_current_local_time(),
        "supported_formats": {
            "database": "UTC",
            "display": "UTC+1 (Europe/Paris)",
            "date_format": "DD/MM/YYYY HH:MM"
        }
    }


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
    Get CVEs with filtering options - CORRIGÉ
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build query
        query = "SELECT * FROM cves WHERE 1=1"
        params = []

        # Status filter
        if status and status in ['PENDING', 'ACCEPTED', 'REJECTED', 'DEFERRED']:
            query += " AND status = ?"
            params.append(status)
        else:
            # Default to PENDING
            query += " AND status = 'PENDING'"
        
        # Severity filter
        if severity and severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            query += " AND severity = ?"
            params.append(severity)
        else:
            # Default to HIGH and MEDIUM
            query += " AND severity IN ('CRITICAL','HIGH','MEDIUM')"

        # Vendor/Product filtering
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
            try:
                cve = dict(row)
                cve_id = cve['cve_id']
                
                # ⚠️ CRÉEZ UN NOUVEAU CURSEUR POUR LA SOUS-REQUÊTE ⚠️
                cursor2 = conn.cursor()
                cursor2.execute('''
                    SELECT vendor, product, confidence 
                    FROM affected_products 
                    WHERE cve_id = ?
                ''', (cve_id,))
                rows = cursor2.fetchall()
                
                products_list = []
                if rows:
                    for r in rows:
                        products_list.append({
                            'vendor': r['vendor'], 
                            'product': r['product'], 
                            'confidence': float(r['confidence'] or 0.0)
                        })
                    cve['affected_products'] = products_list
                else:
                    cve['affected_products'] = [{'vendor': 'Unknown', 'product': 'Multiple Products', 'confidence': 0.0}]

                # Add a short summary
                cve['short_description'] = (cve.get('description') or '')[:300]
                
                # Format date if exists
                if cve['published_date']:
                    try:
                        if 'T' in cve['published_date'] and 'Z' in cve['published_date']:
                            utc_date = datetime.fromisoformat(cve['published_date'].replace('Z', '+00:00'))
                        else:
                            utc_date = datetime.strptime(cve['published_date'], '%Y-%m-%d %H:%M:%S')
                        
                        paris_tz = pytz.timezone('Europe/Paris')
                        local_date = utc_date.astimezone(paris_tz)
                        
                        cve['published_date_formatted'] = local_date.strftime('%d/%m/%Y %H:%M')
                        cve['published_date_utc'] = utc_date.strftime('%Y-%m-%d %H:%M:%S UTC')
                        cve['published_date_local'] = local_date.strftime('%Y-%m-%d %H:%M:%S UTC+1')
                        cve['timezone'] = 'Europe/Paris (UTC+1)'
                        
                    except Exception as e:
                        cve['published_date_formatted'] = cve['published_date'].replace('T', ' ')
                else:
                    cve['published_date_formatted'] = 'N/A'
                
                cves.append(cve)
                
            except Exception as e:
                logger.error(f"Error processing CVE {cve_id}: {e}")
                continue  # Continue avec le prochain CVE
        
        # Count query
        count_query = "SELECT COUNT(*) FROM cves WHERE 1=1"
        count_params = []
        
        if status and status in ['PENDING', 'ACCEPTED', 'REJECTED', 'DEFERRED']:
            count_query += " AND status = ?"
            count_params.append(status)
        else:
            count_query += " AND status = 'PENDING'"
        
        if severity and severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count_query += " AND severity = ?"
            count_params.append(severity)
        else:
            count_query += " AND severity IN ('CRITICAL','HIGH','MEDIUM')"

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


@app.get("/api/simple-cves")
async def simple_cves():
    """Simple test without complex filtering"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Exact same query as debug-filter
    cursor.execute("SELECT * FROM cves WHERE status = 'PENDING' AND severity IN ('HIGH','MEDIUM') ORDER BY published_date DESC LIMIT 50")
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {
        "count": len(results),
        "cves": results[:5]  # First 5 only
    }


@app.get("/api/debug-filter")
async def debug_filter():
    """Debug the filter logic"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Test 1: Exact same query as get_cves
    query1 = "SELECT * FROM cves WHERE 1=1 AND status = 'PENDING' AND severity IN ('HIGH','MEDIUM') ORDER BY published_date DESC LIMIT 50"
    cursor.execute(query1)
    results1 = cursor.fetchall()
    
    # Test 2: Check what severities actually exist
    query2 = "SELECT DISTINCT severity FROM cves WHERE status = 'PENDING'"
    cursor.execute(query2)
    actual_severities = [r['severity'] for r in cursor.fetchall()]
    
    # Test 3: Count by severity
    query3 = "SELECT severity, COUNT(*) as count FROM cves WHERE status = 'PENDING' GROUP BY severity"
    cursor.execute(query3)
    severity_counts = dict(cursor.fetchall())
    
    # Test 4: Show some samples
    query4 = "SELECT cve_id, severity FROM cves WHERE status = 'PENDING' ORDER BY published_date DESC LIMIT 5"
    cursor.execute(query4)
    samples = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    
    return {
        "test1_query": query1,
        "test1_results_count": len(results1),
        "actual_severities_in_db": actual_severities,
        "severity_counts": severity_counts,
        "sample_cves": samples,
        "note": "If test1_results_count is 0 but we have CVEs, the severity values in DB don't match 'HIGH' or 'MEDIUM'"
    }


@app.get("/api/all-pending")
async def all_pending():
    """Get ALL pending CVEs regardless of severity"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT c.*, 
               GROUP_CONCAT(ap.vendor || ': ' || ap.product, '; ') as products
        FROM cves c
        LEFT JOIN affected_products ap ON c.cve_id = ap.cve_id
        WHERE c.status = 'PENDING'
        GROUP BY c.cve_id
        ORDER BY c.published_date DESC
    ''')
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {
        "count": len(results),
        "cves": results
    }

# Endpoint de test pour voir tous les CVEs
@app.get("/api/test-cves")
async def test_cves():
    """Test endpoint to see all CVEs"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id, severity, status, published_date FROM cves ORDER BY published_date DESC")
    rows = cursor.fetchall()
    conn.close()
    return {"cves": [dict(row) for row in rows]}

@app.get('/api/stats')
async def api_stats():
    """Return basic statistics for dashboard: total, pending, accepted, rejected, by severity, by CVSS version."""
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
        
        # CVSS versions
        cursor.execute("SELECT cvss_version, COUNT(*) as cnt FROM cves WHERE cvss_version != 'N/A' GROUP BY cvss_version")
        cvss_rows = cursor.fetchall()
        cves_by_cvss_version = {r['cvss_version']: r['cnt'] for r in cvss_rows}
        
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
                },
                'cves_by_cvss_version': cves_by_cvss_version
            }
        }
    except Exception as e:
        logger.error('Error computing stats: %s', e)
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/api/cves/cvss4")
async def get_cvss4_cves(limit: int = 20):
    """Get CVEs with CVSS 4.x"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT cve_id, description, severity, cvss_score, cvss_version, published_date
            FROM cves 
            WHERE cvss_version IN ('4.0', '4.1')
            ORDER BY published_date DESC 
            LIMIT ?
        ''', (limit,))
        
        cves = []
        for row in cursor.fetchall():
            cve = dict(row)
            cve['short_description'] = (cve.get('description') or '')[:200]
            cves.append(cve)
        
        conn.close()
        
        return {
            "success": True,
            "cves": cves,
            "count": len(cves)
        }
        
    except Exception as e:
        logger.error(f"❌ Error fetching CVSS 4.x CVEs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
@app.post("/api/import/test-now")
async def import_test_now():
    """Import latest CVEs immediately - PUBLIC endpoint - MODIFIÉ POUR PÉRIODE PLUS LONGUE"""
    logger.info("=== IMMEDIATE IMPORT OF LATEST CVEs ===")
    
    try:
        # MODIFICATION ICI : Importer les CVEs des 24 dernières heures (au lieu de 6)
        start_date = datetime.now() - timedelta(hours=24)  # ← Changé de 6 à 24 heures
        end_date = datetime.now()
        
        logger.info(f"🕒 Importing CVEs from {start_date} to {end_date}")
        
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "resultsPerPage": 200  # Augmenté aussi pour récupérer plus
        }
        
        logger.info(f"📡 Requesting NVD API...")
        
        response = requests.get(base_url, params=params, timeout=60)  # Timeout augmenté
        response.raise_for_status()
        data = response.json()
        
        total_results = data.get('totalResults', 0)
        vulnerabilities = data.get('vulnerabilities', [])
        
        logger.info(f"📊 Found {total_results} total results, {len(vulnerabilities)} in this page")
        
        # Si plus de résultats que ce que nous avons récupéré, nous pouvons paginer
        if total_results > len(vulnerabilities):
            logger.info(f"⚠️ Note: More CVEs available ({total_results}) than fetched ({len(vulnerabilities)}). Consider pagination.")
        
        # Traitement et import
        conn = get_db_connection()
        cursor = conn.cursor()
        
        imported = 0
        skipped = 0
        for idx, vuln in enumerate(vulnerabilities):
            try:
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                if not cve_id:
                    continue
                
                # Vérifier si le CVE existe déjà
                cursor.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,))
                if cursor.fetchone():
                    skipped += 1
                    continue
                
                # Extraire les informations de base
                description = ""
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')[:2000]  # Limite augmentée
                        break
                
                # ⚡ EXTRACTION DES MÉTRIQUES AVEC PRIORITÉ: 4.0 > 4.1 > 3.1 > 3.0 > 2.0
                severity, score, cvss_version = extract_cvss_metrics(cve_data)
                
                # Date de publication
                published_date = cve_data.get('published', '')
                if published_date:
                    try:
                        if published_date.endswith('Z'):
                            published_date = published_date.replace('Z', '+00:00')
                    except:
                        pass
                
                # Extraire les produits affectés
                product_list = get_products_for_cve(cve_data)
                
                # Vérifier la blacklist
                is_blacklisted = False
                for p in product_list:
                    vendor_val = (p.get('vendor') or 'Unknown').strip()[:50]
                    product_val = (p.get('product') or 'Multiple Products').strip()[:50]
                    
                    if not product_val or product_val == 'Multiple Products':
                        continue
                    if not is_valid_product_name(product_val):
                        continue
                        
                    cursor.execute('''
                        SELECT status FROM technologies 
                        WHERE LOWER(vendor) = ? AND LOWER(product) = ? AND status = 'OUT_OF_SCOPE' 
                        LIMIT 1
                    ''', (vendor_val.lower(), product_val.lower()))
                    tech_row = cursor.fetchone()
                    if tech_row:
                        is_blacklisted = True
                        break
                
                if is_blacklisted:
                    logger.info(f"⛔ Skipping CVE {cve_id} due to OUT_OF_SCOPE technology")
                    skipped += 1
                    continue
                
                # Insérer le CVE
                imported_at = datetime.now().isoformat()
                cursor.execute('''
                    INSERT INTO cves (cve_id, description, severity, cvss_score, cvss_version, 
                                    published_date, imported_at, last_updated, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (cve_id, description, severity, score, cvss_version, 
                      published_date, imported_at, imported_at, 'NVD'))
                
                # Insérer les produits affectés
                for p in product_list:
                    vendor_val = (p.get('vendor') or 'Unknown').strip()[:50]
                    product_val = (p.get('product') or 'Multiple Products').strip()[:50]
                    confidence_val = float(p.get('confidence', 0.0))
                    
                    if product_val and product_val != 'Multiple Products' and not is_valid_product_name(product_val):
                        continue
                    
                    cursor.execute('''
                        SELECT 1 FROM affected_products 
                        WHERE cve_id = ? AND vendor = ? AND product = ?
                    ''', (cve_id, vendor_val, product_val))
                    if not cursor.fetchone():
                        cursor.execute('''
                            INSERT INTO affected_products (cve_id, vendor, product, confidence)
                            VALUES (?, ?, ?, ?)
                        ''', (cve_id, vendor_val, product_val, confidence_val))
                
                imported += 1
                
                if imported % 10 == 0:
                    logger.info(f"  Imported {imported} new CVEs...")
                
            except Exception as e:
                logger.warning(f"Error importing CVE {cve_id if 'cve_id' in locals() else 'unknown'}: {e}")
                skipped += 1
                continue
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Immediate import completed: {imported} new CVEs, {skipped} skipped")
        
        return {
            "success": True,
            "imported": imported,
            "skipped": skipped,
            "total_found": len(vulnerabilities),
            "message": f"Imported {imported} new CVEs from the last 48 hours"
        }
        
    except Exception as e:
        logger.error(f"❌ Immediate import failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to import latest CVEs"
        }

@app.post("/api/nlp/extract")
async def nlp_extract_products(request: NLPTestRequest):
    """
    Test endpoint pour l'extraction NLP parallèle
    """
    try:
        products = nlp_extractor.extract_products(
            request.description, 
            request.cve_id or ""
        )
        
        return {
            "success": True,
            "input_length": len(request.description),
            "products_found": len(products),
            "products": products,
            "nlp_initialized": nlp_extractor.initialized
        }
    except Exception as e:
        logger.error(f"NLP extraction API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/nlp/test-cve/{cve_id}")
async def test_nlp_on_cve(cve_id: str):
    """
    Tester NLP sur un CVE existant
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT description FROM cves WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        description = row['description'] or ""
        
        # Extraction avec NLP
        nlp_products = nlp_extractor.extract_products(description, cve_id)
        
        # Comparer avec l'extraction existante
        cursor = get_db_connection().cursor()
        cursor.execute("""
            SELECT vendor, product, confidence, source 
            FROM affected_products 
            WHERE cve_id = ?
        """, (cve_id,))
        
        existing_products = []
        for row in cursor.fetchall():
            existing_products.append(dict(row))
        
        cursor.connection.close()
        
        return {
            "success": True,
            "cve_id": cve_id,
            "description_preview": description[:200] + "..." if len(description) > 200 else description,
            "nlp_products": nlp_products,
            "existing_products": existing_products,
            "comparison": {
                "nlp_count": len(nlp_products),
                "existing_count": len(existing_products),
                "matches": len([p for p in nlp_products if any(
                    ep['vendor'].lower() == p['vendor'].lower() and 
                    ep['product'].lower() == p['product'].lower() 
                    for ep in existing_products
                )])
            }
        }
        
    except Exception as e:
        logger.error(f"NLP test error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/nlp/improve-cves")
async def improve_cves_with_nlp(batch_size: int = 10):
    """
    Améliorer les CVEs existants avec NLP (batch processing)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Récupérer les CVEs avec extraction faible
        cursor.execute("""
            SELECT c.cve_id, c.description, 
                   COUNT(ap.id) as product_count,
                   AVG(ap.confidence) as avg_confidence
            FROM cves c
            LEFT JOIN affected_products ap ON c.cve_id = ap.cve_id
            WHERE c.description IS NOT NULL 
            AND LENGTH(c.description) > 50
            GROUP BY c.cve_id
            HAVING product_count = 0 OR avg_confidence < 0.5
            ORDER BY c.published_date DESC
            LIMIT ?
        """, (batch_size,))
        
        cves_to_improve = []
        for row in cursor.fetchall():
            cves_to_improve.append(dict(row))
        
        improvements = []
        
        for cve in cves_to_improve:
            cve_id = cve['cve_id']
            description = cve['description']
            
            # Extraire avec NLP
            nlp_products = nlp_extractor.extract_products(description, cve_id)
            
            if nlp_products:
                # Comparer avec l'existant
                cursor2 = conn.cursor()
                cursor2.execute("""
                    SELECT vendor, product FROM affected_products 
                    WHERE cve_id = ?
                """, (cve_id,))
                
                existing = [(r['vendor'].lower(), r['product'].lower()) 
                           for r in cursor2.fetchall()]
                
                new_products = []
                for prod in nlp_products:
                    key = (prod['vendor'].lower(), prod['product'].lower())
                    if key not in existing:
                        new_products.append(prod)
                
                # Ajouter les nouveaux produits
                for prod in new_products:
                    cursor2.execute("""
                        INSERT OR IGNORE INTO affected_products 
                        (cve_id, vendor, product, confidence, source)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        cve_id,
                        prod['vendor'][:50],
                        prod['product'][:50],
                        prod['confidence'],
                        prod.get('source', 'nlp_improvement')
                    ))
                
                if new_products:
                    improvements.append({
                        'cve_id': cve_id,
                        'new_products': len(new_products),
                        'products': new_products
                    })
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "processed": len(cves_to_improve),
            "improved": len(improvements),
            "improvements": improvements,
            "message": f"Improved {len(improvements)} CVEs with NLP"
        }
        
    except Exception as e:
        logger.error(f"NLP improvement error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
@app.post("/api/fix-missing-descriptions")
async def fix_missing_descriptions():
    """Récupérer les descriptions manquantes depuis NVD"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Trouver les CVEs avec descriptions courtes ou manquantes
    cursor.execute('''
        SELECT cve_id FROM cves 
        WHERE description IS NULL OR LENGTH(description) < 50
        ORDER BY published_date DESC
        LIMIT 20
    ''')
    
    results = cursor.fetchall()
    fixed_count = 0
    
    for row in results:
        cve_id = row['cve_id']
        
        try:
            # Récupérer depuis NVD
            response = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    cve_data = data['vulnerabilities'][0]['cve']
                    
                    # Extraire la description
                    description = ""
                    for desc in cve_data.get('descriptions', []):
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    if description and len(description) > 10:
                        # Mettre à jour la description
                        cursor.execute('''
                            UPDATE cves SET description = ? WHERE cve_id = ?
                        ''', (description[:2000], cve_id))
                        
                        # Re-extraire les produits
                        product_list = get_products_for_cve(cve_data)
                        
                        # Supprimer les anciens produits
                        cursor.execute('DELETE FROM affected_products WHERE cve_id = ?', (cve_id,))
                        
                        # Insérer les nouveaux produits
                        for p in product_list:
                            vendor_val = (p.get('vendor') or 'Unknown').strip()[:50]
                            product_val = (p.get('product') or 'Multiple Products').strip()[:50]
                            confidence_val = float(p.get('confidence', 0.0))
                            
                            cursor.execute('''
                                INSERT INTO affected_products (cve_id, vendor, product, confidence)
                                VALUES (?, ?, ?, ?)
                            ''', (cve_id, vendor_val, product_val, confidence_val))
                        
                        fixed_count += 1
                        logger.info(f"Fixed description for {cve_id}")
                        
        except Exception as e:
            logger.warning(f"Error fixing {cve_id}: {e}")
            continue
    
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "fixed_count": fixed_count,
        "total_checked": len(results),
        "message": f"Fixed {fixed_count} CVEs with missing descriptions"
    }
@app.post("/api/re-extract-products")
async def re_extract_products(cve_id: Optional[str] = None):
    """Forcer la ré-extraction des produits pour une CVE ou toutes"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if cve_id:
        # Ré-extraire une CVE spécifique
        cursor.execute('SELECT description FROM cves WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()
        
        if row and row['description']:
            description = row['description']
            vendor, product = extract_product_from_description_improved(description)
            
            if vendor and product:
                vendor, product = clean_vendor_product(vendor, product)
                
                cursor.execute('''
                    UPDATE affected_products 
                    SET vendor = ?, product = ?, confidence = 0.9
                    WHERE cve_id = ?
                ''', (vendor, product, cve_id))
                
                conn.commit()
                conn.close()
                
                return {
                    "success": True,
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "message": f"Re-extracted products for {cve_id}"
                }
    else:
        # Ré-extraire toutes les CVEs avec Unknown: Multiple Products
        cursor.execute('''
            SELECT DISTINCT c.cve_id, c.description
            FROM cves c
            JOIN affected_products ap ON c.cve_id = ap.cve_id
            WHERE ap.vendor = 'Unknown' AND ap.product = 'Multiple Products'
            AND c.description IS NOT NULL
            LIMIT 50
        ''')
        
        results = cursor.fetchall()
        fixed_count = 0
        
        for row in results:
            cve_id = row['cve_id']
            description = row['description']
            
            vendor, product = extract_product_from_description_improved(description)
            if not vendor or not product:
                vendor, product = extract_product_from_description(description)
            
            if vendor and product and product != 'Multiple Products':
                vendor, product = clean_vendor_product(vendor, product)
                
                cursor.execute('''
                    UPDATE affected_products 
                    SET vendor = ?, product = ?, confidence = 0.8
                    WHERE cve_id = ? AND vendor = 'Unknown' AND product = 'Multiple Products'
                ''', (vendor, product, cve_id))
                
                fixed_count += 1
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "fixed_count": fixed_count,
            "total_checked": len(results),
            "message": f"Re-extracted {fixed_count} CVEs"
        }
    
    conn.close()
    return {"success": False, "message": "No CVE found or no description available"}
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
@app.get("/api/cves-simple")
async def get_cves_simple():
    """Simple version without complex processing"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT cve_id, description, severity, cvss_score, published_date, status
            FROM cves 
            WHERE status = 'PENDING'
            ORDER BY published_date DESC 
            LIMIT 10
        """)
        
        cves = []
        for row in cursor.fetchall():
            cve = dict(row)
            cve['short_description'] = (cve.get('description') or '')[:100]
            cves.append(cve)
        
        conn.close()
        
        return {
            "success": True,
            "cves": cves,
            "count": len(cves)
        }
        
    except Exception as e:
        logger.error(f"❌ Error in cves-simple: {str(e)}")
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