"""
CTBA Platform - Backend API
Compatible avec CVElist.js React frontend - INTELLIGENT PRODUCT EXTRACTION
"""
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query, Header, Form, Body, File, UploadFile, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
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
import concurrent.futures
from dotenv import load_dotenv
from services.cve_enrichment_service import CVEEnrichmentService
from ai_remediation_groq import get_groq_service  # Groq (GRATUIT, ULTRA-RAPIDE) ⭐⭐⭐
from ai_remediation_huggingface import get_huggingface_service  # Hugging Face (API dépréciée)
from ai_remediation_ollama import get_ollama_service  # Ollama (local, lourd)
from ai_remediation_simple import SimpleAIRemediationService  # Templates (fallback)

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Configuration IA - Groq API (GRATUIT, ULTRA-RAPIDE, Mixtral-8x7B)
# Options disponibles via variable d'environnement AI_PROVIDER:
# - "groq" (DÉFAUT): API Groq gratuite, ultra-rapide, Mixtral-8x7B
# - "simple": Templates intelligents (fallback)
# - "ollama": IA locale (lourd, non recommandé)
# - "huggingface": API dépréciée (ne fonctionne plus)
AI_PROVIDER = os.getenv('AI_PROVIDER', 'groq').lower()

# Configuration Groq
GROQ_API_KEY = os.getenv('GROQ_API_KEY', '')
GROQ_MODEL = os.getenv('GROQ_MODEL', 'llama-3.3-70b-versatile')

# Configuration Hugging Face (dépréciée)
HUGGINGFACE_TOKEN = os.getenv('HUGGINGFACE_TOKEN', '')
HUGGINGFACE_MODEL = os.getenv('HUGGINGFACE_MODEL', 'mistralai/Mixtral-8x7B-Instruct-v0.1')

# Instances globales des services IA
_simple_ai_service = SimpleAIRemediationService()
_groq_service = None

def get_ai_service():
    """Retourne le service IA approprié selon la configuration"""
    global _groq_service
    
    # Groq par défaut (RECOMMANDÉ : gratuit, ultra-rapide, Mixtral-8x7B)
    if AI_PROVIDER == 'groq':
        if not GROQ_API_KEY or GROQ_API_KEY == 'YOUR_GROQ_API_KEY_HERE':
            logger.warning("⚠️ GROQ_API_KEY manquant ou invalide dans .env")
            logger.info("📋 Fallback vers Simple AI")
            return _simple_ai_service, "Simple AI", "Template-Based"
        try:
            logger.info(f"🚀 Utilisation de Groq API ({GROQ_MODEL}) - Ultra-rapide")
            if _groq_service is None:
                _groq_service = get_groq_service(GROQ_API_KEY, GROQ_MODEL)
            return _groq_service, "Groq API", GROQ_MODEL
        except Exception as e:
            logger.warning(f"⚠️ Erreur Groq: {e}")
            logger.info("📋 Fallback vers Simple AI")
            return _simple_ai_service, "Simple AI", "Template-Based"
    
    # Simple AI (templates)
    elif AI_PROVIDER == 'simple':
        logger.info("📋 Utilisation de Simple AI (templates intelligents)")
        return _simple_ai_service, "Simple AI", "Template-Based"
    
    # Hugging Face (API dépréciée)
    elif AI_PROVIDER == 'huggingface':
        if not HUGGINGFACE_TOKEN:
            logger.warning("⚠️ HUGGINGFACE_TOKEN manquant dans .env")
            logger.info("📋 Fallback vers Simple AI")
            return _simple_ai_service, "Simple AI", "Template-Based"
        try:
            logger.info(f"🤗 Utilisation de Hugging Face ({HUGGINGFACE_MODEL})")
            service = get_huggingface_service(HUGGINGFACE_TOKEN, HUGGINGFACE_MODEL)
            return service, "Hugging Face", HUGGINGFACE_MODEL
        except Exception as e:
            logger.warning(f"⚠️ Erreur Hugging Face: {e}")
            logger.info("📋 Fallback vers Simple AI")
            return _simple_ai_service, "Simple AI", "Template-Based"
    
    # Ollama (local - lourd)
    elif AI_PROVIDER == 'ollama':
        try:
            logger.info("🤖 Tentative d'utilisation d'Ollama...")
            service = get_ollama_service()
            if service.check_ollama_running():
                logger.info("✅ Ollama disponible")
                return service, "Ollama", "qwen2.5:3b"
            else:
                logger.warning("⚠️ Ollama non disponible")
                logger.info("📋 Fallback vers Simple AI")
                return _simple_ai_service, "Simple AI", "Template-Based"
        except Exception as e:
            logger.warning(f"⚠️ Erreur Ollama: {e}")
            logger.info("📋 Fallback vers Simple AI")
            return _simple_ai_service, "Simple AI", "Template-Based"
    
    # Par défaut: Simple AI
    logger.info("📋 Utilisation de Simple AI (templates intelligents)")
    return _simple_ai_service, "Simple AI", "Template-Based"


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
            'timezone': 'UTC',
            'iso_local': '',
            'iso_utc': ''
        }

    try:
        # Parse UTC date - CORRECTION ICI
        if isinstance(date_str, str):
            # Format NVD typique: "2024-01-18T15:30:00.000Z" ou "2024-01-18T15:30:00Z"
            # Remplacer 'Z' par '+00:00' pour Python 3.7+
            date_str = date_str.strip()
            if date_str.endswith('Z'):
                date_str = date_str[:-1] + '+00:00'
            
            # Essayer d'abord le parsing ISO
            try:
                utc_date = datetime.fromisoformat(date_str)
            except ValueError:
                # Essayer d'autres formats
                formats = [
                    '%Y-%m-%dT%H:%M:%S.%f%z',
                    '%Y-%m-%dT%H:%M:%S%z',
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%d'
                ]
                
                for fmt in formats:
                    try:
                        utc_date = datetime.strptime(date_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    # Si aucun format ne fonctionne
                    raise ValueError(f"Format de date non reconnu: {date_str}")
        else:
            # Si ce n'est pas une string, retourner les valeurs par défaut
            return {
                'formatted': str(date_str),
                'utc': str(date_str),
                'local': str(date_str),
                'timezone': 'UTC',
                'iso_local': '',
                'iso_utc': ''
            }
        
        # S'assurer que la date a un timezone
        if utc_date.tzinfo is None:
            utc_date = utc_date.replace(tzinfo=pytz.UTC)
        else:
            # Convertir en UTC si ce n'est pas déjà le cas
            utc_date = utc_date.astimezone(pytz.UTC)
        
        # Convertir en Africa/Tunis (UTC+1)
        tunis_tz = pytz.timezone('Africa/Tunis')
        local_date = utc_date.astimezone(tunis_tz)
        
        # Formater pour l'affichage
        iso_utc = utc_date.isoformat()
        if iso_utc.endswith('+00:00'):
            iso_utc = iso_utc.replace('+00:00', 'Z')
        
        iso_local = local_date.isoformat()
        
        return {
            'formatted': local_date.strftime('%d/%m/%Y %H:%M:%S'),
            'utc': utc_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'local': local_date.strftime('%Y-%m-%d %H:%M:%S'),
            'timezone': f'Africa/Tunis ({local_date.strftime("%Z")})',
            'iso_local': iso_local,
            'iso_utc': iso_utc
        }
        
    except Exception as e:
        logger.warning(f"Error formatting date {date_str}: {e}")
        # Retourner la date brute si le formatage échoue
        return {
            'formatted': str(date_str).replace('T', ' '),
            'utc': str(date_str),
            'local': str(date_str),
            'timezone': 'UTC',
            'iso_local': '',
            'iso_utc': str(date_str)
        }


def format_date_simple(date_str: str) -> str:
    """
    Formate une date pour l'affichage simple.
    Retourne une string formatée ou la date d'origine en cas d'erreur.
    """
    try:
        result = format_date_for_display(date_str)
        return result.get('formatted', date_str)
    except:
        return str(date_str)


def get_current_local_time() -> Dict[str, str]:
    """Get current time in both UTC and UTC+1"""
    try:
        utc_now = datetime.now(pytz.UTC)
        tunis_tz = pytz.timezone('Africa/Tunis')
        local_now = utc_now.astimezone(tunis_tz)
        
        iso_utc = utc_now.isoformat()
        if iso_utc.endswith('+00:00'):
            iso_utc = iso_utc.replace('+00:00', 'Z')
        
        return {
            'utc': utc_now.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'local': local_now.strftime('%Y-%m-%d %H:%M:%S'),
            'formatted_local': local_now.strftime('%d/%m/%Y %H:%M'),
            'timezone': f'Africa/Tunis ({local_now.strftime("%Z")})',
            'timestamp': iso_utc,
            'iso_local': local_now.isoformat(),
            'iso_utc': iso_utc
        }
    except Exception as e:
        logger.error(f"Error getting current time: {e}")
        now = datetime.now()
        return {
            'utc': now.strftime('%Y-%m-%d %H:%M:%S'),
            'local': now.strftime('%Y-%m-%d %H:%M:%S'),
            'formatted_local': now.strftime('%d/%m/%Y %H:%M'),
            'timezone': 'UTC',
            'timestamp': now.isoformat()
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
    DEFERRED = "DEFERRED"

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
    
    # Initialiser NLP extractor (en parallèle)
    nlp_extractor.initialize()
    
    init_database()
    
    # ✅ Import automatique au démarrage depuis NVD, CVEdetails et MSRC
    logger.info("🚀 Import automatique au démarrage...")
    
    # Import NVD (rapide)
    threading.Thread(target=lambda: import_from_nvd(), daemon=True).start()
    
    # Import CVEdetails en parallèle
    threading.Thread(target=lambda: import_from_cvedetails(), daemon=True).start()
    
    # Import MSRC (Microsoft)
    threading.Thread(target=lambda: import_from_msrc(), daemon=True).start()
    
    # 🔄 Enrichissement automatique CVE.org
    def auto_enrich_cveorg():
        """Enrichir automatiquement tous les CVEs avec CVE.org au démarrage"""
        time.sleep(5)  # Attendre que les imports initiaux se lancent
        logger.info("🔄 Démarrage enrichissement automatique CVE.org...")
        try:
            stats = CVEEnrichmentService.enrich_all_pending_cves(limit=None)
            logger.info(f"✅ Enrichissement CVE.org terminé: {stats['total_processed']} CVEs traités, "
                       f"{stats['total_products_added']} produits ajoutés, "
                       f"{stats['total_dates_updated']} dates mises à jour")
        except Exception as e:
            logger.error(f"❌ Erreur enrichissement CVE.org au démarrage: {e}")
    
    threading.Thread(target=auto_enrich_cveorg, daemon=True).start()
    
    logger.info("✅ Base de données initialisée - imports NVD/CVEdetails/MSRC + enrichissement CVE.org lancés")
    
    # Scheduler pour imports périodiques
    threading.Thread(target=start_import_scheduler, daemon=True).start()
    logger.info("CTBA Platform API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down CTBA Platform API...")

app = FastAPI(
    description="CVE Management System with Dynamic Blacklist",
    version="7.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# If a React build exists in ../frontend/build, mount it so the UI is served from :8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_BUILD_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'frontend', 'build'))
if os.path.isdir(FRONTEND_BUILD_DIR):
    try:
        static_dir = os.path.join(FRONTEND_BUILD_DIR, 'static')
        if os.path.isdir(static_dir):
            app.mount('/static', StaticFiles(directory=static_dir), name='static')
    except Exception as _e:
        logger.warning('Could not mount frontend static files: %s', _e)
    FRONTEND_INDEX = os.path.join(FRONTEND_BUILD_DIR, 'index.html')
else:
    FRONTEND_INDEX = None

# CORS configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://127.0.0.1:3001"],
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
            status TEXT DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','SENT','NOT_PROCESSED','CLOSED')),
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sent_at TIMESTAMP,
            last_reminder INTEGER DEFAULT 0,
            reminder_7_sent_at TIMESTAMP,
            reminder_14_sent_at TIMESTAMP,
            escalation_30_sent_at TIMESTAMP,
            closed_at TIMESTAMP,
            closed_by TEXT,
            closure_reason TEXT,
            can_reopen BOOLEAN DEFAULT 1,
            reopened_at TIMESTAMP,
            reopened_by TEXT
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
    logger.info(f"Users count in DB: {cnt}")
    if cnt == 0:
        # Seed default users with generated password hashes
        logger.info("Seeding default test users...")
        test_users = [
            ('analyst1', 'password123', 'VOC_L1'),
            ('lead1', 'password123', 'VOC_LEAD'),
            ('admin', 'password123', 'ADMINISTRATOR'),
            ('manager1', 'password123', 'MANAGER')
        ]
        for username, password, role in test_users:
            try:
                salt, h = _hash_password(password)
                cursor.execute("INSERT INTO users (username, role, password_hash, password_salt) VALUES (?, ?, ?, ?)", (username, role, h, salt))
                logger.info(f"✅ Seeded user: {username} ({role})")
            except Exception as e:
                logger.warning(f"Could not insert user {username}: {e}")
        conn.commit()
        logger.info("User seeding completed")
    else:
        logger.info(f"Users already exist in database ({cnt} users)")
    
    # Seed default regions (if none exist)
    cursor.execute("SELECT COUNT(*) as cnt FROM regions")
    region_cnt = cursor.fetchone()[0]
    logger.info(f"Regions count in DB: {region_cnt}")
    
    default_regions = [
        ('NORAM', 'North America Region', 'admin@example.com'),
        ('LATAM', 'Latin America Region', 'admin@example.com'),
        ('EUROPE', 'Europe Region', 'nahla.messaoudi@esprit.tn'),
        ('APMEA', 'Asia Pacific, Middle East & Africa Region', 'admin@example.com')
    ]
    
    if region_cnt == 0:
        logger.info("Seeding default regions...")
        for name, description, recipients in default_regions:
            try:
                cursor.execute("INSERT INTO regions (name, description, recipients) VALUES (?, ?, ?)", 
                             (name, description, recipients))
                logger.info(f"✅ Seeded region: {name}")
            except Exception as e:
                logger.warning(f"Could not insert region {name}: {e}")
        conn.commit()
        logger.info("Region seeding completed")
    else:
        logger.info(f"Regions already exist in database ({region_cnt} regions)")
        # Update existing regions to ensure correct emails
        logger.info("Updating existing regions with latest configuration...")
        for name, description, recipients in default_regions:
            try:
                cursor.execute("UPDATE regions SET description=?, recipients=? WHERE name=?", 
                             (description, recipients, name))
                logger.info(f"✅ Updated region: {name} -> {recipients}")
            except Exception as e:
                logger.warning(f"Could not update region {name}: {e}")
        conn.commit()
        logger.info("Region update completed")
    
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
    'java network launch protocol': ('Oracle', 'Java Network Launch Protocol'),
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
        (r'([A-Z][a-z0-9&\.\-]+)\'s\s+([A-Za-z0-9&\.\-]+(?:\s+[A-Za-z0-9&\.\-]+)*)', (1, 2)),
        
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

def is_valid_product_extraction(vendor: str, product: str) -> bool:
    """Valider si l'extraction vendor/product est plausible"""
    if not vendor or not product:
        return False
    
    vendor = vendor.strip()
    product = product.strip()
    
    # Vérifier que ni l'un ni l'autre ne sont trop courts
    if len(vendor) < 2 or len(product) < 2:
        return False
    
    # Vérifier que ce ne sont pas des mots communs
    common_words = ['the', 'and', 'or', 'but', 'for', 'with', 'without', 
                   'this', 'that', 'these', 'those', 'which', 'what']
    
    if vendor.lower() in common_words or product.lower() in common_words:
        return False
    
    # Vérifier que le produit n'est pas une phrase complète
    if len(product.split()) > 5:
        return False
    
    return True

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

def clean_product_name(product: str) -> str:
    """Nettoyer un nom de produit"""
    product = re.sub(r'\s+(?:before|through|up\s+to|version|vulnerability|vulnerable|allows|enables).*$', '', product, flags=re.IGNORECASE)
    product = product.strip()
    
    if product and not product[0].isupper():
        product = product.title()
    
    return product

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

def _is_valid_affected_product(vendor: str, product: str) -> bool:
    """
    Validate that a product is legitimate and not corrupted.
    Rejects products containing noise/invalid patterns.
    """
    if not vendor or not product:
        return False
    
    # Reject known noise patterns
    noise_patterns = [
        'vuldb', '?ctiid', '?id', '?submit', 'ctiid', 'submit',
        'user attachments', 'prior', 'dev', 'esm.sh', 'lx 66 lx',
        'davcloudz', 'github', 'github:', 'bugzilla'
    ]
    
    vendor_lower = vendor.lower()
    product_lower = product.lower()
    
    # Check if vendor or product contains noise
    for pattern in noise_patterns:
        if pattern in vendor_lower or pattern in product_lower:
            return False
    
    # Reject if contains special characters that indicate corruption
    if '?' in product or '?' in vendor:
        return False
    
    # Vendor should be at least 2 chars and reasonably short
    if len(vendor) < 2 or len(vendor) > 100:
        return False
    
    # Product should be at least 2 chars
    if len(product) < 2:
        return False
    
    # Both should contain at least one alphanumeric character
    if not any(c.isalnum() for c in vendor) or not any(c.isalnum() for c in product):
        return False
    
    # Reject if vendor == product (bad extraction)
    if vendor_lower == product_lower:
        return False
    
    return True

def _get_severity_from_cvss(cvss_score: float) -> str:
    """Convert CVSS score to severity level"""
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0:
        return "LOW"
    else:
        # Default to MEDIUM for unknown/missing scores
        return "MEDIUM"

def get_products_for_cve(cve_data: Dict) -> List[Dict[str, Any]]:
    """
    Extract a list of affected products using CPE URIs + improved NLP extraction
    With filtering to remove corrupted/hash-like products
    """
    products_dict = {}

    def is_valid_product_name(vendor: str, product: str) -> bool:
        """Check if vendor/product look legitimate (not hash-like or corrupted)"""
        # Reject if contains only hex characters or hash-like patterns
        vendor_lower = vendor.lower() if vendor else ""
        product_lower = product.lower() if product else ""
        
        # Filter out hash-like identifiers (too many hex chars)
        hex_count = sum(1 for c in vendor_lower + product_lower if c in 'abcdef0123456789')
        total_chars = len(vendor_lower) + len(product_lower)
        if total_chars > 0 and hex_count / total_chars > 0.8:
            return False  # Looks like a hash
        
        # Filter out corrupted patterns like "Old6Ma:", "C4M0Uflag3:"
        if re.match(r'^[A-Za-z0-9]{1,10}$', vendor_lower) and len(vendor_lower) <= 15:
            # Single word vendor with lots of numbers - suspicious
            if sum(1 for c in vendor_lower if c.isdigit()) / len(vendor_lower) > 0.4:
                return False
        
        # Filter out 'www.' patterns that are corrupted
        if vendor_lower.startswith('www.'):
            # Should have proper domain name after www.
            domain_part = vendor_lower[4:]
            if not any(c.isalpha() for c in domain_part) or len(domain_part) < 3:
                return False
        
        return True

    def walk_nodes_with_confidence(nodes, parent_confidence=1.0):
        for node in nodes:
            node_confidence = parent_confidence * 0.9 if parent_confidence < 1.0 else 1.0

            for match in node.get('cpeMatch', []):
                uri = match.get('cpe23Uri') or match.get('criteria')
                if uri:
                    vendor, product = extract_vendor_product_from_cpe(uri)
                    if vendor and product and is_valid_product_name(vendor, product):
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

    # 2. Extraction depuis la description avec NLP AMÉLIORÉ
    description = ""
    cve_id = cve_data.get('id', 'UNKNOWN')
    for desc in cve_data.get('descriptions', []) or []:
        if desc.get('lang') == 'en':
            description = desc.get('value', '')
            break

    if description:
        # Utiliser le NLP extractor amélioré directement
        nlp_products = nlp_extractor.extract_products(description, cve_id)
        
        for p in nlp_products:
            vendor = p.get('vendor', '').strip()
            product = p.get('product', '').strip()
            confidence = p.get('confidence', 0.5)
            
            if vendor and product and product != 'Multiple Products' and is_valid_product_name(vendor, product):
                key = f"{vendor.lower()}|{product.lower()}"
                # Donner priorité aux résultats NLP avec haute confiance
                if key not in products_dict or confidence > products_dict[key]['confidence']:
                    products_dict[key] = {
                        'vendor': vendor,
                        'product': product,
                        'confidence': confidence,
                        'source': 'nlp'
                    }

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

    # 4. Final fallback - ONLY if nothing found
    if not products_dict:
        products_dict['unknown|multiple'] = {
            'vendor': 'Unknown',
            'product': 'Multiple Products',
            'confidence': 0.1,
            'source': 'fallback'
        }

    # Trier par confidence
    sorted_products = sorted(products_dict.values(), key=lambda x: x['confidence'], reverse=True)

    # Limiter à 5 produits maximum pour éviter le bruit
    return sorted_products[:5]

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
def get_cvss_priority(version):
    """Get priority level for CVSS version (higher = better)"""
    priority_map = {'4.1': 4, '4.0': 3, '3.1': 2, '3.0': 1, '2.0': 0}
    return priority_map.get(version, -1)


def compare_cvss(existing_score, existing_version, new_score, new_version):
    """
    Compare two CVSS scores and versions.
    Returns (best_score, best_version).
    Priority: 4.1 > 4.0 > 3.1 > 3.0 > 2.0
    For same version, uses max score
    """
    existing_priority = get_cvss_priority(existing_version or 'N/A')
    new_priority = get_cvss_priority(new_version or 'N/A')
    
    existing_score = float(existing_score or 0)
    new_score = float(new_score or 0)
    
    # If new version is better (higher priority), use it
    if new_priority > existing_priority:
        return new_score, new_version
    # If same priority, use max score
    elif new_priority == existing_priority and new_score > existing_score:
        return new_score, new_version
    # Otherwise keep existing
    else:
        return existing_score, existing_version


def extract_cvss_metrics(cve_data):
    """
    Extract MAXIMUM CVSS score from ALL sources and ALL versions.
    Parcourt tous les CNAs (VulDB, CVE.org, etc.) et retourne le score le plus élevé.
    Returns: (severity, max_score, cvss_version)
    """
    metrics = cve_data.get('metrics', {})
    all_scores = []  # Liste de tuples: (score, version, severity, source)
    
    # Helper pour convertir score CVSS 2.0 en sévérité
    def cvss2_to_severity(score):
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    # 1. Extraire TOUS les scores CVSS 4.1
    if 'cvssMetricV41' in metrics and metrics['cvssMetricV41']:
        for idx, metric in enumerate(metrics['cvssMetricV41']):
            try:
                cvss_data = metric.get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity', 'MEDIUM').upper()
                source = metric.get('source', f'CNA-{idx+1}')
                if score:
                    all_scores.append((float(score), '4.1', severity, source))
            except Exception as e:
                logger.warning(f"Error parsing CVSS 4.1 metric #{idx}: {e}")
    
    # 2. Extraire TOUS les scores CVSS 4.0
    if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
        for idx, metric in enumerate(metrics['cvssMetricV40']):
            try:
                cvss_data = metric.get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity', 'MEDIUM').upper()
                source = metric.get('source', f'CNA-{idx+1}')
                if score:
                    all_scores.append((float(score), '4.0', severity, source))
            except Exception as e:
                logger.warning(f"Error parsing CVSS 4.0 metric #{idx}: {e}")
    
    # 3. Extraire TOUS les scores CVSS 3.1
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        for idx, metric in enumerate(metrics['cvssMetricV31']):
            try:
                cvss_data = metric.get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity', 'MEDIUM').upper()
                source = metric.get('source', f'CNA-{idx+1}')
                if score:
                    all_scores.append((float(score), '3.1', severity, source))
            except Exception as e:
                logger.warning(f"Error parsing CVSS 3.1 metric #{idx}: {e}")
    
    # 4. Extraire TOUS les scores CVSS 3.0
    if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
        for idx, metric in enumerate(metrics['cvssMetricV30']):
            try:
                cvss_data = metric.get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity', 'MEDIUM').upper()
                source = metric.get('source', f'CNA-{idx+1}')
                if score:
                    all_scores.append((float(score), '3.0', severity, source))
            except Exception as e:
                logger.warning(f"Error parsing CVSS 3.0 metric #{idx}: {e}")
    
    # 5. Extraire TOUS les scores CVSS 2.0
    if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        for idx, metric in enumerate(metrics['cvssMetricV2']):
            try:
                cvss_data = metric.get('cvssData', {})
                score = cvss_data.get('baseScore')
                source = metric.get('source', f'CNA-{idx+1}')
                if score:
                    score = float(score)
                    severity = cvss2_to_severity(score)
                    all_scores.append((score, '2.0', severity, source))
            except Exception as e:
                logger.warning(f"Error parsing CVSS 2.0 metric #{idx}: {e}")
    
    # 6. Retourner le score MAXIMUM
    if all_scores:
        # Trier par score décroissant
        all_scores.sort(reverse=True, key=lambda x: x[0])
        max_score, version, severity, source = all_scores[0]
        
        # Logger tous les scores trouvés
        if len(all_scores) > 1:
            logger.info(f"📊 Scores CVSS trouvés ({len(all_scores)}): {[(s[0], s[1], s[3]) for s in all_scores]}")
            logger.info(f"✅ Score MAXIMUM retenu: {max_score} (CVSS {version}, {severity}, source={source})")
        else:
            logger.info(f"✅ Score CVSS unique: {max_score} (CVSS {version}, {severity}, source={source})")
        
        return severity, max_score, version
    
    # Aucun score trouvé
    logger.warning(f"❌ No CVSS metrics found for CVE")
    return "MEDIUM", 5.0, "N/A"

# ========== IMPORT SERVICES ==========
def import_new_cves_from_cveorg_api():
    """Import NEW CVEs from CVE.org API as PRIMARY source (NOTE: This is disabled - no public API for bulk CVE import)
    
    CVE.org doesn't provide a public API for bulk CVE import, so this function is kept for reference.
    Instead, we use the enhancement function below to add product data to existing CVEs.
    """
    logger.info("⚠️ CVE.org bulk import: Using enhancement instead (no public bulk import API)")
    return {'imported': 0, 'source': 'CVEORG_ENHANCEMENT'}


def merge_cve_from_sources(cve_id: str, source: str, cve_data: dict):
    """Merge CVE data from multiple sources
    
    If CVE exists:
    - Keep the highest CVSS score
    - Keep CVE.org dates as reference
    - Add source to sources_secondary
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if CVE exists
        cursor.execute("SELECT id, cvss_score, source FROM cves WHERE cve_id = ?", (cve_id,))
        existing = cursor.fetchone()
        
        if existing:
            existing_score = existing['cvss_score'] or 0
            new_score = cve_data.get('cvss_score', 0)
            
            # Use higher score
            final_score = max(existing_score, new_score)
            
            # Get CVE.org data if not already set
            if existing['source'] != 'CVEORG' and source == 'CVEORG':
                # Update with CVE.org as primary
                cursor.execute('''
                    UPDATE cves 
                    SET source = ?, cvss_score = ?, 
                        published_date = COALESCE(?, published_date),
                        last_updated = COALESCE(?, last_updated)
                    WHERE cve_id = ?
                ''', (
                    'CVEORG',
                    final_score,
                    cve_data.get('published_date'),
                    cve_data.get('last_updated'),
                    cve_id
                ))
            else:
                # Just update score if higher
                if new_score > existing_score:
                    cursor.execute("UPDATE cves SET cvss_score = ? WHERE cve_id = ?", 
                                 (new_score, cve_id))
            
            # Add to secondary sources
            cursor.execute('''
                INSERT INTO cve_sources (cve_id, source_name, added_at)
                VALUES (?, ?, datetime('now'))
            ''', (existing['id'], source))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.debug(f"Could not merge {cve_id} from {source}: {e}")


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
                    # Utiliser format_date_for_display pour formater correctement
                    formatted_date = format_date_for_display(published_date_raw)
                    if formatted_date.get('iso_utc') and formatted_date['iso_utc'] != 'Invalid Date':
                        published_date = formatted_date['iso_utc']
                    else:
                        # Fallback
                        published_date = published_date_raw.replace('T', ' ').split('.')[0]
                else:
                    published_date = None
                
                # Extract last modified date (if available in API response)
                last_modified_raw = cve_data.get('lastModified', '') or published_date_raw
                if last_modified_raw:
                    formatted_last_mod = format_date_for_display(last_modified_raw)
                    if formatted_last_mod.get('iso_utc') and formatted_last_mod['iso_utc'] != 'Invalid Date':
                        last_modified_date = formatted_last_mod['iso_utc']
                    else:
                        last_modified_date = last_modified_raw.replace('T', ' ').split('.')[0] if last_modified_raw else published_date
                else:
                    last_modified_date = published_date
                
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
                imported_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
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
                    last_modified_date or imported_at,
                    'NVD'
                ))
                # Insert each unique product for this CVE (avoid duplicates)
                for p in product_list:
                    vendor_val = (p.get('vendor') or 'Unknown').strip()[:50]
                    product_val = (p.get('product') or 'Multiple Products').strip()[:50]
                    confidence_val = float(p.get('confidence', 0.0))
                    
                    # STRICT VALIDATION: skip if product is invalid/corrupted
                    if not _is_valid_affected_product(vendor_val, product_val):
                        logger.debug(f"⛔ Skipping invalid product for {cve_id}: {vendor_val}/{product_val}")
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


def _should_reject_cve(cve_id, products):
    """Check if CVE should be rejected based on blacklisted products"""
    if not products:
        return False
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        for product in products:
            if isinstance(product, dict):
                vendor = product.get('vendor', '').strip().lower()
                product_name = product.get('product', '').strip().lower()
            elif isinstance(product, str):
                # Handle string format like "vendor: product"
                parts = product.split(':')
                vendor = parts[0].strip().lower() if len(parts) > 0 else ''
                product_name = parts[1].strip().lower() if len(parts) > 1 else ''
            else:
                continue
            
            if not vendor or not product_name:
                continue
            
            # Check if this product is blacklisted
            cursor.execute('''
                SELECT status FROM technologies 
                WHERE LOWER(vendor) = ? AND LOWER(product) = ? LIMIT 1
            ''', (vendor, product_name))
            
            tech_row = cursor.fetchone()
            if tech_row and tech_row['status'] == 'OUT_OF_SCOPE':
                conn.close()
                return True
        
        conn.close()
        return False
    except Exception as e:
        logger.debug(f"Error checking blacklist for {cve_id}: {str(e)}")
        return False


def import_from_cvedetails():
    """Import CVEs from CVE Details API using /vulnerability/important-cves endpoint"""
    
    api_token = os.environ.get('CVEDETAILS_API_TOKEN')
    
    if not api_token:
        logger.warning("⚠️ CVE Details: API token not configured (set CVEDETAILS_API_TOKEN)")
        return {'imported': 0, 'source': 'cvedetails'}
    
    logger.info("🚀 Starting CVE Details import from official API...")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        imported_count = 0
        start_time = time.time()
        
        # CVE Details API endpoint - use search endpoint instead of important-cves
        # because important-cves only returns critical/very recent ones
        # API Base: https://www.cvedetails.com/api/v1
        api_url = "https://www.cvedetails.com/api/v1/vulnerability/search"
        
        # Prepare headers with authentication
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        
        # Pagination and search parameters for /vulnerability/search endpoint
        # Using a broad search query to get various CVEs
        params = {
            "query": "*",  # Search all CVEs
            "page": 1,
            "limit": 100,
            "orderby": "date",
            "order": "desc"
        }
        
        logger.info(f"📡 Fetching CVEs from CVE Details search API...")
        logger.debug(f"   URL: {api_url}")
        logger.debug(f"   Using Bearer token authentication")
        
        response = requests.get(api_url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        cves_data = response.json()
        
        # Handle API response structure - CVE Details returns pagination format
        if isinstance(cves_data, dict) and 'results' in cves_data:
            cves_list = cves_data['results']
        elif isinstance(cves_data, dict) and 'data' in cves_data:
            cves_list = cves_data['data']
        elif isinstance(cves_data, dict) and 'vulnerabilities' in cves_data:
            cves_list = cves_data['vulnerabilities']
        elif isinstance(cves_data, dict) and 'important_cves' in cves_data:
            cves_list = cves_data['important_cves']
        elif isinstance(cves_data, dict) and 'records' in cves_data:
            cves_list = cves_data['records']
        elif isinstance(cves_data, list):
            cves_list = cves_data
        else:
            logger.warning("⚠️ Unexpected CVE Details API response format")
            logger.info(f"   Response keys: {list(cves_data.keys()) if isinstance(cves_data, dict) else 'N/A'}")
            return {'imported': 0, 'source': 'cvedetails'}
            return {'imported': 0, 'source': 'cvedetails'}
        
        logger.info(f"📊 Found {len(cves_list)} important CVEs from CVE Details")
        
        # Debug: log first CVE structure to see available fields
        if cves_list:
            logger.info(f"🔍 Sample CVE Details response structure: {list(cves_list[0].keys())}")
        
        for cve_data in cves_list:
            try:
                # Extract CVE ID - CVE Details API returns 'cveId' field (camelCase)
                cve_id = (cve_data.get('cveId') or cve_data.get('id') or 
                         cve_data.get('cve_id') or cve_data.get('cve'))
                
                if not cve_id:
                    logger.debug(f"⚠️ No CVE ID found in response: {list(cve_data.keys())}")
                    continue
                
                logger.info(f"🔍 Processing CVE: {cve_id}")
                
                # Ensure CVE ID is in proper format
                if not cve_id.startswith('CVE-'):
                    cve_id = f"CVE-{cve_id}"
                
                # Extract CVSS score from CVEdetails - try different CVSS versions in priority order
                cvss_score = 0
                cvss_version = 'N/A'
                
                # CVEdetails API provides maxCvssBaseScorev4, v3, v2 fields
                # Priority: 4 > 3 > 2
                if 'maxCvssBaseScorev4' in cve_data and cve_data['maxCvssBaseScorev4']:
                    try:
                        cvss_score = float(cve_data['maxCvssBaseScorev4'])
                        cvss_version = '4.0'
                    except (ValueError, TypeError):
                        pass
                
                if cvss_score == 0 and 'maxCvssBaseScorev3' in cve_data and cve_data['maxCvssBaseScorev3']:
                    try:
                        cvss_score = float(cve_data['maxCvssBaseScorev3'])
                        cvss_version = '3.1'
                    except (ValueError, TypeError):
                        pass
                
                if cvss_score == 0 and 'maxCvssBaseScorev2' in cve_data and cve_data['maxCvssBaseScorev2']:
                    try:
                        cvss_score = float(cve_data['maxCvssBaseScorev2'])
                        cvss_version = '2.0'
                    except (ValueError, TypeError):
                        pass
                
                if cvss_score > 0:
                    logger.debug(f"   ✅ Got CVSS {cvss_version}/{cvss_score} from CVEdetails")
                
                severity = _get_severity_from_cvss(cvss_score)
                
                # Get description from 'summary' field (CVE Details API field)
                description = (cve_data.get('summary') or cve_data.get('description') or 
                              cve_data.get('title') or '')
                
                # Extract products using NLP
                products = nlp_extractor.extract_products(description)
                products_json = json.dumps(products) if products else '[]'
                
                # Check blacklist
                if _should_reject_cve(cve_id, products):
                    logger.debug(f"⏭️ Skipped {cve_id} (blacklist)")
                    continue
                
                # Get published date (CVE Details uses 'publishDate' field)
                published = (cve_data.get('publishDate') or cve_data.get('published_date') or 
                            cve_data.get('published') or cve_data.get('date'))
                
                # Check if CVE already exists
                cursor.execute("SELECT id, source FROM cves WHERE cve_id = ?", (cve_id,))
                existing = cursor.fetchone()
                
                # If CVE already exists, update source to include 'cvedetails'
                if existing:
                    existing_id, existing_source = existing
                    
                    # Get existing CVSS score to compare
                    cursor.execute("SELECT cvss_score, cvss_version FROM cves WHERE id = ?", (existing_id,))
                    existing_cve = cursor.fetchone()
                    existing_score = existing_cve['cvss_score'] if existing_cve else 0
                    existing_version = existing_cve['cvss_version'] if existing_cve else 'N/A'
                    
                    # Build combined source list
                    sources = set()
                    if existing_source:
                        sources.update(existing_source.split(','))
                    sources.add('cvedetails')
                    combined_source = ','.join(sorted(sources))
                    
                    # Use best version/score combination
                    # IMPORTANT: If CVEdetails has no score (0), prefer existing score
                    best_score, best_version = compare_cvss(
                        float(existing_score or 0), existing_version,
                        float(cvss_score or 0) if cvss_score > 0 else 0, cvss_version  # Only use CVEdetails score if it's > 0
                    )
                    
                    # If we still have no score, keep existing (don't overwrite with 0)
                    if best_score == 0 and existing_score > 0:
                        best_score = existing_score
                        best_version = existing_version
                    
                    cursor.execute("""
                        UPDATE cves SET source = ?, cvss_score = ?, cvss_version = ? WHERE id = ?
                    """, (combined_source, best_score, best_version, existing_id))
                    
                    if best_score > float(existing_score or 0) or get_cvss_priority(best_version) > get_cvss_priority(existing_version):
                        logger.info(f"✅ Updated {cve_id} source to: {combined_source}, CVSS: {existing_version} {existing_score} → {best_version} {best_score}")
                    else:
                        logger.info(f"✅ Updated {cve_id} source to: {combined_source}")
                else:
                    # Insert new CVE
                    imported_at = datetime.utcnow().isoformat()
                    cursor.execute("""
                        INSERT INTO cves (
                            cve_id, description, severity, cvss_score, cvss_version,
                            published_date, source, imported_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_id,
                        description[:2000] if description else '',
                        severity,
                        cvss_score,
                        cvss_version,  # Use detected CVSS version from detail API
                        published or datetime.utcnow().isoformat(),
                        'cvedetails',
                        imported_at
                    ))
                    logger.info(f"✅ Added {cve_id} with {len(products)} products (CVSS: {cvss_version}/{cvss_score})")
                    
                    # Insert affected products
                    for product in products:
                        if isinstance(product, dict):
                            vendor = (product.get('vendor') or 'Unknown').strip()[:50]
                            prod_name = (product.get('product') or 'Multiple').strip()[:50]
                        elif isinstance(product, str):
                            parts = product.split(':')
                            vendor = parts[0].strip()[:50] if len(parts) > 0 else 'Unknown'
                            prod_name = parts[1].strip()[:50] if len(parts) > 1 else 'Multiple'
                        else:
                            continue
                        
                        # STRICT VALIDATION: skip invalid/corrupted products
                        if not _is_valid_affected_product(vendor, prod_name):
                            logger.debug(f"⛔ Skipping invalid product for {cve_id}: {vendor}/{prod_name}")
                            continue
                        
                        try:
                            cursor.execute("""
                                INSERT OR IGNORE INTO affected_products (cve_id, vendor, product)
                                VALUES (?, ?, ?)
                            """, (cve_id, vendor, prod_name))
                        except Exception as e:
                            logger.debug(f"  Error inserting product {vendor}:{prod_name}: {str(e)}")
                
                imported_count += 1
                
            except Exception as e:
                error_str = str(e).lower()
                if 'database is locked' in error_str:
                    # Database is locked by another thread - retry with exponential backoff
                    logger.debug(f"⏳ Database locked for {cve_id}, retrying...")
                    time.sleep(0.5)  # Wait 500ms before retrying
                    try:
                        # Retry the operation
                        cursor.execute("SELECT id, source FROM cves WHERE cve_id = ?", (cve_id,))
                        existing = cursor.fetchone()
                        if existing:
                            existing_id, existing_source = existing
                            cursor.execute("SELECT cvss_score, cvss_version FROM cves WHERE id = ?", (existing_id,))
                            existing_cve = cursor.fetchone()
                            if existing_cve:
                                logger.debug(f"✅ Retry successful for {cve_id}")
                    except Exception as retry_e:
                        logger.debug(f"⚠️ Retry also failed for {cve_id}: {str(retry_e)}")
                else:
                    logger.error(f"❌ Error processing CVE Details entry: {str(e)}", exc_info=True)
                continue
        
        conn.commit()
        conn.close()
        
        elapsed = time.time() - start_time
        logger.info(f"✅ CVE Details import completed in {elapsed:.2f}s")
        logger.info(f"📊 Imported {imported_count} CVEs from CVE Details")
        
        return {'imported': imported_count, 'source': 'cvedetails'}
        
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"⚠️ CVE Details: Connection error - {str(e)}")
        return {'imported': 0, 'source': 'cvedetails'}
    except requests.exceptions.HTTPError as e:
        if "401" in str(e) or "403" in str(e):
            logger.warning(f"⚠️ CVE Details: Authentication failed - check your API token")
        elif "404" in str(e):
            logger.warning(f"⚠️ CVE Details: Endpoint not found - API structure may have changed")
        else:
            logger.error(f"⚠️ CVE Details API HTTP error: {str(e)}")
        return {'imported': 0, 'source': 'cvedetails'}
    except Exception as e:
        logger.error(f"⚠️ CVE Details import failed: {str(e)}")
        return {'imported': 0, 'source': 'cvedetails'}

def import_from_cveorg():
    """
    Import CVEs from official CVE.org (MITRE) with precise vendor/product info
    Uses the CVE.org REST API to get accurate affected products and dates
    REPLACES all products with official MITRE data, UPDATES dates from authoritative source
    
    Uses the new CVEEnrichmentService for optimized enrichment
    """
    logger.info("🚀 Starting CVE.org enhancement - REPLACING products with official MITRE data...")
    
    try:
        # Utiliser le nouveau service d'enrichissement (limite à 100 CVEs par run)
        stats = CVEEnrichmentService.enrich_all_pending_cves(limit=100)
        
        logger.info(f"✅ CVE.org enhancement completed in {stats['duration']}s")
        logger.info(f"📊 Enhanced {stats['total_products_added']} products, "
                   f"{stats['total_dates_updated']} dates updated, "
                   f"{stats['total_errors']} errors")
        
        return {
            'imported': stats['total_products_added'],
            'updated': stats['total_dates_updated'],
            'source': 'cveorg',
            'processed': stats['total_processed'],
            'errors': stats['total_errors']
        }
        
    except Exception as e:
        logger.error(f"⚠️ CVE.org enhancement failed: {str(e)}")
        return {'imported': 0, 'source': 'cveorg', 'error': str(e)}

def import_from_msrc():
    """Import CVEs from Microsoft Security Response Center using MSRCImporter"""
    logger.info("🚀 Starting MSRC import from Microsoft CVRF API...")
    
    try:
        from app.ingestion.msrc_importer import MSRCImporter
        
        # Initialize MSRC importer
        importer = MSRCImporter()
        
        # Get latest CVEs from MSRC
        cves = importer.get_latest_cves()
        
        if not cves:
            logger.info("ℹ️ No MSRC CVEs available")
            return {'imported': 0, 'source': 'msrc', 'note': 'No CVEs available'}
        
        logger.info(f"📊 Found {len(cves)} CVEs from MSRC")
        
        import_count = 0
        duplicate_count = 0
        
        conn = sqlite3.connect('ctba_platform.db')
        cursor = conn.cursor()
        
        for cve_data in cves:
            # MSRCImporter returns 'id' not 'cve_id'
            cve_id = cve_data.get('id', '').strip()
            if not cve_id or not cve_id.startswith('CVE-'):
                continue
            
            # Check if CVE already exists
            cursor.execute("SELECT cve_id, source FROM cves WHERE cve_id = ?", (cve_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update source to include 'msrc'
                existing_source = existing[1] or ''
                if 'msrc' not in existing_source:
                    new_source = f"{existing_source},msrc" if existing_source else 'msrc'
                    cursor.execute("UPDATE cves SET source = ?, updated_at = ? WHERE cve_id = ?",
                                 (new_source, datetime.utcnow().isoformat() + 'Z', cve_id))
                    logger.info(f"✅ Updated {cve_id} source to include MSRC")
                duplicate_count += 1
                continue
            
            # Extract data - MSRCImporter structure
            description = cve_data.get('description', 'No description available')
            cvss_score = float(cve_data.get('cvss', 7.0))
            severity = _get_severity_from_cvss(cvss_score)
            products = cve_data.get('affected_products', [])
            references = cve_data.get('references', [])
            published_date = cve_data.get('published', datetime.utcnow().isoformat() + 'Z')
            
            # Check against blacklist
            in_blacklist = False
            if products:
                for product in products:
                    vendor = str(product.get('vendor', '')).lower()
                    prod_name = str(product.get('product', '')).lower()
                    cursor.execute(
                        "SELECT id FROM technologies WHERE LOWER(vendor) = ? AND LOWER(product) = ? AND status = 'DEFERRED'",
                        (vendor, prod_name)
                    )
                    if cursor.fetchone():
                        in_blacklist = True
                        break
            
            if in_blacklist:
                logger.info(f"⏭️  Skipping {cve_id} (in blacklist)")
                continue
            
            # Insert CVE (using available columns only)
            now_iso = datetime.utcnow().isoformat() + 'Z'
            cursor.execute("""
                INSERT INTO cves (
                    cve_id, description, published_date, cvss_score, severity,
                    source, status, imported_at, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                description[:5000],
                published_date,
                cvss_score,
                severity,
                'msrc',
                'PENDING',
                now_iso,
                now_iso
            ))
            
            import_count += 1
            if import_count % 10 == 0:
                logger.info(f"   📊 Imported {import_count} CVEs from MSRC...")
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ MSRC import completed: imported {import_count} new CVEs, updated {duplicate_count} existing")
        return {'imported': import_count, 'updated': duplicate_count, 'source': 'msrc'}
        
    except ImportError as e:
        logger.warning(f"⚠️ MSRC importer not available: {str(e)}")
        return {'imported': 0, 'source': 'msrc', 'error': 'MSRCImporter not available'}
    except Exception as e:
        logger.error(f"❌ MSRC import error: {str(e)}")
        logger.exception(e)
        return {'imported': 0, 'source': 'msrc', 'error': str(e)}
        return {'imported': 0, 'source': 'msrc', 'error': str(e)}

def import_from_hackuity():
    """Import CVEs from Hackuity threat intelligence platform"""
    logger.info("🔧 Hackuity importer called (no data source configured)")
    return {'imported': 0, 'source': 'hackuity'}

def import_manual_entries():
    """Import manually entered CVEs from the database"""
    logger.info("📝 Processing manually entered CVEs...")
    try:
        conn = sqlite3.connect('ctba_platform.db')
        cursor = conn.cursor()
        
        # Check if manual_cves table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='manual_cves'")
        if not cursor.fetchone():
            logger.info("⚠️  No manual CVEs table found")
            conn.close()
            return {'imported': 0, 'source': 'manual'}
        
        # Get unprocessed manual CVEs
        cursor.execute("""
            SELECT id, cve_id, description, cvss_score, affected_products, references, created_at
            FROM manual_cves
            WHERE processed = 0
            LIMIT 100
        """)
        
        manual_cves = cursor.fetchall()
        imported_count = 0
        
        for cve_row in manual_cves:
            cve_id, desc, cvss, products, refs, created = cve_row[1], cve_row[2], cve_row[3], cve_row[4], cve_row[5], cve_row[6]
            
            # Check if CVE already exists
            cursor.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,))
            if cursor.fetchone():
                continue
            
            # Extract products using improved NLP
            extracted_products = nlp_extractor.extract_products(desc, cve_id) if desc else []
            
            # Parse references if provided
            ref_list = []
            if refs:
                try:
                    ref_list = json.loads(refs) if isinstance(refs, str) else refs
                except:
                    ref_list = []
            
            # Insert CVE
            cursor.execute("""
                INSERT INTO cves (
                    cve_id, description, published_date, cvss_score,
                    severity, affected_products, references, source,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                desc,
                datetime.utcnow().isoformat() + 'Z',
                cvss or 5.0,
                _get_severity_from_cvss(cvss or 5.0),
                json.dumps([{'vendor': p.get('vendor', 'Unknown'), 
                           'product': p.get('product', 'Unknown')} for p in extracted_products]),
                json.dumps(ref_list),
                'manual',
                'PENDING',
                datetime.utcnow().isoformat() + 'Z',
                datetime.utcnow().isoformat() + 'Z'
            ))
            
            # Mark as processed
            cursor.execute("UPDATE manual_cves SET processed = 1, imported_date = ? WHERE id = ?",
                         (datetime.utcnow().isoformat(), cve_row[0]))
            
            imported_count += 1
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Manual CVE import completed: imported {imported_count} CVEs")
        return {'imported': imported_count, 'source': 'manual'}
    
    except Exception as e:
        logger.error(f"❌ Manual CVE import failed: {e}")
        return {'imported': 0, 'source': 'manual', 'error': str(e)}

def start_import_scheduler():
    """
    Start background scheduler for automatic CVE imports
    
    Import Strategy (every 30 minutes):
    - Phase 1: Direct CVE.org scan (last 3 days) - catches newest CVEs before NVD
    - Phase 2: NVD + MSRC import (last 7 days) - primary sources with CVSS scores
    - Phase 3: CVE Details import (last 7 days) - additional coverage
    - Phase 4: CVE.org enrichment - adds detailed product info to all imported CVEs
    
    This multi-source approach ensures maximum coverage and up-to-date information.
    """
    logger.info("=" * 80)
    logger.info("🚀 Starting multi-source CVE import scheduler")
    logger.info("=" * 80)
    logger.info("📡 Import Sources:")
    logger.info("   1️⃣  CVE.org (direct scan) - Real-time updates, bypasses NVD delay")
    logger.info("   2️⃣  NVD + MSRC - Primary sources with official CVSS scores")
    logger.info("   3️⃣  CVE Details - Additional coverage and context")
    logger.info("   4️⃣  CVE.org enrichment - Detailed product information")
    logger.info("⏱️  Frequency: Every 30 minutes")
    logger.info("=" * 80)
    
    # Run import immediately
    # ✅ CORRECTION: Utiliser la nouvelle API multi-sources
    def run_importers():
        """Run multi-source CVE import using the new API service"""
        try:
            logger.info("⏳ Exécution de l'import multi-sources automatique...")
            from services.cve_fetcher_service import CVEFetcherService
            import sqlite3
            from datetime import datetime
            import pytz
            
            # 🆕 NOUVEAU: Scanner CVE.org directement avec enrichissement NVD automatique
            logger.info("🔍 Phase 1: Scan CVE.org avec enrichissement NVD automatique...")
            try:
                # enrich_with_nvd=True active l'enrichissement CVSS automatique
                cveorg_cves = CVEFetcherService.fetch_recent_cves_from_cveorg(days=7, limit=100, enrich_with_nvd=True)
                enriched = sum(1 for cve in cveorg_cves if cve.get('cvss_score', 0) > 0)
                logger.info(f"📡 CVE.org: {len(cveorg_cves)} CVEs trouvés, {enriched} avec scores CVSS")
            except Exception as cveorg_error:
                logger.warning(f"⚠️ Erreur scan CVE.org: {cveorg_error}")
                cveorg_cves = []
            
            # 🔄 Phase 2: Récupérer depuis toutes les sources (NVD, MSRC, CVE Details)
            logger.info("📥 Phase 2: Import multi-sources (NVD, MSRC, CVE Details)...")
            all_sources_data = CVEFetcherService.fetch_all_sources(days=30, limit=500)
            nvd_cves = all_sources_data.get("all", [])
            
            # 🆕 Phase 3: CVE Details en complément
            logger.info("📥 Phase 3: Import depuis CVE Details...")
            try:
                from services.cve_details_fetcher import fetch_recent_cves_from_cvedetails
                cvedetails_cves = fetch_recent_cves_from_cvedetails(days=7, limit=100)
                logger.info(f"📡 CVE Details: {len(cvedetails_cves)} CVEs récupérés")
            except Exception as cvedetails_error:
                logger.warning(f"⚠️ Erreur CVE Details: {cvedetails_error}")
                cvedetails_cves = []
            
            # Fusionner les trois sources (CVE.org direct + NVD + CVE Details)
            cves_by_id = {}
            for cve in cveorg_cves + nvd_cves + cvedetails_cves:
                cve_id = cve['cve_id']
                # Si CVE existe déjà, garder la version avec le meilleur score
                if cve_id in cves_by_id:
                    existing_score = cves_by_id[cve_id].get('cvss_score', 0) or 0
                    new_score = cve.get('cvss_score', 0) or 0
                    if new_score > existing_score:
                        cves_by_id[cve_id] = cve
                else:
                    cves_by_id[cve_id] = cve
            
            cves = list(cves_by_id.values())
            
            if not cves:
                logger.info("ℹ️ Aucun nouveau CVE à importer")
                return
            
            # Import dans la base de données
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            imported = 0
            updated = 0
            
            for cve in cves:
                cve_id = cve['cve_id']
                source = cve.get('source', 'Unknown')
                
                try:
                    cursor.execute("SELECT id, cvss_score, source FROM cves WHERE cve_id = ?", (cve_id,))
                    existing = cursor.fetchone()
                    
                    if existing:
                        existing_score = existing[1] if existing[1] else 0
                        new_score = cve.get('cvss_score', 0)
                        
                        if new_score > existing_score:
                            cursor.execute("""
                                UPDATE cves
                                SET cvss_score = ?, cvss_version = ?, severity = ?, 
                                    description = ?, last_updated = ?, source = ?
                                WHERE cve_id = ?
                            """, (
                                new_score,
                                cve.get('cvss_version', 'N/A'),
                                cve.get('severity', 'UNKNOWN'),
                                cve.get('description', '')[:2000],
                                datetime.now(pytz.UTC).isoformat(),
                                source,
                                cve_id
                            ))
                            updated += 1
                    else:
                        imported_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
                        
                        cursor.execute('''
                            INSERT INTO cves 
                            (cve_id, description, severity, cvss_score, cvss_version, 
                             published_date, imported_at, last_updated, source, status)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            cve_id,
                            cve.get('description', '')[:2000],
                            cve.get('severity', 'UNKNOWN'),
                            cve.get('cvss_score', 0),
                            cve.get('cvss_version', 'N/A'),
                            cve.get('published_date', ''),
                            imported_at,
                            cve.get('last_updated', imported_at),
                            source,
                            'PENDING'
                        ))
                        
                        # Produits affectés
                        for product in cve.get('affected_products', [])[:10]:
                            vendor = product.get('vendor', 'Unknown')[:50]
                            product_name = product.get('product', 'Multiple Products')[:50]
                            confidence = product.get('confidence', 0.0)
                            
                            if vendor and product_name:
                                cursor.execute('''
                                    INSERT OR IGNORE INTO affected_products 
                                    (cve_id, vendor, product, confidence)
                                    VALUES (?, ?, ?, ?)
                                ''', (cve_id, vendor, product_name, confidence))
                        
                        imported += 1
                    
                    conn.commit()
                    
                except Exception as e:
                    logger.error(f"❌ Erreur import {cve_id}: {str(e)}")
                    continue
            
            conn.close()
            
            logger.info(f"📊 Import automatique terminé: {imported} importés, {updated} mis à jour depuis 3 sources")
            logger.info(f"   └─ Sources: CVE.org ({len(cveorg_cves)}), NVD/MSRC ({len(nvd_cves)}), CVE Details ({len(cvedetails_cves)})")
            
            # 🚀 Phase 4: Enrichir TOUS les CVEs avec CVE.org pour avoir les produits complets
            try:
                logger.info("🔄 Phase 4: Enrichissement CVE.org (produits affectés, dates exactes)...")
                enrich_stats = CVEEnrichmentService.enrich_all_pending_cves(limit=100)
                logger.info(f"✅ Phase 4: {enrich_stats.get('total_products_added', 0)} produits ajoutés")
            except Exception as enrich_error:
                logger.error(f"⚠️ Erreur enrichissement CVE.org: {enrich_error}")
            
            # 🆕 Phase 5: Ré-enrichir les CVEs avec score CVSS = 0 depuis NVD (OPTIONNEL - backup)
            # Cette phase est maintenant moins critique car Phase 1 enrichit déjà pendant l'import
            try:
                logger.info("🔄 Phase 5: Vérification finale NVD pour CVEs sans score...")
                
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                
                # Trouver les CVEs avec score 0 (limité à 20 pour ne pas ralentir)
                cursor.execute("""
                    SELECT cve_id FROM cves 
                    WHERE (cvss_score IS NULL OR cvss_score = 0 OR cvss_score = 0.0)
                    AND status = 'PENDING'
                    ORDER BY imported_at DESC
                    LIMIT 20
                """)
                cves_without_score = [row[0] for row in cursor.fetchall()]
                
                if cves_without_score:
                    logger.info(f"📊 {len(cves_without_score)} CVEs sans score trouvés (vérification NVD)...")
                    
                    enriched_count = 0
                    for cve_id in cves_without_score:
                        try:
                            # Récupérer depuis NVD
                            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                            response = requests.get(url, timeout=10)
                            
                            if response.status_code == 200:
                                data = response.json()
                                vulnerabilities = data.get("vulnerabilities", [])
                                
                                if vulnerabilities:
                                    vuln = vulnerabilities[0]
                                    cve_data = vuln.get("cve", {})
                                    metrics = cve_data.get("metrics", {})
                                    
                                    cvss_score = 0.0
                                    severity = "UNKNOWN"
                                    cvss_version = "N/A"
                                    cvss_vector = "N/A"
                                    
                                    # Chercher CVSS v3.1
                                    if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                                        cvss_score = float(cvss_data.get("baseScore", 0))
                                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                                        cvss_version = "3.1"
                                        cvss_vector = cvss_data.get("vectorString", "N/A")
                                    # CVSS v3.0
                                    elif "cvssMetricV30" in metrics and len(metrics["cvssMetricV30"]) > 0:
                                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                                        cvss_score = float(cvss_data.get("baseScore", 0))
                                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                                        cvss_version = "3.0"
                                        cvss_vector = cvss_data.get("vectorString", "N/A")
                                    # CVSS v2.0
                                    elif "cvssMetricV2" in metrics and len(metrics["cvssMetricV2"]) > 0:
                                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                                        cvss_score = float(cvss_data.get("baseScore", 0))
                                        cvss_version = "2.0"
                                        cvss_vector = cvss_data.get("vectorString", "N/A")
                                        if cvss_score >= 7.0:
                                            severity = "HIGH"
                                        elif cvss_score >= 4.0:
                                            severity = "MEDIUM"
                                        else:
                                            severity = "LOW"
                                    
                                    # Si score trouvé, mettre à jour
                                    if cvss_score > 0:
                                        cursor.execute("""
                                            UPDATE cves 
                                            SET cvss_score = ?, severity = ?, cvss_version = ?, 
                                                cvss_vector = ?, last_updated = ?
                                            WHERE cve_id = ?
                                        """, (
                                            cvss_score,
                                            severity,
                                            cvss_version,
                                            cvss_vector,
                                            datetime.now(pytz.UTC).isoformat(),
                                            cve_id
                                        ))
                                        conn.commit()
                                        enriched_count += 1
                                        logger.info(f"✅ {cve_id}: Score CVSS enrichi → {cvss_score} ({severity})")
                            
                            # Rate limiting NVD (max 5 requêtes par 30 secondes sans API key)
                            time.sleep(0.8)
                            
                        except Exception as cve_enrich_error:
                            logger.debug(f"⏳ {cve_id}: Pas encore dans NVD ou erreur")
                            continue
                    
                    if enriched_count > 0:
                        logger.info(f"✅ Phase 5: {enriched_count}/{len(cves_without_score)} CVEs enrichis (backup)")
                    else:
                        logger.info(f"ℹ️  Phase 5: Aucun nouveau score trouvé (CVEs trop récents)")
                else:
                    logger.info("✅ Phase 5: Tous les CVEs ont déjà des scores CVSS")
                
                conn.close()
                
            except Exception as nvd_enrich_error:
                logger.error(f"⚠️ Erreur enrichissement NVD: {nvd_enrich_error}")
            
            logger.info("=" * 80)
            logger.info("✅ Cycle d'import automatique complet terminé")
            logger.info("=" * 80)
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'import automatique: {e}")

    # Premier import au démarrage (optionnel - décommenter si souhaité)
    # run_importers()
    
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
    """Serve the dashboard HTML as the main page. If a React build exists, serve it dynamically.
    This checks for the `frontend/build/index.html` at request time so a build can be produced
    while the server is running without needing a restart.
    """
    try:
        # Compute frontend build index dynamically to avoid requiring a server restart
        base_dir = os.path.dirname(os.path.abspath(__file__))
        candidate_index = os.path.abspath(os.path.join(base_dir, '..', 'frontend', 'build', 'index.html'))
        candidate_static = os.path.abspath(os.path.join(base_dir, '..', 'frontend', 'build', 'static'))
        if os.path.isfile(candidate_index) and os.path.isdir(candidate_static):
            try:
                # Ensure static mount exists (idempotent)
                app.mount('/static', StaticFiles(directory=candidate_static), name='static')
            except Exception:
                pass
            return FileResponse(candidate_index, media_type='text/html')

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
        "display_timezone": "Africa/Tunis (UTC+1)",
        "current_time": get_current_local_time(),
        "supported_formats": {
            "database": "UTC",
            "display": "UTC+1 (Africa/Tunis)",
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
    source: Optional[str] = Query(None, description="Filter by source (nvd, cvedetails, msrc, hackuity, manual)"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    force_refresh: bool = Query(False, description="Force immediate import of latest CVEs from all sources")
):
    """
    Get CVEs with filtering options - CORRIGÉ
    """
    try:
        # If force_refresh is requested, run importers in background
        if force_refresh:
            logger.info("🔄 Force refresh requested - importing from all sources...")
            try:
                # Import synchrone pour avoir les résultats immédiatement
                import_stats = {
                    'nvd': 0,
                    'cvedetails': 0,
                    'cveorg': 0
                }
                
                # Import NVD
                try:
                    nvd_result = import_from_nvd()
                    import_stats['nvd'] = nvd_result.get('imported', 0)
                except Exception as e:
                    logger.warning(f"⚠️ Erreur import NVD: {str(e)[:100]}")
                
                # Import CVEdetails
                try:
                    cvedetails_result = import_from_cvedetails()
                    import_stats['cvedetails'] = cvedetails_result.get('imported', 0)
                except Exception as e:
                    logger.warning(f"⚠️ Erreur import CVEdetails: {str(e)[:100]}")
                
                # Enrichissement CVE.org (limite à 50 pour ne pas bloquer)
                try:
                    cveorg_result = import_from_cveorg()
                    import_stats['cveorg'] = cveorg_result.get('imported', 0)
                except Exception as e:
                    logger.warning(f"⚠️ Erreur enrichissement CVE.org: {str(e)[:100]}")
                
                total = sum(import_stats.values())
                logger.info(f"✅ Force refresh terminé: {total} CVEs importés/enrichis (NVD:{import_stats['nvd']}, CVEdetails:{import_stats['cvedetails']}, CVE.org:{import_stats['cveorg']})")
            except Exception as e:
                logger.warning(f"⚠️ Force refresh encountered errors: {e}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build query
        query = "SELECT id, cve_id, description, severity, cvss_score, cvss_version, published_date, status, analyst, decision_date, decision_comments, imported_at, last_updated, source as source_primary, NULL as sources_secondary FROM cves WHERE 1=1"
        params = []
        
        # ✅ PAS de filtre de date par défaut - afficher TOUS les CVEs récents
        # Le tri par published_date DESC assurera que les plus récents sont en premier

        # Status filter
        if status and status in ['PENDING', 'ACCEPTED', 'REJECTED', 'DEFERRED']:
            query += " AND status = ?"
            params.append(status)
        else:
            # Default: afficher PENDING et DEFERRED (mais pas ACCEPTED/REJECTED)
            query += " AND status IN ('PENDING', 'DEFERRED')"
        
        # Severity filter
        if severity and severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            query += " AND severity = ?"
            params.append(severity)
        else:
            # ✅ Par défaut: afficher uniquement CRITICAL et HIGH
            query += " AND severity IN ('CRITICAL', 'HIGH')"

        # Vendor/Product filtering
        if vendor:
            query += " AND EXISTS (SELECT 1 FROM affected_products ap WHERE ap.cve_id = cves.cve_id AND LOWER(ap.vendor) LIKE ? )"
            params.append(f"%{vendor.lower()}%")
        if product:
            query += " AND EXISTS (SELECT 1 FROM affected_products ap2 WHERE ap2.cve_id = cves.cve_id AND LOWER(ap2.product) LIKE ? )"
            params.append(f"%{product.lower()}%")
        
        # Source filtering
        if source and source in ['nvd', 'cvedetails', 'msrc', 'hackuity', 'manual']:
            query += " AND source = ?"
            params.append(source)

        # ✅ Tri par date de mise à jour puis publication (les plus récents en premier)
        query += " ORDER BY last_updated DESC, published_date DESC, cvss_score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        
        cves = []
        
        for row in cursor.fetchall():
            try:
                cve = dict(row)
                cve_id = cve['cve_id']
                
                # Parse sources: if source is "NVD,cvedetails", primary=NVD, secondary=[cvedetails]
                source_str = cve.get('source_primary', '')
                if source_str and ',' in source_str:
                    sources_list = source_str.split(',')
                    cve['source_primary'] = sources_list[0]  # First is primary
                    # Create secondary sources list
                    cve['sources_secondary'] = [
                        {'name': s.strip(), 'type': 'secondary', 'added_at': cve.get('imported_at', 'N/A')}
                        for s in sources_list[1:]
                    ]
                else:
                    # Single source - just primary
                    cve['source_primary'] = source_str
                    cve['sources_secondary'] = []
                
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
                
                # 🔄 ENRICHISSEMENT À LA VOLÉE : Si pas de produits ou produits suspects, enrichir avec CVE.org
                should_enrich = False
                source_primary = cve.get('source_primary', '')
                
                # Vérifier si le CVE n'a pas encore été enrichi avec CVE.org
                if 'cveorg' not in source_primary.lower():
                    # Cas 1: Pas de produits du tout
                    if not products_list or (len(products_list) == 1 and products_list[0]['vendor'] == 'Unknown'):
                        should_enrich = True
                    # Cas 2: Produits suspects (URLs, WWW, etc.)
                    elif any('www.' in p['vendor'].lower() or 'http' in p['vendor'].lower() or 
                            'www.' in p['product'].lower() or 'advisories' in p['product'].lower() 
                            for p in products_list):
                        should_enrich = True
                
                # Enrichir si nécessaire
                if should_enrich:
                    try:
                        from services.cve_enrichment_service import CVEEnrichmentService
                        
                        # Enrichir en temps réel (avec un curseur de connexion séparé)
                        conn_enrich = get_db_connection()
                        enrich_stats = CVEEnrichmentService.enrich_single_cve(cve_id, conn_enrich)
                        conn_enrich.close()
                        
                        # Si enrichissement réussi, recharger les produits
                        if enrich_stats['products_added'] > 0:
                            cursor2.execute('''
                                SELECT vendor, product, confidence 
                                FROM affected_products 
                                WHERE cve_id = ?
                            ''', (cve_id,))
                            enriched_rows = cursor2.fetchall()
                            
                            if enriched_rows:
                                products_list = []
                                for r in enriched_rows:
                                    products_list.append({
                                        'vendor': r['vendor'], 
                                        'product': r['product'], 
                                        'confidence': float(r['confidence'] or 0.0)
                                    })
                                cve['affected_products'] = products_list
                                logger.info(f"✅ Enrichi à la volée: {cve_id} ({enrich_stats['products_added']} produits)")
                    except Exception as enrich_error:
                        # Ne pas bloquer l'affichage si l'enrichissement échoue
                        logger.debug(f"⚠️ Enrichissement à la volée échoué pour {cve_id}: {str(enrich_error)[:100]}")
                        pass

                # Add a short summary
                cve['short_description'] = (cve.get('description') or '')[:300]
                
                # Format date using format_date_for_display
                if cve['published_date']:
                    try:
                        formatted_date = format_date_for_display(cve['published_date'])
                        cve['published_date_formatted'] = formatted_date.get('formatted', 'N/A')
                        cve['published_date_utc'] = formatted_date.get('utc', 'N/A')
                        cve['published_date_local'] = formatted_date.get('local', 'N/A')
                        cve['timezone'] = formatted_date.get('timezone', 'UTC')
                    except Exception as e:
                        logger.warning(f"Error formatting date for CVE {cve_id}: {e}")
                        cve['published_date_formatted'] = cve['published_date'].replace('T', ' ')
                else:
                    cve['published_date_formatted'] = 'N/A'
                
                # Format last_updated date
                if cve.get('last_updated'):
                    try:
                        formatted_date = format_date_for_display(cve['last_updated'])
                        cve['last_updated_formatted'] = formatted_date.get('formatted', 'N/A')
                    except Exception as e:
                        logger.warning(f"Error formatting last_updated for CVE {cve_id}: {e}")
                        cve['last_updated_formatted'] = cve['last_updated'].replace('T', ' ')
                else:
                    cve['last_updated_formatted'] = 'N/A'
                
                # Build sources list (primary + all secondaries)
                sources_list = []
                primary = cve.get('source_primary', 'unknown')
                if primary:
                    sources_list.append({
                        'name': primary,
                        'type': 'primary',
                        'added_at': cve.get('imported_at', 'N/A')
                    })
                
                # Parse and add secondary sources
                secondaries = cve.get('sources_secondary')
                if secondaries:
                    try:
                        import json
                        if isinstance(secondaries, str):
                            secondaries = json.loads(secondaries)
                        if isinstance(secondaries, list):
                            for src in secondaries:
                                sources_list.append({
                                    'name': src.get('name', 'unknown'),
                                    'type': 'secondary',
                                    'added_at': src.get('added_at', 'N/A')
                                })
                    except Exception as e:
                        logger.debug(f"Error parsing sources_secondary for {cve_id}: {e}")
                
                cve['sources_list'] = sources_list
                
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
    cursor.execute("SELECT * FROM cves WHERE status = 'PENDING' AND severity IN ('HIGH','MEDIUM') ORDER BY last_updated DESC, published_date DESC LIMIT 50")
    
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
    query1 = "SELECT * FROM cves WHERE 1=1 AND status = 'PENDING' AND severity IN ('HIGH','MEDIUM') ORDER BY last_updated DESC, published_date DESC LIMIT 50"
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
    query4 = "SELECT cve_id, severity FROM cves WHERE status = 'PENDING' ORDER BY last_updated DESC, published_date DESC LIMIT 5"
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
        ORDER BY c.last_updated DESC, c.published_date DESC
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
    cursor.execute("SELECT cve_id, severity, status, published_date FROM cves ORDER BY last_updated DESC, published_date DESC")
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
            # Format date
            if cve['published_date']:
                formatted_date = format_date_for_display(cve['published_date'])
                cve['published_date_formatted'] = formatted_date.get('formatted', 'N/A')
            else:
                cve['published_date_formatted'] = 'N/A'
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
                    # Formater correctement la date
                    formatted_date = format_date_for_display(published_date)
                    if formatted_date.get('iso_utc') and formatted_date['iso_utc'] != 'Invalid Date':
                        published_date = formatted_date['iso_utc']
                
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
                imported_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
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
            ORDER BY c.last_updated DESC, c.published_date DESC
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


@app.post("/api/nlp/clean-affected-products")
async def clean_affected_products(limit: int = 100):
    """
    Nettoyer et normaliser les produits affectés existants
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Récupérer tous les produits affectés
        cursor.execute("""
            SELECT id, vendor, product, cve_id FROM affected_products
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        
        affected_products = cursor.fetchall()
        updated = 0
        removed = 0
        
        for row in affected_products:
            if isinstance(row, dict):
                ap_id = row['id']
                vendor = row['vendor']
                product = row['product']
                cve_id = row['cve_id']
            else:
                ap_id, vendor, product, cve_id = row[0], row[1], row[2], row[3]
            
            # Nettoyer using the NLP extractor's methods
            cleaned_vendor, cleaned_product = nlp_extractor._clean_vendor_product(vendor, product)
            
            # Vérifier si c'est valide
            if nlp_extractor._is_valid_extraction(cleaned_vendor, cleaned_product):
                # Vérifier si changé
                if cleaned_vendor != vendor or cleaned_product != product:
                    logger.info(f"Cleaning {cve_id}: {vendor}/{product} -> {cleaned_vendor}/{cleaned_product}")
                    cursor.execute("""
                        UPDATE affected_products 
                        SET vendor = ?, product = ? 
                        WHERE id = ?
                    """, (cleaned_vendor, cleaned_product, ap_id))
                    updated += 1
            else:
                # Supprimer les mauvaises extractions
                logger.info(f"Removing invalid extraction for {cve_id}: {vendor}/{product}")
                cursor.execute("DELETE FROM affected_products WHERE id = ?", (ap_id,))
                removed += 1
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "processed": len(affected_products),
            "updated": updated,
            "removed": removed,
            "message": f"Cleaned {updated} products, removed {removed} invalid extractions"
        }
    except Exception as e:
        logger.error(f"Error cleaning affected products: {e}", exc_info=True)
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


@app.post("/api/import/all-sources")
async def import_from_all_sources(
    days: int = Query(default=7, ge=1, le=30, description="Nombre de jours à importer"),
    enrich: bool = Query(default=True, description="Enrichir avec CVE.org après l'import")
):
    """
    Importe les CVEs récents depuis TOUTES les sources (NVD, CVEdetails, CVE.org)
    et retourne les CVEs importés
    
    Args:
        days: Nombre de jours précédents à importer (défaut: 7)
        enrich: Enrichir automatiquement avec CVE.org (défaut: true)
    
    Returns:
        Statistiques d'import et liste des CVEs importés
    """
    try:
        logger.info(f"🚀 Import multi-sources demandé (days={days}, enrich={enrich})")
        
        import_stats = {
            'nvd': {'imported': 0, 'updated': 0, 'errors': 0},
            'cvedetails': {'imported': 0, 'updated': 0, 'errors': 0},
            'cveorg_enrichment': {'products_added': 0, 'dates_updated': 0, 'processed': 0, 'errors': 0},
            'total_imported': 0,
            'total_updated': 0,
            'duration': 0
        }
        
        start_time = time.time()
        
        # 1. Import depuis NVD (source principale)
        logger.info("📡 Import depuis NVD...")
        try:
            nvd_result = import_from_nvd()
            import_stats['nvd']['imported'] = nvd_result.get('imported', 0)
            import_stats['nvd']['updated'] = nvd_result.get('updated', 0)
            import_stats['total_imported'] += import_stats['nvd']['imported']
            import_stats['total_updated'] += import_stats['nvd']['updated']
            logger.info(f"✅ NVD: {import_stats['nvd']['imported']} importés, {import_stats['nvd']['updated']} mis à jour")
        except Exception as e:
            logger.error(f"❌ Erreur import NVD: {str(e)}")
            import_stats['nvd']['errors'] = 1
        
        # 2. Import depuis CVEdetails (source secondaire)
        logger.info("📡 Import depuis CVEdetails...")
        try:
            cvedetails_result = import_from_cvedetails()
            import_stats['cvedetails']['imported'] = cvedetails_result.get('imported', 0)
            import_stats['cvedetails']['updated'] = cvedetails_result.get('updated', 0)
            import_stats['total_imported'] += import_stats['cvedetails']['imported']
            import_stats['total_updated'] += import_stats['cvedetails']['updated']
            logger.info(f"✅ CVEdetails: {import_stats['cvedetails']['imported']} importés")
        except Exception as e:
            logger.error(f"❌ Erreur import CVEdetails: {str(e)}")
            import_stats['cvedetails']['errors'] = 1
        
        # 3. Enrichissement avec CVE.org (si demandé)
        if enrich:
            logger.info("🔄 Enrichissement avec CVE.org...")
            try:
                cveorg_result = import_from_cveorg()
                import_stats['cveorg_enrichment']['products_added'] = cveorg_result.get('imported', 0)
                import_stats['cveorg_enrichment']['dates_updated'] = cveorg_result.get('updated', 0)
                import_stats['cveorg_enrichment']['processed'] = cveorg_result.get('processed', 0)
                import_stats['cveorg_enrichment']['errors'] = cveorg_result.get('errors', 0)
                logger.info(f"✅ CVE.org: {import_stats['cveorg_enrichment']['products_added']} produits enrichis")
            except Exception as e:
                logger.error(f"❌ Erreur enrichissement CVE.org: {str(e)}")
                import_stats['cveorg_enrichment']['errors'] = 1
        
        duration = time.time() - start_time
        import_stats['duration'] = round(duration, 2)
        
        # Récupérer les CVEs récemment importés pour les afficher
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT cve_id, description, severity, cvss_score, source, published_date, imported_at
            FROM cves
            WHERE status = 'PENDING'
            AND datetime(imported_at) >= datetime('now', '-' || ? || ' days')
            ORDER BY imported_at DESC
            LIMIT 100
        ''', (days,))
        
        recent_cves = []
        for row in cursor.fetchall():
            recent_cves.append({
                'cve_id': row['cve_id'],
                'description': (row['description'] or '')[:200],
                'severity': row['severity'],
                'cvss_score': row['cvss_score'],
                'source': row['source'],
                'published_date': row['published_date'],
                'imported_at': row['imported_at']
            })
        
        conn.close()
        
        logger.info(f"✅ Import multi-sources terminé en {duration:.2f}s - {import_stats['total_imported']} nouveaux CVEs")
        
        return {
            "success": True,
            "message": f"✅ Import multi-sources terminé : {import_stats['total_imported']} nouveaux CVEs importés",
            "statistics": import_stats,
            "recent_cves": recent_cves,
            "total_cves": len(recent_cves),
            "duration_seconds": duration
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur import multi-sources: {str(e)}")
        return {
            "success": False,
            "message": f"❌ Erreur: {str(e)}",
            "statistics": import_stats,
            "recent_cves": [],
            "total_cves": 0,
            "duration_seconds": 0
        }


@app.get("/api/import/stats")
async def get_import_stats():
    """
    Récupère les statistiques d'import des CVEs
    
    Returns:
        Statistiques par source et globales
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) as total FROM cves")
        total_cves = cursor.fetchone()['total']
        
        # CVEs par source
        cursor.execute("""
            SELECT source, COUNT(*) as count
            FROM cves
            GROUP BY source
        """)
        by_source = {}
        for row in cursor.fetchall():
            source = row['source'] or 'Unknown'
            by_source[source] = row['count']
        
        # CVEs enrichis avec CVE.org
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM cves
            WHERE source LIKE '%cveorg%'
        """)
        enriched_count = cursor.fetchone()['count']
        
        # CVEs récents (7 derniers jours)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM cves
            WHERE datetime(imported_at) >= datetime('now', '-7 days')
        """)
        recent_count = cursor.fetchone()['count']
        
        # CVEs par statut
        cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM cves
            GROUP BY status
        """)
        by_status = {}
        for row in cursor.fetchall():
            by_status[row['status']] = row['count']
        
        # CVEs par sévérité
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM cves
            GROUP BY severity
        """)
        by_severity = {}
        for row in cursor.fetchall():
            by_severity[row['severity']] = row['count']
        
        conn.close()
        
        return {
            "success": True,
            "statistics": {
                "total_cves": total_cves,
                "enriched_with_cveorg": enriched_count,
                "recent_7_days": recent_count,
                "by_source": by_source,
                "by_status": by_status,
                "by_severity": by_severity
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur récupération stats: {str(e)}")
        return {
            "success": False,
            "message": str(e),
            "statistics": {}
        }


class AuthRequest(BaseModel):
    username: str
    password: str


@app.post('/api/auth/login')
async def auth_login(req: AuthRequest):
    logger.info(f"Login attempt for user: {req.username}")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ? LIMIT 1', (req.username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        logger.warning(f"User not found: {req.username}")
        raise HTTPException(status_code=401, detail='Invalid credentials')
    logger.info(f"User found: {row['username']}, Role: {row['role']}")
    is_valid = _verify_password(row['password_salt'], row['password_hash'], req.password)
    logger.info(f"Password verification result: {is_valid}")
    if not is_valid:
        logger.warning(f"Invalid password for user: {req.username}")
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token = create_access_token({'sub': row['username'], 'role': row['role']}, expires_delta=timedelta(hours=8))
    logger.info(f"Login successful for user: {req.username}")
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
        decision_date = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
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


@app.post("/api/cves/test/{cve_id}/action")
async def cve_action_test(cve_id: str, action_request: CVEActionRequest):
    """Allow testing CVE actions without authentication"""
    try:
        # Validate action: only ACCEPTED or REJECTED are allowed via this endpoint
        if action_request.action not in [CVEStatus.ACCEPTED, CVEStatus.REJECTED]:
            raise HTTPException(status_code=400, detail='Invalid action - only ACCEPTED or REJECTED allowed')

        # Update cve status
        decision_date = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
        max_attempts = 5
        success = False
        last_err = None
        
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
                    'test_analyst',
                    decision_date,
                    action_request.comments,
                    decision_date,
                    cve_id
                ))

                # Log action
                cursor.execute('''
                    INSERT INTO cve_actions (cve_id, action, analyst, comments)
                    VALUES (?, ?, ?, ?)
                ''', (cve_id, action_str, 'test_analyst', action_request.comments))

                conn.commit()
                success = True
                break
            except sqlite3.OperationalError as oe:
                last_err = oe
                msg = str(oe).lower()
                if 'database is locked' in msg:
                    logger.warning('Database locked on attempt %d for cve_action_test %s; retrying...', attempt, cve_id)
                    time.sleep(0.1 * (2 ** (attempt - 1)))
                    continue
                else:
                    raise
            except Exception as e:
                last_err = e
                raise
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

        if not success:
            logger.error('Failed to perform cve_action_test for %s after %d attempts: %s', cve_id, max_attempts, last_err)
            raise HTTPException(status_code=500, detail='Database busy; please retry the action')

        return {'success': True, 'cve_id': cve_id, 'action': action_str}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing test action on CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/technologies/test")
async def add_technology_test(tech: TechnologyCreate):
    """Add a technology/product to the tracked list with a status - TEST version without auth"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert or ignore if exists
        cursor.execute('''
            INSERT OR IGNORE INTO technologies (vendor, product, status, added_by, reason)
            VALUES (?, ?, ?, ?, ?)
        ''', (tech.vendor[:50], tech.product[:50], tech.status, 'test_analyst', tech.reason[:200]))

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
                now = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
                # Find matching CVEs
                cursor.execute('SELECT DISTINCT cve_id FROM affected_products WHERE LOWER(vendor) = ? AND LOWER(product) = ?', (v, p))
                rows = cursor.fetchall()
                for r in rows:
                    cve_id = r['cve_id']
                    # Update CVE status to DEFERRED so it won't appear in default PENDING list
                    cursor.execute('UPDATE cves SET status = ?, analyst = ?, decision_date = ?, decision_comments = ?, last_updated = ? WHERE cve_id = ?', (
                        'DEFERRED', 'test_analyst', now, f'Marked OUT_OF_SCOPE due to technology {tech.vendor}/{tech.product}', now, cve_id
                    ))
                    # Log action for audit
                    cursor.execute('INSERT INTO cve_actions (cve_id, action, analyst, comments) VALUES (?, ?, ?, ?)', (cve_id, 'DEFERRED', 'test_analyst', f'Auto-deferred due to OUT_OF_SCOPE technology {tech.vendor}/{tech.product}'))
                conn.commit()
        except Exception as e:
            logger.warning('Error deferring CVEs after OUT_OF_SCOPE add: %s', e)

        conn.close()

        return {'success': True, 'vendor': tech.vendor, 'product': tech.product, 'status': tech.status}
    except Exception as e:
        logger.error(f"Error adding technology: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cves/sorted")
def get_sorted_cves():
    """
    Endpoint pour récupérer les CVEs triées par score CVSS (4.0 prioritaire, sinon 3.1).
    """
    try:
        conn = get_db_connection()  # Utiliser get_db_connection au lieu de sqlite3.connect
        cursor = conn.cursor()

        # Récupérer les CVEs triées par CVSS
        query = """
        SELECT cve_id, description, cvss_score, published_date
        FROM cves
        ORDER BY cvss_score DESC
        LIMIT 50
        """
        cursor.execute(query)
        rows = cursor.fetchall()

        # Formater les résultats
        result = []
        for row in rows:
            cve_id = row['cve_id']
            description = row['description']
            cvss_score = row['cvss_score']
            published_date_raw = row['published_date']
            
            formatted_date = format_date_for_display(published_date_raw)
            
            # Calculer les jours depuis publication
            days_since = "N/A"
            if formatted_date.get("iso_local"):
                try:
                    local_date = datetime.fromisoformat(formatted_date["iso_local"])
                    now = datetime.now(pytz.timezone('Africa/Tunis'))
                    days_since = (now - local_date).days
                except:
                    pass
            
            result.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "published_date": formatted_date.get("formatted", "Invalid Date"),
                "days_since_published": days_since
            })

        conn.close()
        return {"cves": result, "timestamp": get_current_local_time()}

    except Exception as e:
        logger.error(f"Erreur lors de la récupération des CVEs triées : {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@app.post('/api/technologies')
async def create_technology(tech: TechnologyCreate):
    """Create/add a technology to blacklist - with analyst tracking"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get analyst from Authorization header or use default
        analyst = 'analyst1'  # Default, will be overridden by authenticated user in future
        
        # Insert or ignore if exists
        cursor.execute('''
            INSERT OR IGNORE INTO technologies (vendor, product, status, added_by, reason)
            VALUES (?, ?, ?, ?, ?)
        ''', (tech.vendor[:50], tech.product[:50], tech.status, analyst, tech.reason[:200]))

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
                now = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
                # Find matching CVEs
                cursor.execute('SELECT DISTINCT cve_id FROM affected_products WHERE LOWER(vendor) = ? AND LOWER(product) = ?', (v, p))
                rows = cursor.fetchall()
                for r in rows:
                    cve_id = r['cve_id']
                    # Update CVE status to DEFERRED
                    cursor.execute('UPDATE cves SET status = ?, analyst = ?, decision_date = ?, decision_comments = ?, last_updated = ? WHERE cve_id = ?', (
                        'DEFERRED', analyst, now, f'Marked OUT_OF_SCOPE due to technology {tech.vendor}/{tech.product}', now, cve_id
                    ))
                    # Log action for audit
                    cursor.execute('INSERT INTO cve_actions (cve_id, action, analyst, comments) VALUES (?, ?, ?, ?)', (cve_id, 'DEFERRED', analyst, f'Auto-deferred due to OUT_OF_SCOPE technology {tech.vendor}/{tech.product}'))
                conn.commit()
        except Exception as e:
            logger.warning('Error deferring CVEs after OUT_OF_SCOPE add: %s', e)
        
        conn.close()
        return {"success": True, "message": f"Technology {tech.vendor}/{tech.product} added to blacklist"}
    except Exception as e:
        logger.error(f"Error creating technology: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/technologies')
async def list_technologies(status: Optional[str] = Query(None, description="Filter by status (OUT_OF_SCOPE, PRIORITY, NORMAL)")):
    """List all technologies with optional status filter"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if status:
            cursor.execute('SELECT id, vendor, product, status, reason, added_by, created_at FROM technologies WHERE status = ? ORDER BY created_at DESC', (status,))
        else:
            cursor.execute('SELECT id, vendor, product, status, reason, added_by, created_at FROM technologies ORDER BY created_at DESC')
        
        rows = cursor.fetchall()
        technologies = [dict(row) for row in rows]
        conn.close()
        return {"success": True, "technologies": technologies}
    except Exception as e:
        logger.error(f"Error listing technologies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/technologies')
async def list_technologies(status: Optional[str] = Query(None, description="Filter by status (OUT_OF_SCOPE, PRIORITY, NORMAL)")):
    """List all technologies with optional status filter"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if status:
            cursor.execute('SELECT id, vendor, product, status, reason, added_by, created_at FROM technologies WHERE status = ? ORDER BY created_at DESC', (status,))
        else:
            cursor.execute('SELECT id, vendor, product, status, reason, added_by, created_at FROM technologies ORDER BY created_at DESC')
        
        rows = cursor.fetchall()
        technologies = [dict(row) for row in rows]
        conn.close()
        return {"success": True, "technologies": technologies}
    except Exception as e:
        logger.error(f"Error listing technologies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete('/api/technologies/{tech_id}')
async def delete_technology_api(tech_id: int):
    """Delete/reintegrate a technology from blacklist"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get technology info
        cursor.execute('SELECT vendor, product FROM technologies WHERE id = ?', (tech_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail='Technology not found')
        
        # Convert row to dict if needed
        if isinstance(row, dict):
            vendor = row['vendor']
            product = row['product']
        else:
            vendor = row[0]
            product = row[1]
        
        logger.info(f"Deleting technology: {vendor}/{product} (id={tech_id})")
        
        # Delete from technologies
        cursor.execute('DELETE FROM technologies WHERE id = ?', (tech_id,))
        conn.commit()
        
        # Mark corresponding CVEs back to PENDING if they were DEFERRED due to this OUT_OF_SCOPE
        cursor.execute('SELECT DISTINCT cve_id FROM affected_products WHERE LOWER(vendor) = ? AND LOWER(product) = ?', 
                      (vendor.lower(), product.lower()))
        cve_rows = cursor.fetchall()
        
        logger.info(f"Found {len(cve_rows)} CVEs to potentially revert")
        
        # Revert DEFERRED CVEs back to PENDING
        for cve_row in cve_rows:
            try:
                # Handle row format
                if isinstance(cve_row, dict):
                    cve_id = cve_row['cve_id']
                else:
                    cve_id = cve_row[0]
                
                cursor.execute('SELECT status FROM cves WHERE cve_id = ?', (cve_id,))
                cve = cursor.fetchone()
                if cve:
                    # Handle cve format
                    if isinstance(cve, dict):
                        cve_status = cve['status']
                    else:
                        cve_status = cve[0]
                    
                    if cve_status == 'DEFERRED':
                        cursor.execute('UPDATE cves SET status = ? WHERE cve_id = ?', ('PENDING', cve_id))
                        cursor.execute('INSERT INTO cve_actions (cve_id, action, analyst, comments) VALUES (?, ?, ?, ?)', 
                                      (cve_id, 'PENDING', 'analyst1', f'Reintegrated {vendor}/{product} from blacklist'))
                        logger.info(f"Reverted CVE {cve_id} from DEFERRED to PENDING")
            except Exception as e:
                logger.warning(f"Error processing CVE {cve_row}: {e}")
                continue
        
        conn.commit()
        conn.close()
        return {'success': True, 'message': f'Reintegrated {vendor}/{product} from blacklist', 'vendor': vendor, 'product': product}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting technology: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/technologies/{tech_id}')
async def get_technology(tech_id: int):
    """Get a specific technology by ID"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, vendor, product, status, reason, added_by, created_at FROM technologies WHERE id = ?', (tech_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail='Technology not found')
        return dict(row)
    except Exception as e:
        logger.error(f"Error fetching technology {tech_id}: {e}")
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


@app.get('/api/cve-actions')
async def get_cve_actions(
    action: Optional[str] = Query(None, description="Filter by action (ACCEPTED, REJECTED, DEFERRED)"),
    analyst: Optional[str] = Query(None, description="Filter by analyst username"),
    cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """
    Get CVE action history with optional filtering
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build query
        query = "SELECT id, cve_id, action, analyst, comments, action_date FROM cve_actions WHERE 1=1"
        params = []
        
        # Filters
        if action and action in ['ACCEPTED', 'REJECTED', 'DEFERRED']:
            query += " AND action = ?"
            params.append(action)
        
        if analyst:
            query += " AND analyst LIKE ?"
            params.append(f"%{analyst}%")
        
        if cve_id:
            query += " AND cve_id LIKE ?"
            params.append(f"%{cve_id}%")
        
        # Order by date descending and paginate
        query += " ORDER BY action_date DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        actions = []
        
        for row in cursor.fetchall():
            action_dict = dict(row)
            # Format the date for display
            if action_dict.get('action_date'):
                try:
                    # Parse ISO format date and format nicely
                    action_date = action_dict['action_date']
                    if isinstance(action_date, str):
                        # Try to parse and reformat
                        from datetime import datetime
                        parsed_date = datetime.fromisoformat(action_date.replace('Z', '+00:00'))
                        action_dict['action_date_formatted'] = parsed_date.strftime('%d/%m/%Y %H:%M:%S')
                        action_dict['action_date_local'] = parsed_date.strftime('%d/%m/%Y %H:%M:%S')
                    else:
                        action_dict['action_date_formatted'] = str(action_date)
                except Exception as e:
                    logger.warning(f"Error formatting action date: {e}")
                    action_dict['action_date_formatted'] = str(action_date)
            
            actions.append(action_dict)
        
        # Get total count
        count_query = "SELECT COUNT(*) FROM cve_actions WHERE 1=1"
        count_params = []
        
        if action and action in ['ACCEPTED', 'REJECTED', 'DEFERRED']:
            count_query += " AND action = ?"
            count_params.append(action)
        
        if analyst:
            count_query += " AND analyst LIKE ?"
            count_params.append(f"%{analyst}%")
        
        if cve_id:
            count_query += " AND cve_id LIKE ?"
            count_params.append(f"%{cve_id}%")
        
        cursor.execute(count_query, count_params)
        total = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "success": True,
            "actions": actions,
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total
            }
        }
    except Exception as e:
        logger.error(f"Error fetching CVE actions: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== MULTI-SOURCE CVE INGESTION ==========

class ManualCVEInput(BaseModel):
    """Manual CVE entry input model"""
    id: str = Field(..., description="CVE ID (e.g., CVE-2024-12345)")
    description: str = Field(..., description="Vulnerability description")
    published: Optional[str] = Field(None, description="Publication date ISO format")
    cvss: Optional[float] = Field(None, ge=0, le=10, description="CVSS score 0-10")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")
    cwe_id: Optional[str] = Field(None, description="CWE ID")
    affected_products: Optional[List[dict]] = Field(None, description="List of affected products")
    references: Optional[List[str]] = Field(None, description="Reference URLs")
    source_url: Optional[str] = Field(None, description="Source URL")
    status: Optional[str] = Field("IMPORTED", description="CVE status")
    notes: Optional[str] = Field(None, description="Analyst notes")


@app.post("/api/ingestion/nvd")
async def ingest_from_nvd(days: int = Query(7, ge=1, le=365)):
    """
    Import CVEs from NVD (National Vulnerability Database)
    Queries the NVD API for recently modified or published CVEs
    """
    try:
        logger.info(f"Starting NVD ingestion (last {days} days)...")
        # Use existing import_from_nvd function
        cves = import_from_nvd()
        return {
            "success": True,
            "source": "nvd",
            "imported_count": len(cves),
            "cve_ids": [cve.get('id') for cve in cves],
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"NVD ingestion error: {e}")
        raise HTTPException(status_code=500, detail=f"NVD ingestion failed: {str(e)}")


@app.post("/api/ingestion/cvedetails")
async def ingest_from_cvedetails(
    keyword: str = Query(..., description="Search keyword"),
    limit: int = Query(100, ge=1, le=1000)
):
    """
    Import CVEs from CVE Details
    Searches CVE Details database for CVEs matching the keyword
    """
    try:
        logger.info(f"Starting CVE Details ingestion: {keyword}")
        # TODO: Implement CVE Details API integration
        return {
            "success": True,
            "source": "cvedetails",
            "message": "CVE Details integration coming soon",
            "keyword": keyword,
            "limit": limit
        }
    except Exception as e:
        logger.error(f"CVE Details ingestion error: {e}")
        raise HTTPException(status_code=500, detail=f"CVE Details ingestion failed: {str(e)}")


@app.post("/api/ingestion/msrc")
async def ingest_from_msrc(
    year: int = Query(..., ge=1999, le=2100),
    month: int = Query(..., ge=1, le=12)
):
    """
    Import CVEs from Microsoft Security Response Center
    Retrieves CVEs from MSRC monthly bulletins for the specified month
    """
    try:
        logger.info(f"Starting MSRC ingestion: {year}-{month:02d}")
        # TODO: Implement MSRC API integration
        return {
            "success": True,
            "source": "msrc",
            "message": "MSRC integration coming soon",
            "year": year,
            "month": month
        }
    except Exception as e:
        logger.error(f"MSRC ingestion error: {e}")
        raise HTTPException(status_code=500, detail=f"MSRC ingestion failed: {str(e)}")


@app.post("/api/ingestion/hackuity")
async def ingest_from_hackuity(
    filter_type: str = Query(
        "recent",
        description="Filter: 'recent', 'exploitable', or search query"
    ),
    limit: int = Query(50, ge=1, le=500)
):
    """
    Import CVEs from Hackuity threat intelligence
    Retrieves CVEs from Hackuity's threat intelligence feed
    """
    try:
        logger.info(f"Starting Hackuity ingestion: {filter_type}")
        # TODO: Implement Hackuity API integration
        return {
            "success": True,
            "source": "hackuity",
            "message": "Hackuity integration coming soon",
            "filter_type": filter_type,
            "limit": limit
        }
    except Exception as e:
        logger.error(f"Hackuity ingestion error: {e}")
        raise HTTPException(status_code=500, detail=f"Hackuity ingestion failed: {str(e)}")


@app.post("/api/ingestion/manual")
async def ingest_manual_entry(cve_data: ManualCVEInput):
    """
    Manually enter a CVE into the system
    Validates and imports manually entered CVE data with comprehensive field validation
    """
    try:
        logger.info(f"Processing manual CVE entry: {cve_data.id}")
        
        # Basic validation
        if not cve_data.id.upper().startswith('CVE-'):
            raise ValueError("CVE ID must start with 'CVE-'")
        
        if len(cve_data.description) < 10:
            raise ValueError("Description must be at least 10 characters")
        
        # Store in database
        conn = sqlite3.connect('ctba_platform.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if CVE already exists
        cursor.execute("SELECT id FROM cves WHERE id = ?", (cve_data.id.upper(),))
        if cursor.fetchone():
            conn.close()
            raise ValueError(f"CVE {cve_data.id.upper()} already exists")
        
        # Insert new CVE
        insert_date = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO cves (id, description, cvss, cwe_id, source, imported_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_data.id.upper(),
            cve_data.description,
            cve_data.cvss or 0,
            cve_data.cwe_id or '',
            'manual',
            insert_date,
            'PENDING'
        ))
        
        # Insert affected products if provided
        if cve_data.affected_products:
            for product in cve_data.affected_products:
                cursor.execute("""
                    INSERT INTO affected_products (cve_id, vendor, product)
                    VALUES (?, ?, ?)
                """, (
                    cve_data.id.upper(),
                    product.get('vendor', 'Unknown'),
                    product.get('product', 'Unknown')
                ))
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "cve_id": cve_data.id.upper(),
            "source": "manual",
            "timestamp": insert_date
        }
        
    except ValueError as e:
        logger.warning(f"Manual entry validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Manual entry error: {e}")
        raise HTTPException(status_code=500, detail=f"Manual entry failed: {str(e)}")


@app.get("/api/ingestion/manual/template")
async def get_manual_entry_template():
    """
    Get template for manual CVE entry
    Returns a JSON template showing all available fields and their formats
    """
    return {
        "id": "CVE-2024-XXXXX",
        "description": "Detailed description of the vulnerability...",
        "published": datetime.utcnow().isoformat(),
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe_id": "CWE-200",
        "affected_products": [
            {
                "vendor": "Example Corp",
                "product": "Example Product",
                "version_affected": "1.0.0 - 2.0.1"
            }
        ],
        "references": [
            "https://example.com/security-advisory",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX"
        ],
        "source_url": "",
        "status": "IMPORTED",
        "notes": "Analyst notes or additional context..."
    }


@app.get("/api/ingestion/sources")
async def list_ingestion_sources():
    """
    List all available CVE ingestion sources
    Returns supported ingestion sources and their characteristics
    """
    return {
        "sources": [
            {
                "id": "nvd",
                "name": "National Vulnerability Database",
                "description": "Official NVD database with comprehensive CVE data",
                "endpoint": "POST /api/ingestion/nvd",
                "requires_auth": False,
                "rate_limit": "6 requests per 30 seconds"
            },
            {
                "id": "cvedetails",
                "name": "CVE Details",
                "description": "CVE Details database with CVSS and product information",
                "endpoint": "POST /api/ingestion/cvedetails",
                "requires_auth": False,
                "status": "Coming soon"
            },
            {
                "id": "msrc",
                "name": "Microsoft Security Response Center",
                "description": "Microsoft security bulletins and CVEs",
                "endpoint": "POST /api/ingestion/msrc",
                "requires_auth": False,
                "status": "Coming soon"
            },
            {
                "id": "hackuity",
                "name": "Hackuity",
                "description": "Threat intelligence with exploitability data",
                "endpoint": "POST /api/ingestion/hackuity",
                "requires_auth": True,
                "status": "Coming soon"
            },
            {
                "id": "manual",
                "name": "Manual Entry",
                "description": "Manually enter CVEs with validation",
                "endpoint": "POST /api/ingestion/manual",
                "requires_auth": True,
                "rate_limit": "No limit"
            }
        ]
    }


@app.get("/api/ingestion/status")
async def get_ingestion_status():
    """
    Get current ingestion status and statistics
    Returns summary of available ingestion sources
    """
    try:
        conn = sqlite3.connect('ctba_platform.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get total CVEs by source
        cursor.execute("""
            SELECT source, COUNT(*) as count 
            FROM cves 
            GROUP BY source
        """)
        
        source_stats = {}
        for row in cursor.fetchall():
            source_stats[row['source']] = row['count']
        
        conn.close()
        
        return {
            "total_cves": sum(source_stats.values()),
            "by_source": source_stats,
            "available_sources": [s['id'] for s in [
                {"id": "nvd"},
                {"id": "cvedetails"},
                {"id": "msrc"},
                {"id": "hackuity"},
                {"id": "manual"}
            ]],
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting ingestion status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/ingestion-sources')
async def get_ingestion_sources():
    """Get list of available CVE ingestion sources and their configuration"""
    try:
        # Reload environment variables to get fresh values
        load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
        
        # Define available sources
        sources = [
            {
                "id": "nvd",
                "name": "National Vulnerability Database",
                "description": "Official US government CVE repository",
                "enabled": True,  # NVD is always enabled
                "frequency": "30 minutes",
                "last_updated": None,
                "cve_count": 0
            },
            {
                "id": "cvedetails",
                "name": "CVE Details",
                "description": "Detailed vulnerability information with attack vectors",
                "enabled": bool(os.environ.get('CVEDETAILS_API_TOKEN')),  # Enabled if token is set
                "frequency": "30 minutes",
                "last_updated": None,
                "cve_count": 0,
                "requires_auth": True
            },
            {
                "id": "msrc",
                "name": "Microsoft Security Response Center",
                "description": "Microsoft security bulletins and vulnerability data",
                "enabled": True,
                "frequency": "30 minutes",
                "last_updated": None,
                "cve_count": 0
            },
            {
                "id": "hackuity",
                "name": "Hackuity",
                "description": "Real-time threat intelligence and exploitability data",
                "enabled": bool(os.environ.get('HACKUITY_API_KEY')),  # Enabled if API key is set
                "frequency": "30 minutes",
                "last_updated": None,
                "cve_count": 0,
                "requires_auth": True
            },
            {
                "id": "manual",
                "name": "Manual Entry",
                "description": "Manually entered CVEs by analysts",
                "enabled": True,
                "frequency": "30 minutes",
                "last_updated": None,
                "cve_count": 0
            }
        ]
        
        # Get CVE counts by source
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            for source in sources:
                cursor.execute("SELECT COUNT(*) as count FROM cves WHERE source = ?", (source['id'],))
                result = cursor.fetchone()
                if result:
                    source['cve_count'] = result['count']
            conn.close()
        except:
            pass
        
        return {
            "sources": sources,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting ingestion sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/api/manual-cve')
async def add_manual_cve(
    cve_id: str = Form(...),
    description: str = Form(...),
    cvss_score: Optional[float] = Form(None),
    affected_products: Optional[str] = Form(None),
    references: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    """Add a manually entered CVE to the system"""
    try:
        # Validate CVE ID format
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            raise HTTPException(status_code=400, detail="Invalid CVE ID format. Use CVE-YYYY-XXXXX")
        
        # Validate CVSS score if provided
        if cvss_score is not None and (cvss_score < 0 or cvss_score > 10):
            raise HTTPException(status_code=400, detail="CVSS score must be between 0 and 10")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if CVE already exists
        cursor.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=409, detail=f"CVE {cve_id} already exists in the system")
        
        # Extract products using improved NLP if description provided
        extracted_products = []
        if description:
            extracted_products = nlp_extractor.extract_products(description, cve_id)
        
        # Parse references JSON if provided
        ref_list = []
        if references:
            try:
                ref_list = json.loads(references) if isinstance(references, str) else references
            except:
                logger.warning(f"Could not parse references for manual CVE {cve_id}")
        
        # Parse affected products if provided
        products_list = []
        if affected_products:
            try:
                products_list = json.loads(affected_products) if isinstance(affected_products, str) else affected_products
            except:
                products_list = []
        
        # Use extracted products if no manual products provided
        if not products_list and extracted_products:
            products_list = [{'vendor': p.get('vendor', 'Unknown'), 
                            'product': p.get('product', 'Unknown')} for p in extracted_products]
        
        # Insert the manual CVE
        now = datetime.utcnow().isoformat() + 'Z'
        cursor.execute("""
            INSERT INTO cves (
                cve_id, description, published_date, cvss_score, severity,
                affected_products, references, source, status, created_by,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            description,
            now,
            cvss_score or 5.0,
            _get_severity_from_cvss(cvss_score or 5.0),
            json.dumps(products_list),
            json.dumps(ref_list),
            'manual',
            'PENDING',
            current_user.get('username', 'unknown'),
            now,
            now
        ))
        
        # Log the action
        cursor.execute("""
            INSERT INTO cve_actions (cve_id, action, analyst, comments)
            VALUES (?, ?, ?, ?)
        """, (
            cve_id,
            'CREATED',
            current_user.get('username', 'unknown'),
            'Manual CVE entry'
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Manual CVE {cve_id} added by {current_user.get('username', 'unknown')}")
        
        return {
            "success": True,
            "cve_id": cve_id,
            "message": f"CVE {cve_id} added successfully",
            "products_extracted": len(products_list)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding manual CVE: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/manual-cves')
async def get_manual_cves(
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get manually entered CVEs with optional status filtering"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if status:
            cursor.execute("""
                SELECT cve_id, description, cvss_score, severity, affected_products,
                       created_by, created_at, status
                FROM cves WHERE source = 'manual' AND status = ?
                ORDER BY created_at DESC
            """, (status,))
        else:
            cursor.execute("""
                SELECT cve_id, description, cvss_score, severity, affected_products,
                       created_by, created_at, status
                FROM cves WHERE source = 'manual'
                ORDER BY created_at DESC
            """)
        
        rows = cursor.fetchall()
        conn.close()
        
        cves = []
        for row in rows:
            cves.append({
                'cve_id': row['cve_id'],
                'description': row['description'],
                'cvss_score': row['cvss_score'],
                'severity': row['severity'],
                'affected_products': json.loads(row['affected_products']) if row['affected_products'] else [],
                'created_by': row['created_by'],
                'created_at': row['created_at'],
                'status': row['status']
            })
        
        return {
            "count": len(cves),
            "cves": cves
        }
    except Exception as e:
        logger.error(f"Error getting manual CVEs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== CVE FETCHER API INTEGRATION ==========
# Import CVE fetcher routes (nouvelles routes pour récupérer CVEs depuis NVD/CVE.org)
try:
    from api.cve_routes import router as cve_fetcher_router
    app.include_router(cve_fetcher_router, tags=["cve-fetcher"])
    logger.info("✅ CVE Fetcher API routes registered")
except ImportError as e:
    logger.warning(f"⚠️ CVE Fetcher routes not available: {e}")
except Exception as e:
    logger.error(f"❌ Error registering CVE Fetcher routes: {e}")

# ========== KPI & ANALYTICS INTEGRATION ==========
try:
    from api.kpi_routes import router as kpi_router
    app.include_router(kpi_router, tags=["kpi"])
    logger.info("✅ KPI & Analytics routes registered")
except ImportError as e:
    logger.warning(f"⚠️ KPI routes not available: {e}")
except Exception as e:
    logger.error(f"❌ Error registering KPI routes: {e}")

# ========== BULLETIN & DELIVERY ENGINE INTEGRATION ==========
# Import bulletin and delivery routes
try:
    from app.api.bulletin_routes import router as bulletin_router, region_router
    from app.api.delivery_routes import router as delivery_router
    from app.services.enhanced_delivery_engine import EnhancedBulletinDeliveryEngine
    from app.services.region_mailing_service import RegionMailingService
    from app.services.audit_logger import AuditLogger
    from services.email_service import EmailService
    
    # Register bulletin and delivery routes
    app.include_router(bulletin_router, prefix="/api", tags=["bulletins"])
    app.include_router(region_router, prefix="/api", tags=["regions"])
    app.include_router(delivery_router, prefix="/api", tags=["delivery", "audit"])
    
    # Initialize services
    delivery_engine = None
    mailing_service = RegionMailingService()
    audit_logger = AuditLogger()
    
    logger.info("✅ Bulletin management & delivery routes registered")
except ImportError as e:
    logger.warning(f"⚠️ Bulletin routes not available: {e}")
except Exception as e:
    logger.error(f"❌ Error registering bulletin routes: {e}")


# ============================================================================
# BULLETIN MANAGEMENT API ENDPOINTS
# ============================================================================
@app.post("/api/bulletins", response_model=Dict)
async def create_bulletin(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new bulletin with automatic CVE grouping by technology/product
    
    - **title**: Bulletin title
    - **body**: Optional bulletin body (can include HTML)
    - **regions**: List of region names (e.g., ["NORAM", "LATAM", "Europe", "APMEA"])
    - **cve_ids**: Optional list of CVE IDs to include in bulletin
    """
    try:
        # Parse JSON sans validation FastAPI
        data = await request.json()
        logger.info(f"📥 Received raw JSON: {data}")
        logger.info(f"👤 Current user: {current_user}")
        
        title = data.get('title')
        body = data.get('body')
        regions = data.get('regions', [])
        cve_ids = data.get('cve_ids', [])
        
        logger.info(f"✅ Parsed: title={title}, regions={regions}, cve_ids={cve_ids}")
        
        from services.bulletin_service import BulletinService
        
        username = current_user.get('username', 'unknown')
        logger.info(f"🔑 Creating bulletin with username: {username} from user: {current_user}")
        
        bulletin = BulletinService.create_bulletin(
            title=title,
            body=body,
            regions=regions,
            cve_ids=cve_ids,
            created_by=username
        )
        
        logger.info(f"✅ Bulletin created with created_by: {bulletin.get('created_by')}")
        
        return bulletin
    
    except Exception as e:
        logger.error(f"Error creating bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/bulletins", response_model=Dict)
async def get_bulletins(
    status: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """
    Get bulletins with optional filters
    
    - **status**: Filter by status (DRAFT, SENT, NOT_PROCESSED)
    - **region**: Filter by region
    - **limit**: Max results to return
    - **offset**: Pagination offset
    """
    try:
        from services.bulletin_service import BulletinService
        
        bulletins, total = BulletinService.get_bulletins(
            status=status,
            region=region,
            limit=limit,
            offset=offset
        )
        
        return {
            'bulletins': bulletins,
            'total': total,
            'limit': limit,
            'offset': offset
        }
    
    except Exception as e:
        logger.error(f"Error fetching bulletins: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/bulletins/{bulletin_id}", response_model=Dict)
async def get_bulletin_detail(
    bulletin_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed bulletin with CVEs, grouped CVEs, and attachments"""
    try:
        from services.bulletin_service import BulletinService
        
        bulletin = BulletinService.get_bulletin_detail(bulletin_id)
        
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        return bulletin
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching bulletin detail: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/bulletins/{bulletin_id}", response_model=Dict)
async def update_bulletin(
    bulletin_id: int,
    title: Optional[str] = Body(None),
    body: Optional[str] = Body(None),
    regions: Optional[List[str]] = Body(None),
    status: Optional[str] = Body(None),
    current_user: dict = Depends(get_current_user)
):
    """
    Update bulletin fields
    
    - **status**: Can be DRAFT, SENT, or NOT_PROCESSED
    """
    try:
        from services.bulletin_service import BulletinService
        
        bulletin = BulletinService.update_bulletin(
            bulletin_id=bulletin_id,
            title=title,
            body=body,
            regions=regions,
            status=status
        )
        
        return bulletin
    
    except Exception as e:
        logger.error(f"Error updating bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/bulletins/{bulletin_id}")
async def delete_bulletin(
    bulletin_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Delete bulletin (requires ADMINISTRATOR role)"""
    if current_user.get('role') != 'ADMINISTRATOR':
        raise HTTPException(status_code=403, detail="Administrator role required")
    
    try:
        from services.bulletin_service import BulletinService
        
        success = BulletinService.delete_bulletin(bulletin_id)
        
        return {'message': f'Bulletin {bulletin_id} deleted', 'success': success}
    
    except Exception as e:
        logger.error(f"Error deleting bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/bulletins/{bulletin_id}/close")
async def close_bulletin(
    bulletin_id: int,
    closure_reason: str = Body(..., embed=True),
    current_user: dict = Depends(get_current_user)
):
    """
    Manually close a bulletin
    
    - Allows analysts to mark a bulletin as closed with a reason
    - Updates status to CLOSED and records closure metadata
    - Stops automatic reminders for this bulletin
    """
    try:
        from datetime import datetime
        import pytz
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if bulletin exists
        cursor.execute('SELECT id, status, title FROM bulletins WHERE id = ?', (bulletin_id,))
        bulletin = cursor.fetchone()
        
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        # Update bulletin to CLOSED status
        now = datetime.now(pytz.UTC).isoformat()
        cursor.execute('''
            UPDATE bulletins
            SET status = 'CLOSED',
                closed_at = ?,
                closed_by = ?,
                closure_reason = ?,
                can_reopen = 1
            WHERE id = ?
        ''', (now, current_user.get('username', 'unknown'), closure_reason, bulletin_id))
        
        # Log the closure action
        cursor.execute('''
            INSERT INTO bulletin_logs (bulletin_id, action, region, recipients, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            bulletin_id,
            'CLOSED',
            'ALL',
            current_user.get('username', 'unknown'),
            f'Bulletin closed manually. Reason: {closure_reason}',
            now
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Bulletin #{bulletin_id} closed by {current_user.get('username')}")
        
        return {
            'bulletin_id': bulletin_id,
            'status': 'CLOSED',
            'closed_at': now,
            'closed_by': current_user.get('username'),
            'closure_reason': closure_reason,
            'message': 'Bulletin closed successfully'
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error closing bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/bulletins/{bulletin_id}/reopen")
async def reopen_bulletin(
    bulletin_id: int,
    reopen_reason: Optional[str] = Body(None, embed=True),
    current_user: dict = Depends(get_current_user)
):
    """
    Reopen a closed bulletin
    
    - Allows reopening of closed bulletins (if can_reopen is True)
    - Changes status back to SENT
    - Records reopening in audit trail
    """
    try:
        from datetime import datetime
        import pytz
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if bulletin exists and can be reopened
        cursor.execute('''
            SELECT id, status, closed_at, can_reopen, title
            FROM bulletins
            WHERE id = ?
        ''', (bulletin_id,))
        bulletin = cursor.fetchone()
        
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        bulletin_id_db, status, closed_at, can_reopen, title = bulletin
        
        if status != 'CLOSED':
            raise HTTPException(status_code=400, detail="Bulletin is not closed")
        
        if not can_reopen:
            raise HTTPException(status_code=403, detail="This bulletin cannot be reopened")
        
        # Reopen the bulletin
        now = datetime.now(pytz.UTC).isoformat()
        cursor.execute('''
            UPDATE bulletins
            SET status = 'SENT',
                reopened_at = ?,
                reopened_by = ?
            WHERE id = ?
        ''', (now, current_user.get('username', 'unknown'), bulletin_id))
        
        # Log the reopen action
        reason_msg = f' Reason: {reopen_reason}' if reopen_reason else ''
        cursor.execute('''
            INSERT INTO bulletin_logs (bulletin_id, action, region, recipients, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            bulletin_id,
            'REOPENED',
            'ALL',
            current_user.get('username', 'unknown'),
            f'Bulletin reopened manually.{reason_msg}',
            now
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Bulletin #{bulletin_id} reopened by {current_user.get('username')}")
        
        return {
            'bulletin_id': bulletin_id,
            'status': 'SENT',
            'reopened_at': now,
            'reopened_by': current_user.get('username'),
            'reopen_reason': reopen_reason,
            'message': 'Bulletin reopened successfully'
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reopening bulletin: {e}")
        if "no such column" in str(e).lower():
            raise HTTPException(
                status_code=500, 
                detail="Database schema outdated. Please restart the backend server to apply migrations."
            )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/bulletins/{bulletin_id}/reminder-status")
async def get_bulletin_reminder_status(
    bulletin_id: int,
    current_user: dict = Depends(get_current_user)
):
    """
    Get reminder status for a bulletin
    
    Returns information about reminders sent and days since bulletin was sent
    """
    try:
        from datetime import datetime
        import pytz
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # First check if the new columns exist
        cursor.execute("PRAGMA table_info(bulletins)")
        columns = {row[1] for row in cursor.fetchall()}
        
        has_new_columns = all([
            'reminder_7_sent_at' in columns,
            'reminder_14_sent_at' in columns,
            'escalation_30_sent_at' in columns,
            'closed_at' in columns
        ])
        
        if has_new_columns:
            cursor.execute('''
                SELECT sent_at, reminder_7_sent_at, reminder_14_sent_at, 
                       escalation_30_sent_at, closed_at, status
                FROM bulletins
                WHERE id = ?
            ''', (bulletin_id,))
            
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                raise HTTPException(status_code=404, detail="Bulletin not found")
            
            sent_at, r7, r14, r30, closed_at, status = result
        else:
            # Fallback for old schema
            cursor.execute('''
                SELECT sent_at, status
                FROM bulletins
                WHERE id = ?
            ''', (bulletin_id,))
            
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                raise HTTPException(status_code=404, detail="Bulletin not found")
            
            sent_at, status = result
            r7 = r14 = r30 = closed_at = None
        
        conn.close()
        
        response = {
            'bulletin_id': bulletin_id,
            'status': status,
            'sent_at': sent_at,
            'reminder_7_sent': bool(r7),
            'reminder_7_sent_at': r7,
            'reminder_14_sent': bool(r14),
            'reminder_14_sent_at': r14,
            'escalation_30_sent': bool(r30),
            'escalation_30_sent_at': r30,
            'is_closed': bool(closed_at),
            'closed_at': closed_at,
            'days_since_sent': None
        }
        
        # Calculate days since sent (regardless of closed status)
        if sent_at:
            try:
                sent_date = datetime.fromisoformat(sent_at.replace('Z', '+00:00'))
                now = datetime.now(pytz.UTC)
                response['days_since_sent'] = (now - sent_date).days
            except Exception as e:
                logger.warning(f"Error calculating days_since_sent for bulletin {bulletin_id}: {e}")
        
        return response
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting reminder status: {e}")
        if "no such column" in str(e).lower():
            raise HTTPException(
                status_code=500, 
                detail="Database schema outdated. Please restart the backend server to apply migrations."
            )
        raise HTTPException(status_code=500, detail=str(e))


    except Exception as e:
        logger.error(f"Error deleting bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/bulletins/{bulletin_id}/attachments")
async def add_bulletin_attachment(
    bulletin_id: int,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Add attachment to bulletin"""
    try:
        import os
        from services.bulletin_service import BulletinService
        
        # Save file to attachments directory
        attachments_dir = "attachments"
        os.makedirs(attachments_dir, exist_ok=True)
        
        filepath = os.path.join(attachments_dir, f"bulletin_{bulletin_id}_{file.filename}")
        
        with open(filepath, "wb") as f:
            content = await file.read()
            f.write(content)
        
        attachment = BulletinService.add_attachment(
            bulletin_id=bulletin_id,
            filename=file.filename,
            filepath=filepath
        )
        
        return attachment
    
    except Exception as e:
        logger.error(f"Error adding attachment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/bulletins/{bulletin_id}/send")
async def send_bulletin(
    bulletin_id: int,
    regions_override: Optional[List[str]] = Body(None),
    current_user: dict = Depends(get_current_user)
):
    """
    Send bulletin to specified regions with automatic mailing list resolution
    
    - Resolves To/Cc/Bcc lists automatically per region
    - Uses HTML template for email
    - Logs all sending actions
    - Updates bulletin status to SENT
    """
    try:
        from services.bulletin_service import BulletinService
        from app.services.enhanced_delivery_engine import EnhancedBulletinDeliveryEngine
        from app.services.region_mailing_service import RegionMailingService
        from services.email_service import EmailService
        from app.services.audit_logger import AuditLogger
        
        # Get bulletin details
        bulletin = BulletinService.get_bulletin_detail(bulletin_id)
        if not bulletin:
            raise HTTPException(status_code=404, detail="Bulletin not found")
        
        # Use override regions if provided, else use bulletin regions
        target_regions = regions_override if regions_override else bulletin['regions']
        
        # Initialize delivery services
        email_service = EmailService()
        mailing_service = RegionMailingService()
        audit_logger = AuditLogger()
        
        # Send bulletin to each region
        results = []
        for region_name in target_regions:
            try:
                # Get region details
                conn = sqlite3.connect('ctba_platform.db')
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM regions WHERE name = ?', (region_name,))
                region_row = cursor.fetchone()
                conn.close()
                
                if not region_row:
                    logger.warning(f"⚠️ Region '{region_name}' not found, skipping")
                    continue
                
                region_id = region_row[0]
                
                # Get mailing lists for region
                mailing_lists = mailing_service.get_region_mailing_lists(region_id)
                
                if not mailing_lists:
                    logger.warning(f"⚠️ No mailing lists for region '{region_name}', skipping")
                    continue
                
                # Send email
                to_recipients = mailing_lists.to_recipients
                cc_recipients = mailing_lists.cc_recipients if mailing_lists.cc_recipients else []
                bcc_recipients = mailing_lists.bcc_recipients if mailing_lists.bcc_recipients else []
                
                email_service.send_email(
                    to=to_recipients,
                    cc=cc_recipients,
                    bcc=bcc_recipients,
                    subject=bulletin['title'],
                    html_body=bulletin['body'] or "",
                    text_body=bulletin['body'] or ""
                )
                
                # Log delivery
                BulletinService.log_delivery(
                    bulletin_id=bulletin_id,
                    action='SENT',
                    region=region_name,
                    recipients=', '.join(to_recipients),
                    message=f"Bulletin sent successfully to {len(to_recipients)} recipients"
                )
                
                results.append({
                    'region': region_name,
                    'status': 'success',
                    'recipients_count': len(to_recipients)
                })
                
                logger.info(f"✅ Bulletin #{bulletin_id} sent to region {region_name}")
            
            except Exception as e:
                logger.error(f"❌ Error sending bulletin to region {region_name}: {e}")
                results.append({
                    'region': region_name,
                    'status': 'error',
                    'error': str(e)
                })
        
        # Update bulletin status to SENT
        BulletinService.update_bulletin(
            bulletin_id=bulletin_id,
            status='SENT'
        )
        
        return {
            'bulletin_id': bulletin_id,
            'results': results,
            'total_regions': len(target_regions),
            'successful': len([r for r in results if r['status'] == 'success'])
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/bulletins/{bulletin_id}/delivery-history")
async def get_bulletin_delivery_history(
    bulletin_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get delivery history and logs for a bulletin"""
    try:
        from services.bulletin_service import BulletinService
        
        history = BulletinService.get_delivery_history(bulletin_id)
        
        return {
            'bulletin_id': bulletin_id,
            'history': history,
            'count': len(history)
        }
    
    except Exception as e:
        logger.error(f"Error fetching delivery history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/bulletins/{bulletin_id}/close")
async def close_bulletin(
    bulletin_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Manually close a bulletin (stops reminders)"""
    try:
        from services.bulletin_reminder_service import reminder_service
        
        success = reminder_service.manually_close_bulletin(
            bulletin_id=bulletin_id,
            closed_by=current_user.get('username', 'unknown')
        )
        
        if success:
            return {'message': f'Bulletin {bulletin_id} closed', 'success': True}
        else:
            raise HTTPException(status_code=500, detail="Failed to close bulletin")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error closing bulletin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/bulletins/reminders/statistics")
async def get_reminder_statistics(current_user: dict = Depends(get_current_user)):
    """Get statistics about bulletin reminders"""
    try:
        from services.bulletin_reminder_service import reminder_service
        
        stats = reminder_service.get_reminder_statistics()
        
        return stats
    
    except Exception as e:
        logger.error(f"Error getting reminder statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# REGION MANAGEMENT API ENDPOINTS
# ============================================================================

@app.get("/api/regions")
async def get_regions(current_user: dict = Depends(get_current_user)):
    """Get all regions"""
    try:
        from services.bulletin_service import RegionService
        
        regions = RegionService.get_regions()
        
        return {
            'regions': regions,
            'count': len(regions)
        }
    
    except Exception as e:
        logger.error(f"Error fetching regions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# AI REMEDIATION ENDPOINTS
# ============================================================================

@app.post("/api/ai/remediation/{cve_id}")
async def generate_ai_remediation(cve_id: str):
    """
    Génère des recommandations de remédiation IA pour un CVE spécifique
    
    - **cve_id**: Identifiant du CVE (ex: CVE-2024-1234)
    
    Returns: Recommandations structurées en 4 sections
    
    NOTE: Endpoint public - pas d'authentification requise
    """
    try:
        # Récupérer le CVE depuis la base de données
        conn = sqlite3.connect('ctba_platform.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT cve_id, description, severity, cvss_score
            FROM cves
            WHERE cve_id = ?
        """, (cve_id,))
        
        cve_data = cursor.fetchone()
        
        if not cve_data:
            conn.close()
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
        cve_id_db = cve_data['cve_id']
        description = cve_data['description']
        severity = cve_data['severity']
        cvss_score = cve_data['cvss_score']
        
        # Récupérer les produits affectés
        cursor.execute("""
            SELECT vendor, product
            FROM affected_products
            WHERE cve_id = ?
            LIMIT 5
        """, (cve_id,))
        
        products_rows = cursor.fetchall()
        conn.close()
        
        # Formater les produits affectés
        affected_products = None
        if products_rows:
            products_list = [f"{row['vendor']}: {row['product']}" for row in products_rows]
            affected_products = ", ".join(products_list)
            logger.info(f"📦 Found {len(products_list)} affected products for {cve_id}")
        
        # Obtenir le service IA approprié
        ai_service, provider, model = get_ai_service()
        
        # Générer les recommandations
        logger.info(f"⚡ Generating remediation for {cve_id} with {provider}...")
        
        remediation = ai_service.generate_remediation(
            cve_id=cve_id_db,
            description=description or "No description available",
            severity=severity or "UNKNOWN",
            cvss_score=cvss_score or 0.0,
            affected_products=affected_products
        )
        
        logger.info(f"✅ Remediation generated for {cve_id} using {provider}")
        
        return {
            "cve_id": cve_id_db,
            "severity": severity,
            "cvss_score": cvss_score,
            "remediation": remediation,
            "provider": provider,
            "model": model,
            "generated_at": datetime.now(pytz.UTC).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating AI remediation for {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=f"AI generation error: {str(e)}")


@app.get("/api/ai/status")
async def get_ai_status():
    """
    Obtient le statut du service IA
    
    Returns: Informations sur le modèle chargé
    
    NOTE: Endpoint public - pas d'authentification requise
    """
    try:
        ai_service, provider, model = get_ai_service()
        model_info = ai_service.get_model_info()
        
        return {
            "status": "ready",
            "provider": provider,
            "model": model,
            "model_info": model_info
        }
        
    except Exception as e:
        logger.error(f"Error getting AI status: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


@app.post("/api/ai/load-model")
async def load_ai_model(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Charge le modèle IA en arrière-plan (peut prendre 1-2 minutes)
    
    - Nécessite rôle ADMINISTRATOR
    NOTE: Service actuel utilise templates légers (pas de chargement nécessaire)
    """
    if current_user.get('role') != 'ADMINISTRATOR':
        raise HTTPException(status_code=403, detail="Administrator role required")
    
    return {
        "status": "ready",
        "message": "Template-based AI service is always ready (no loading required)"
    }


@app.post("/api/regions")
async def create_region(
    name: str = Body(...),
    description: Optional[str] = Body(None),
    recipients: str = Body(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new region
    
    - **name**: Region name (e.g., "NORAM", "LATAM", "Europe", "APMEA")
    - **description**: Optional description
    - **recipients**: Comma-separated email addresses
    """
    if current_user.get('role') not in ['ADMINISTRATOR', 'VOC_LEAD']:
        raise HTTPException(status_code=403, detail="Administrator or VOC_LEAD role required")
    
    try:
        from services.bulletin_service import RegionService
        
        region = RegionService.create_region(
            name=name,
            description=description,
            recipients=recipients
        )
        
        return region
    
    except Exception as e:
        logger.error(f"Error creating region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/regions/{region_id}")
async def get_region(
    region_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get single region details"""
    try:
        from services.bulletin_service import RegionService
        
        region = RegionService.get_region(region_id)
        
        if not region:
            raise HTTPException(status_code=404, detail="Region not found")
        
        return region
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/regions/{region_id}")
async def update_region(
    region_id: int,
    description: Optional[str] = Body(None),
    recipients: Optional[str] = Body(None),
    current_user: dict = Depends(get_current_user)
):
    """Update region (allows archiving by updating description)"""
    if current_user.get('role') not in ['ADMINISTRATOR', 'VOC_LEAD']:
        raise HTTPException(status_code=403, detail="Administrator or VOC_LEAD role required")
    
    try:
        from services.bulletin_service import RegionService
        
        region = RegionService.update_region(
            region_id=region_id,
            description=description,
            recipients=recipients
        )
        
        return region
    
    except Exception as e:
        logger.error(f"Error updating region: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ANALYTICS & KPI API ENDPOINTS
# ============================================================================

@app.get("/api/analytics/analyst-performance")
async def get_analyst_performance(
    analyst_username: Optional[str] = Query(None),
    days: int = Query(default=30, le=365),
    current_user: dict = Depends(get_current_user)
):
    """
    Get analyst performance metrics
    
    - CVE throughput (accepted/rejected/pending)
    - Processing times
    - Action history
    - Workload distribution
    
    **Parameters:**
    - **analyst_username**: Optional - filter by specific analyst
    - **days**: Time period for analysis (default: 30 days)
    """
    try:
        from services.analytics_service import AnalyticsService
        
        performance = AnalyticsService.get_analyst_performance(
            analyst_username=analyst_username,
            days=days
        )
        
        return performance
    
    except Exception as e:
        logger.error(f"Error getting analyst performance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/operational-dashboard")
async def get_operational_dashboard(current_user: dict = Depends(get_current_user)):
    """
    Get operational dashboard metrics
    
    - CVE volumes by source (NVD, CVEdetails, CVE.org)
    - CVE volumes by severity (CRITICAL, HIGH, MEDIUM, LOW)
    - Processing status distribution
    - Bulletin statistics
    - 7-day ingestion trends
    """
    try:
        from services.analytics_service import AnalyticsService
        
        dashboard = AnalyticsService.get_operational_dashboard()
        
        return dashboard
    
    except Exception as e:
        logger.error(f"Error getting operational dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/bulletin-timelines")
async def get_bulletin_timelines(current_user: dict = Depends(get_current_user)):
    """
    Get bulletin timeline metrics
    
    - Average time from creation to sending
    - Bulletin status distribution
    - Reminders and escalation statistics
    - Bulletins awaiting action
    """
    try:
        from services.analytics_service import AnalyticsService
        
        timelines = AnalyticsService.get_bulletin_timelines()
        
        return timelines
    
    except Exception as e:
        logger.error(f"Error getting bulletin timelines: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/reviewer-workload")
async def get_reviewer_workload(current_user: dict = Depends(get_current_user)):
    """
    Get reviewer workload monitoring
    
    - Total pending CVEs
    - Pending CVEs by severity
    - Workload distribution by analyst
    - Average processing times per analyst
    """
    try:
        from services.analytics_service import AnalyticsService
        
        workload = AnalyticsService.get_reviewer_workload()
        
        return workload
    
    except Exception as e:
        logger.error(f"Error getting reviewer workload: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/real-time-dashboard")
async def get_real_time_dashboard(current_user: dict = Depends(get_current_user)):
    """
    Get real-time dashboard with live metrics
    
    - Current pending CVEs
    - Today's CVE ingestion count
    - Active bulletins (DRAFT + SENT)
    - Recent actions (last 24 hours)
    - Hourly CVE processing velocity
    
    **Use this endpoint for live monitoring dashboards**
    """
    try:
        from services.analytics_service import AnalyticsService
        
        dashboard = AnalyticsService.get_real_time_dashboard()
        
        return dashboard
    
    except Exception as e:
        logger.error(f"Error getting real-time dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== MAIN ENTRY POINT ==========
if __name__ == "__main__":
    # Initialize database
    init_database()
    
    # Initialize delivery engine if available
    try:
        from services.email_service import EmailService
        from app.services.enhanced_delivery_engine import EnhancedBulletinDeliveryEngine
        from app.services.region_mailing_service import RegionMailingService
        from app.services.audit_logger import AuditLogger
        
        email_service = EmailService()
        mailing_service = RegionMailingService()
        audit_logger = AuditLogger()
        
        delivery_engine = EnhancedBulletinDeliveryEngine(
            email_service=email_service,
            mailing_service=mailing_service,
            audit_logger=audit_logger
        )
        
        # Start background delivery processor
        delivery_engine.start_background_processor(interval_seconds=60)
        
        # Set delivery engine reference in bulletin routes
        from app.api import bulletin_routes
        bulletin_routes.set_delivery_engine(delivery_engine)
        
        # Initialize region mailing lists - ALWAYS ensure they exist
        try:
            conn = sqlite3.connect('ctba_platform.db')
            cursor = conn.cursor()
            
            logger.info("📧 Checking and initializing region mailing lists...")
            cursor.execute('SELECT id, name, recipients FROM regions')
            regions = cursor.fetchall()
            
            for region_id, region_name, recipients_str in regions:
                # Check if mailing list exists for this region
                cursor.execute('SELECT id, to_recipients FROM region_mailing_lists WHERE region_id = ?', (region_id,))
                existing = cursor.fetchone()
                
                to_recipients = [e.strip() for e in recipients_str.split(',') if e.strip()]
                
                if not existing and to_recipients:
                    # Create new mailing list
                    logger.info(f"📧 Creating mailing list for {region_name}: {to_recipients}")
                    cursor.execute('''
                        INSERT INTO region_mailing_lists (region_id, to_recipients, cc_recipients, bcc_recipients, active)
                        VALUES (?, ?, '', '', 1)
                    ''', (region_id, ','.join(to_recipients)))
                    conn.commit()
                    logger.info(f"✅ Mailing list created for {region_name}")
                elif existing:
                    existing_recipients = existing[1] if existing[1] else ''
                    if not existing_recipients.strip() and to_recipients:
                        # Update empty mailing list with default recipients
                        logger.info(f"📧 Updating empty mailing list for {region_name}: {to_recipients}")
                        cursor.execute('''
                            UPDATE region_mailing_lists 
                            SET to_recipients = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE region_id = ?
                        ''', (','.join(to_recipients), region_id))
                        conn.commit()
                        logger.info(f"✅ Mailing list updated for {region_name}")
                    else:
                        logger.info(f"✓ Mailing list already configured for {region_name}")
                else:
                    logger.warning(f"⚠️ No recipients defined for {region_name}")
            
            conn.close()
            logger.info("✅ Region mailing lists initialization complete")
        except Exception as e:
            logger.error(f"❌ Could not initialize region mailing lists: {e}")
            import traceback
            traceback.print_exc()
        
        logger.info("✅ Enhanced bulletin delivery engine started")
    except Exception as e:
        logger.warning(f"⚠️ Delivery engine not available: {e}")
    
    # Start bulletin reminder service
    try:
        from services.bulletin_reminder_service import reminder_service
        
        # Check reminders every hour (3600 seconds)
        reminder_service.start(interval_seconds=3600)
        
        logger.info("✅ Bulletin reminder service started (checks every hour)")
    except Exception as e:
        logger.warning(f"⚠️ Reminder service not available: {e}")
    
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )