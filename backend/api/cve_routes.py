"""
Routes API pour la récupération des CVEs depuis NVD et CVE.org
Compatible avec FastAPI
"""
from fastapi import APIRouter, Query, HTTPException
from typing import Optional
import sys
import os

# Ajouter le chemin du backend au sys.path
backend_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from services.cve_fetcher_service import CVEFetcherService
from services.cve_enrichment_service import CVEEnrichmentService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cves", tags=["CVE Fetcher"])

@router.post("/import-from-all-sources")
async def import_cves_from_all_sources(
    days: int = Query(default=7, ge=1, le=30, description="Nombre de jours précédents"),
    limit: int = Query(default=200, ge=1, le=500, description="Nombre max de CVEs par source")
):
    """
    Importe les CVEs récents depuis TOUTES les sources (NVD, CVE.org, CVEdetails, MSRC)
    directement dans la base de données avec les scores CVSS corrects
    
    Returns:
        JSON avec le résultat de l'importation par source
    """
    try:
        import sqlite3
        import sys
        import os
        from datetime import datetime
        import pytz
        
        logger.info(f"📥 Import des CVEs depuis TOUTES LES SOURCES (days={days}, limit={limit})")
        
        # Récupérer les CVEs depuis TOUTES les sources
        all_sources_data = CVEFetcherService.fetch_all_sources(days=days, limit=limit)
        # Récupérer les CVEs depuis TOUTES les sources
        all_sources_data = CVEFetcherService.fetch_all_sources(days=days, limit=limit)
        
        cves = all_sources_data.get("all", [])
        
        if not cves:
            return {
                "success": False,
                "message": "Aucun CVE récupéré depuis les sources",
                "imported": 0,
                "sources": all_sources_data
            }
        
        logger.info(f"📊 Total CVEs récupérés depuis toutes les sources: {len(cves)}")
        
        # Connexion à la base de données
        backend_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(backend_path, "ctba_platform.db")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        imported = 0
        updated = 0
        skipped = 0
        by_source = {}
        
        for cve in cves:
            cve_id = cve['cve_id']
            source = cve.get('source', 'Unknown')
            
            # Compter par source
            if source not in by_source:
                by_source[source] = 0
            
            try:
                # ✅ FILTRER AVANT TOUT: Ignorer les CVEs sans score CVSS valide
                severity = cve.get('severity', 'UNKNOWN')
                if severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    # Skip CVEs sans score CVSS valide (pas encore analysés par NVD)
                    skipped += 1
                    continue
                
                # Vérifier si le CVE existe déjà
                cursor.execute("SELECT id, cvss_score, source FROM cves WHERE cve_id = ?", (cve_id,))
                existing = cursor.fetchone()
                
                if existing:
                    # Mettre à jour seulement si le nouveau score est meilleur ou source manquante
                    existing_score = existing[1] if existing[1] else 0
                    existing_source = existing[2] if existing[2] else ''
                    new_score = cve.get('cvss_score', 0)
                    
                    # Fusionner les sources
                    sources_list = existing_source.split(',') if existing_source else []
                    for s in source.split(','):
                        if s and s not in sources_list:
                            sources_list.append(s)
                    merged_source = ','.join(sources_list)
                    
                    if new_score > existing_score or merged_source != existing_source:
                        cursor.execute("""
                            UPDATE cves
                            SET cvss_score = ?, cvss_version = ?, severity = ?, 
                                description = ?, last_updated = ?, source = ?
                            WHERE cve_id = ?
                        """, (
                            max(new_score, existing_score),
                            cve.get('cvss_version', 'N/A'),
                            severity,
                            cve.get('description', '')[:2000],
                            datetime.now(pytz.UTC).isoformat(),
                            merged_source,
                            cve_id
                        ))
                        updated += 1
                        by_source[source] += 1
                        logger.info(f"🔄 Mis à jour: {cve_id} - Score: {max(new_score, existing_score)} - Source: {merged_source}")
                    else:
                        skipped += 1
                else:
                    # Insérer nouveau CVE
                    imported_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
                    
                    cursor.execute('''
                        INSERT INTO cves 
                        (cve_id, description, severity, cvss_score, cvss_version, 
                         published_date, imported_at, last_updated, source, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        cve.get('description', '')[:2000],
                        severity,
                        cve.get('cvss_score', 0),
                        cve.get('cvss_version', 'N/A'),
                        cve.get('published_date', ''),
                        imported_at,
                        cve.get('last_updated', imported_at),
                        source,
                        'PENDING'
                    ))
                    
                    # Insérer les produits affectés
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
                    by_source[source] += 1
                    logger.info(f"✅ Importé: {cve_id} - Score: {cve.get('cvss_score', 0)} - Source: {source}")
                
                conn.commit()
                
            except Exception as e:
                logger.error(f"❌ Erreur pour {cve_id}: {str(e)}")
                continue
        
        conn.close()
        
        # 2. Importer depuis CVEdetails (si API token configuré)
        cvedetails_imported = 0
        try:
            sys.path.insert(0, backend_path)
            from main import import_from_cvedetails as cvedetails_importer
            result = cvedetails_importer()
            cvedetails_imported = result.get('imported', 0)
            logger.info(f"✅ CVEdetails: {cvedetails_imported} CVEs importés")
        except Exception as e:
            logger.warning(f"⚠️ CVEdetails non disponible: {str(e)}")
        
        # 3. Importer depuis MSRC
        msrc_imported = 0
        try:
            from main import import_from_msrc as msrc_importer
            result = msrc_importer()
            msrc_imported = result.get('imported', 0)
            logger.info(f"✅ MSRC: {msrc_imported} CVEs importés")
        except Exception as e:
            logger.warning(f"⚠️ MSRC non disponible: {str(e)}")
        
        # 4. Enrichir automatiquement les CVEs avec CVE.org
        enrichment_stats = {
            'total_processed': 0,
            'total_products_added': 0,
            'total_dates_updated': 0,
            'total_errors': 0
        }
        try:
            logger.info("🔄 Enrichissement automatique avec CVE.org...")
            enrichment_stats = CVEEnrichmentService.enrich_all_pending_cves(limit=min(imported + updated, 100))
            logger.info(f"✅ Enrichissement CVE.org: {enrichment_stats['total_products_added']} produits ajoutés, "
                       f"{enrichment_stats['total_dates_updated']} dates mises à jour")
        except Exception as e:
            logger.warning(f"⚠️ Enrichissement CVE.org échoué: {str(e)}")
        
        return {
            "success": True,
            "message": f"✅ Import multi-sources terminé (CVE.org + NVD + CVEdetails + MSRC) avec enrichissement",
            "imported": imported,
            "updated": updated,
            "skipped": skipped,
            "total_processed": len(cves),
            "by_source": by_source,
            "cvedetails_imported": cvedetails_imported,
            "msrc_imported": msrc_imported,
            "enrichment": {
                "products_added": enrichment_stats.get('total_products_added', 0),
                "dates_updated": enrichment_stats.get('total_dates_updated', 0),
                "cves_enriched": enrichment_stats.get('total_processed', 0),
                "errors": enrichment_stats.get('total_errors', 0)
            },
            "sources_stats": {
                "nvd": len(all_sources_data.get("nvd", [])),
                "cveorg": len(all_sources_data.get("cveorg", [])),
                "cvedetails": len(all_sources_data.get("cvedetails", [])),
                "msrc": len(all_sources_data.get("msrc", []))
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur import_cves_from_all_sources: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/fetch-latest")
async def fetch_latest_cves(
    days: int = Query(default=7, ge=1, le=120, description="Nombre de jours précédents"),
    limit: int = Query(default=100, ge=1, le=200, description="Nombre max de CVEs")
):
    """
    Récupère les CVEs les plus récents depuis NVD
    
    Returns:
        JSON avec la liste des CVEs et leurs scores CVSS corrects
    """
    try:
        logger.info(f"📥 Récupération des CVEs des {days} derniers jours (limit: {limit})")
        
        # Récupérer depuis NVD
        cves = CVEFetcherService.fetch_recent_cves_from_nvd(days=days, limit=limit)
        
        # Trier par score CVSS décroissant
        cves_sorted = sorted(cves, key=lambda x: x.get("cvss_score", 0), reverse=True)
        
        # Statistiques
        stats = {
            "total": len(cves_sorted),
            "critical": len([c for c in cves_sorted if c.get("severity") == "CRITICAL"]),
            "high": len([c for c in cves_sorted if c.get("severity") == "HIGH"]),
            "medium": len([c for c in cves_sorted if c.get("severity") == "MEDIUM"]),
            "low": len([c for c in cves_sorted if c.get("severity") == "LOW"]),
            "unknown": len([c for c in cves_sorted if c.get("severity") == "UNKNOWN"]),
            "avg_score": round(sum(c.get("cvss_score", 0) for c in cves_sorted) / len(cves_sorted), 1) if cves_sorted else 0
        }
        
        return {
            "success": True,
            "count": len(cves_sorted),
            "cves": cves_sorted,
            "stats": stats,
            "message": f"✅ {len(cves_sorted)} CVEs récupérés depuis NVD"
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur fetch_latest_cves: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/search")
async def search_cves(
    keyword: str = Query(..., min_length=2, description="Mot-clé de recherche"),
    limit: int = Query(default=20, ge=1, le=100, description="Nombre max de résultats")
):
    """
    Recherche les CVEs par mot-clé dans NVD
    
    Returns:
        JSON avec les CVEs correspondants
    """
    try:
        logger.info(f"🔍 Recherche CVEs pour: '{keyword}'")
        
        cves = CVEFetcherService.search_cves_by_keyword(keyword, limit=limit)
        
        # Trier par score décroissant
        cves_sorted = sorted(cves, key=lambda x: x.get("cvss_score", 0), reverse=True)
        
        return {
            "success": True,
            "count": len(cves_sorted),
            "cves": cves_sorted,
            "keyword": keyword,
            "message": f"✅ {len(cves_sorted)} CVEs trouvés pour '{keyword}'"
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur search_cves: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/details/{cve_id}")
async def get_cve_details(cve_id: str):
    """
    Récupère les détails d'un CVE spécifique depuis CVE.org
    
    Args:
        cve_id: ID du CVE (ex: CVE-2026-0001)
    
    Returns:
        JSON avec les détails du CVE
    """
    try:
        # Validation du format CVE-YYYY-NNNNN
        import re
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            raise HTTPException(
                status_code=400,
                detail=f"Format CVE invalide: {cve_id}. Format attendu: CVE-YYYY-NNNNN"
            )
        
        logger.info(f"🔍 Récupération détails pour: {cve_id}")
        
        cve = CVEFetcherService.fetch_cve_from_cveorg(cve_id)
        
        if not cve:
            raise HTTPException(
                status_code=404,
                detail=f"CVE {cve_id} non trouvé dans CVE.org"
            )
        
        return {
            "success": True,
            "cve": cve,
            "message": f"✅ Détails récupérés pour {cve_id}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur get_cve_details: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    """Vérification de l'état du service"""
    return {
        "success": True,
        "service": "CVE Fetcher API",
        "status": "healthy",
        "endpoints": [
            "POST /api/cves/import-from-all-sources",
            "POST /api/cves/import-from-cvedetails",
            "POST /api/cves/import-from-msrc",
            "POST /api/cves/enrich-from-cveorg",
            "GET /api/cves/fetch-latest",
            "GET /api/cves/search",
            "GET /api/cves/details/{cve_id}"
        ]
    }

@router.post("/import-from-cvedetails")
async def import_from_cvedetails():
    """
    Importe les CVEs depuis CVEdetails (nécessite CVEDETAILS_API_TOKEN)
    """
    try:
        # Importer la fonction depuis main.py
        sys.path.insert(0, backend_path)
        from main import import_from_cvedetails as cvedetails_importer
        
        result = cvedetails_importer()
        return {
            "success": True,
            "message": "Import CVEdetails terminé",
            "imported": result.get("imported", 0),
            "source": "cvedetails"
        }
    except Exception as e:
        logger.error(f"❌ Erreur import CVEdetails: {str(e)}")
        return {
            "success": False,
            "message": str(e),
            "imported": 0
        }

@router.post("/import-from-msrc")
async def import_from_msrc():
    """
    Importe les CVEs depuis MSRC (Microsoft Security Response Center)
    """
    try:
        # Importer la fonction depuis main.py
        sys.path.insert(0, backend_path)
        from main import import_from_msrc as msrc_importer
        
        result = msrc_importer()
        return {
            "success": True,
            "message": "Import MSRC terminé",
            "imported": result.get("imported", 0),
            "source": "msrc"
        }
    except Exception as e:
        logger.error(f"❌ Erreur import MSRC: {str(e)}")
        return {
            "success": False,
            "message": str(e),
            "imported": 0
        }

@router.post("/fetch-single-cve")
async def fetch_single_cve(
    cve_id: str = Query(..., description="CVE ID à importer (ex: CVE-2026-24936)")
):
    """
    🎯 Importer un CVE spécifique depuis CVE.org
    
    Utile pour récupérer immédiatement un CVE précis sans attendre le scan automatique
    
    Returns:
        JSON avec le résultat de l'import
    """
    try:
        import sqlite3
        from datetime import datetime
        import pytz
        
        # Valider le format CVE ID
        import re
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            raise HTTPException(status_code=400, detail="Format CVE ID invalide. Utilisez CVE-YYYY-XXXXX")
        
        logger.info(f"🎯 Import direct de {cve_id}...")
        
        # Récupérer depuis CVE.org
        cve_data = CVEFetcherService.fetch_cve_from_cveorg(cve_id)
        
        if not cve_data:
            return {
                "success": False,
                "message": f"CVE {cve_id} non trouvé sur CVE.org",
                "cve_id": cve_id
            }
        
        # Import en base de données
        backend_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_file = os.path.join(backend_path, "ctba_platform.db")
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Vérifier si existe déjà
        cursor.execute("SELECT id, status FROM cves WHERE cve_id = ?", (cve_id,))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return {
                "success": True,
                "message": f"CVE {cve_id} existe déjà dans la base",
                "cve_id": cve_id,
                "status": existing[1] if len(existing) > 1 else "UNKNOWN",
                "action": "already_exists"
            }
        
        # Import nouveau CVE
        imported_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
        
        cursor.execute('''
            INSERT INTO cves 
            (cve_id, description, severity, cvss_score, cvss_version, 
             published_date, imported_at, last_updated, source_primary, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cve_id,
            cve_data.get('description', '')[:2000],
            cve_data.get('severity', 'UNKNOWN'),
            cve_data.get('cvss_score', 0),
            cve_data.get('cvss_version', 'N/A'),
            cve_data.get('published_date', ''),
            imported_at,
            cve_data.get('last_updated', imported_at),
            'CVE.org',
            'PENDING'
        ))
        
        # Produits affectés
        products_added = 0
        for product in cve_data.get('affected_products', [])[:10]:
            vendor = product.get('vendor', 'Unknown')[:50]
            product_name = product.get('product', 'Multiple Products')[:50]
            
            if vendor and product_name:
                cursor.execute('''
                    INSERT OR IGNORE INTO affected_products 
                    (cve_id, vendor, product)
                    VALUES (?, ?, ?)
                ''', (cve_id, vendor, product_name))
                products_added += 1
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ {cve_id} importé avec succès ({products_added} produits)")
        
        return {
            "success": True,
            "message": f"CVE {cve_id} importé avec succès",
            "cve_id": cve_id,
            "severity": cve_data.get('severity', 'UNKNOWN'),
            "cvss_score": cve_data.get('cvss_score', 0),
            "products_added": products_added,
            "action": "imported"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur import {cve_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan-cveorg-direct")
async def scan_cveorg_direct(
    days: int = Query(default=3, ge=1, le=7, description="Scan des N derniers jours"),
    limit: int = Query(default=50, ge=1, le=100, description="Nombre max de CVEs à scanner")
):
    """
    🆕 Scanner direct CVE.org pour trouver les CVEs très récents
    Utile pour les CVEs publiés sur CVE.org avant NVD
    
    Cette méthode scanne les derniers CVE IDs de l'année en cours
    pour trouver les CVEs publiés dans les N derniers jours.
    
    Returns:
        JSON avec les CVEs trouvés et importés
    """
    try:
        import sqlite3
        from datetime import datetime
        import pytz
        
        logger.info(f"🔍 Scan direct CVE.org (days={days}, limit={limit})")
        
        # Scanner CVE.org directement
        cves = CVEFetcherService.fetch_recent_cves_from_cveorg(days=days, limit=limit)
        
        if not cves:
            return {
                "success": True,
                "message": "Aucun nouveau CVE trouvé sur CVE.org",
                "scanned": 0,
                "imported": 0,
                "cves": []
            }
        
        # Import dans la base de données
        backend_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_file = os.path.join(backend_path, "ctba_platform.db")
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        imported = 0
        updated = 0
        skipped = 0
        imported_cve_ids = []
        
        for cve in cves:
            cve_id = cve['cve_id']
            
            try:
                # Vérifier si existe déjà
                cursor.execute("SELECT id, cvss_score FROM cves WHERE cve_id = ?", (cve_id,))
                existing = cursor.fetchone()
                
                if existing:
                    skipped += 1
                    continue
                
                # Import nouveau CVE
                imported_at = datetime.now(pytz.UTC).isoformat().replace('+00:00', 'Z')
                
                cursor.execute('''
                    INSERT INTO cves 
                    (cve_id, description, severity, cvss_score, cvss_version, 
                     published_date, imported_at, last_updated, source_primary, status)
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
                    'CVE.org',
                    'NEW'
                ))
                
                # Produits affectés
                for product in cve.get('affected_products', [])[:10]:
                    vendor = product.get('vendor', 'Unknown')[:50]
                    product_name = product.get('product', 'Multiple Products')[:50]
                    
                    if vendor and product_name:
                        cursor.execute('''
                            INSERT OR IGNORE INTO affected_products 
                            (cve_id, vendor, product)
                            VALUES (?, ?, ?)
                        ''', (cve_id, vendor, product_name))
                
                imported += 1
                imported_cve_ids.append(cve_id)
                conn.commit()
                logger.info(f"✅ Imported {cve_id} from CVE.org")
                
            except Exception as e:
                logger.error(f"❌ Erreur import {cve_id}: {str(e)}")
                continue
        
        conn.close()
        
        return {
            "success": True,
            "message": f"Scan CVE.org terminé: {imported} nouveaux CVEs importés",
            "scanned": len(cves),
            "imported": imported,
            "updated": updated,
            "skipped": skipped,
            "cves": imported_cve_ids,
            "source": "CVE.org (direct scan)"
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur scan CVE.org: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/enrich-from-cveorg")
async def enrich_cves_from_cveorg(
    limit: int = Query(default=100, ge=1, le=500, description="Nombre max de CVEs à enrichir"),
    cve_ids: Optional[str] = Query(default=None, description="CVE IDs séparés par virgule (ex: CVE-2024-1234,CVE-2024-5678)")
):
    """
    Enrichit les CVEs avec les données officielles de CVE.org (MITRE)
    
    Enrichit:
    - Produits affectés (vendor, product)
    - Date de publication
    - Date de mise à jour
    
    Params:
        - limit: Nombre maximum de CVEs à enrichir (par défaut 100)
        - cve_ids: Liste optionnelle de CVE IDs spécifiques à enrichir
    
    Returns:
        JSON avec les statistiques d'enrichissement
    """
    try:
        logger.info(f"🚀 Enrichissement CVE.org demandé (limit={limit}, specific_ids={cve_ids is not None})")
        
        if cve_ids:
            # Enrichir uniquement les CVEs spécifiés
            cve_list = [cve_id.strip() for cve_id in cve_ids.split(',')]
            logger.info(f"📋 Enrichissement de {len(cve_list)} CVEs spécifiques")
            stats = CVEEnrichmentService.enrich_specific_cves(cve_list)
        else:
            # Enrichir tous les CVEs en attente
            logger.info(f"📋 Enrichissement de tous les CVEs PENDING (limit={limit})")
            stats = CVEEnrichmentService.enrich_all_pending_cves(limit=limit)
        
        return {
            "success": True,
            "message": f"✅ Enrichissement CVE.org terminé en {stats['duration']}s",
            "statistics": {
                "total_processed": stats['total_processed'],
                "products_added": stats['total_products_added'],
                "products_skipped": stats['total_products_skipped'],
                "dates_updated": stats['total_dates_updated'],
                "errors": stats['total_errors'],
                "duration_seconds": stats['duration']
            }
        }
    except Exception as e:
        logger.error(f"❌ Erreur enrichissement CVE.org: {str(e)}")
        return {
            "success": False,
            "message": f"❌ Erreur: {str(e)}",
            "statistics": {
                "total_processed": 0,
                "products_added": 0,
                "products_skipped": 0,
                "dates_updated": 0,
                "errors": 1,
                "duration_seconds": 0
            }
        }

@router.post("/enrich-cvss-scores-from-nvd")
async def enrich_cvss_scores_from_nvd(
    limit: int = Query(default=50, ge=1, le=100, description="Nombre max de CVEs sans score à enrichir")
):
    """
    Enrichit les CVEs qui ont un score CVSS = 0 en vérifiant la NVD
    
    Cette fonction est utile pour les CVEs importés depuis CVE.org qui n'avaient pas encore
    de scores CVSS mais qui ont été analysés par la NVD depuis leur import initial.
    
    Params:
        - limit: Nombre maximum de CVEs à vérifier (par défaut 50, max 100)
    
    Returns:
        JSON avec les statistiques d'enrichissement CVSS
    """
    try:
        import sqlite3
        import time
        import requests
        from datetime import datetime
        import pytz
        
        logger.info(f"🔄 Enrichissement scores CVSS depuis NVD (limit={limit})")
        
        # Connexion à la base de données
        backend_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(backend_path, "ctba_platform.db")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Trouver les CVEs avec score 0 ou NULL
        cursor.execute("""
            SELECT cve_id FROM cves 
            WHERE (cvss_score IS NULL OR cvss_score = 0 OR cvss_score = 0.0)
            AND status = 'PENDING'
            ORDER BY imported_at DESC
            LIMIT ?
        """, (limit,))
        cves_without_score = [row[0] for row in cursor.fetchall()]
        
        if not cves_without_score:
            conn.close()
            return {
                "success": True,
                "message": "✅ Aucun CVE sans score CVSS trouvé",
                "statistics": {
                    "total_checked": 0,
                    "enriched": 0,
                    "not_in_nvd": 0,
                    "errors": 0
                }
            }
        
        logger.info(f"📊 {len(cves_without_score)} CVEs sans score CVSS trouvés")
        
        enriched_count = 0
        not_in_nvd = 0
        errors = 0
        enriched_details = []
        
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
                            enriched_details.append({
                                "cve_id": cve_id,
                                "cvss_score": cvss_score,
                                "severity": severity,
                                "cvss_version": cvss_version
                            })
                            logger.info(f"✅ {cve_id}: Score CVSS enrichi → {cvss_score} ({severity})")
                        else:
                            not_in_nvd += 1
                            logger.debug(f"⏳ {cve_id}: Pas encore de score CVSS dans NVD")
                    else:
                        not_in_nvd += 1
                elif response.status_code == 404:
                    not_in_nvd += 1
                    logger.debug(f"⏳ {cve_id}: Pas encore dans NVD")
                else:
                    errors += 1
                    logger.warning(f"⚠️ {cve_id}: Erreur HTTP {response.status_code}")
                
                # Rate limiting NVD (max 5 requêtes par 30 secondes sans API key)
                time.sleep(0.7)
                
            except Exception as cve_enrich_error:
                errors += 1
                logger.error(f"❌ {cve_id}: Erreur enrichissement: {str(cve_enrich_error)[:100]}")
                continue
        
        conn.close()
        
        return {
            "success": True,
            "message": f"✅ Enrichissement NVD terminé: {enriched_count}/{len(cves_without_score)} CVEs enrichis",
            "statistics": {
                "total_checked": len(cves_without_score),
                "enriched": enriched_count,
                "not_in_nvd": not_in_nvd,
                "errors": errors
            },
            "enriched_cves": enriched_details[:20]  # Limiter la réponse aux 20 premiers
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur enrichissement CVSS: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
