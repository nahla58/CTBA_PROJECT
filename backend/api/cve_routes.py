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
        
        return {
            "success": True,
            "message": f"✅ Import multi-sources terminé (CVE.org + NVD + CVEdetails + MSRC)",
            "imported": imported,
            "updated": updated,
            "skipped": skipped,
            "total_processed": len(cves),
            "by_source": by_source,
            "cvedetails_imported": cvedetails_imported,
            "msrc_imported": msrc_imported,
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
