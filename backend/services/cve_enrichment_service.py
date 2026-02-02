"""
Service d'enrichissement des CVEs avec CVE.org API
Enrichit les produits affectés, dates de publication et dates de mise à jour
"""
import requests
import logging
import time
import sqlite3
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import sys
import os

# Ajouter le chemin du backend au sys.path
backend_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

logger = logging.getLogger(__name__)


class CVEEnrichmentService:
    """Service pour enrichir les CVEs avec les données officielles de CVE.org"""
    
    CVE_ORG_API_BASE = "https://cveawg.mitre.org/api/cve"
    RATE_LIMIT_DELAY = 0.6  # 600ms entre chaque requête pour respecter le rate limit
    REQUEST_TIMEOUT = 10
    BATCH_SIZE = 50  # Traiter par lots pour éviter les timeouts
    
    @staticmethod
    def get_db_connection():
        """Obtenir une connexion à la base de données"""
        backend_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(backend_path, "ctba_platform.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def fetch_cve_from_cveorg(cve_id: str) -> Optional[Dict]:
        """
        Récupérer les données d'un CVE depuis CVE.org API
        
        Args:
            cve_id: L'identifiant du CVE (ex: CVE-2024-1234)
            
        Returns:
            Dictionnaire avec les données du CVE ou None si erreur
        """
        url = f"{CVEEnrichmentService.CVE_ORG_API_BASE}/{cve_id}"
        
        try:
            response = requests.get(url, timeout=CVEEnrichmentService.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.debug(f"CVE {cve_id} non trouvé sur CVE.org (404)")
                return None
            elif response.status_code == 429:
                logger.warning(f"Rate limit atteint pour CVE.org, attente 2s...")
                time.sleep(2)
                return None
            else:
                logger.warning(f"Erreur {response.status_code} pour {cve_id}")
                return None
                
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout pour {cve_id}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Erreur réseau pour {cve_id}: {str(e)[:50]}")
            return None
        except Exception as e:
            logger.error(f"Erreur inattendue pour {cve_id}: {str(e)[:100]}")
            return None
    
    @staticmethod
    def extract_affected_products(cveorg_data: Dict) -> List[Tuple[str, str]]:
        """
        Extraire les produits affectés depuis les données CVE.org
        
        Args:
            cveorg_data: Données JSON de CVE.org
            
        Returns:
            Liste de tuples (vendor, product)
        """
        products = []
        
        try:
            containers = cveorg_data.get('containers', {})
            cna = containers.get('cna', {})
            affected_list = cna.get('affected', [])
            
            for affected in affected_list:
                vendor = affected.get('vendor', '').strip()
                product = affected.get('product', '').strip()
                
                # Validation
                if not vendor or not product:
                    continue
                
                # Filtrer les entrées trop longues (probablement du bruit)
                if len(vendor) > 100 or len(product) > 100:
                    continue
                
                # Normaliser la casse
                vendor = vendor.title() if vendor != vendor.upper() else vendor
                product = product.title() if product != product.upper() else product
                
                products.append((vendor, product))
            
            return products
            
        except Exception as e:
            logger.error(f"Erreur extraction produits: {str(e)}")
            return []
    
    @staticmethod
    def extract_dates(cveorg_data: Dict) -> Tuple[Optional[str], Optional[str]]:
        """
        Extraire les dates de publication et mise à jour depuis CVE.org
        
        Args:
            cveorg_data: Données JSON de CVE.org
            
        Returns:
            Tuple (date_published, date_updated) en format ISO 8601
        """
        try:
            cve_metadata = cveorg_data.get('cveMetadata', {})
            date_published = cve_metadata.get('datePublished', '')
            date_updated = cve_metadata.get('dateUpdated', '')
            
            # Normaliser les dates en format ISO 8601 avec 'Z'
            if date_published and not date_published.endswith('Z'):
                date_published = date_published.rstrip('+00:00') + 'Z'
            
            if date_updated and not date_updated.endswith('Z'):
                date_updated = date_updated.rstrip('+00:00') + 'Z'
            elif not date_updated and date_published:
                # Si pas de date de mise à jour, utiliser la date de publication
                date_updated = date_published
            
            return (date_published or None, date_updated or None)
            
        except Exception as e:
            logger.error(f"Erreur extraction dates: {str(e)}")
            return (None, None)
    
    @staticmethod
    def enrich_single_cve(cve_id: str, conn: sqlite3.Connection) -> Dict[str, int]:
        """
        Enrichir un seul CVE avec les données de CVE.org
        
        Args:
            cve_id: L'identifiant du CVE
            conn: Connexion à la base de données
            
        Returns:
            Dictionnaire avec les statistiques d'enrichissement
        """
        stats = {
            'products_added': 0,
            'products_skipped': 0,
            'dates_updated': 0,
            'errors': 0
        }
        
        try:
            cursor = conn.cursor()
            
            # Récupérer les données depuis CVE.org
            cveorg_data = CVEEnrichmentService.fetch_cve_from_cveorg(cve_id)
            
            if not cveorg_data:
                stats['errors'] = 1
                return stats
            
            # Extraire les produits affectés
            products = CVEEnrichmentService.extract_affected_products(cveorg_data)
            
            if products:
                # Supprimer les produits existants pour ce CVE (remplacement par données officielles)
                cursor.execute('DELETE FROM affected_products WHERE cve_id = ?', (cve_id,))
                
                # Insérer les nouveaux produits
                for vendor, product in products:
                    try:
                        # Vérifier si existe déjà
                        cursor.execute('''
                            SELECT 1 FROM affected_products 
                            WHERE cve_id = ? AND vendor = ? AND product = ?
                        ''', (cve_id, vendor, product))
                        
                        if cursor.fetchone():
                            stats['products_skipped'] += 1
                            continue
                        
                        # Insérer avec confiance maximale (source officielle)
                        cursor.execute('''
                            INSERT INTO affected_products (cve_id, vendor, product, confidence)
                            VALUES (?, ?, ?, 1.0)
                        ''', (cve_id, vendor, product))
                        
                        stats['products_added'] += 1
                        
                    except sqlite3.IntegrityError:
                        stats['products_skipped'] += 1
                        continue
            
            # Extraire et mettre à jour les dates
            date_published, date_updated = CVEEnrichmentService.extract_dates(cveorg_data)
            
            if date_published or date_updated:
                update_parts = []
                params = []
                
                if date_published:
                    update_parts.append('published_date = ?')
                    params.append(date_published)
                
                if date_updated:
                    update_parts.append('last_updated = ?')
                    params.append(date_updated)
                
                if update_parts:
                    # Mettre à jour aussi la source pour indiquer l'enrichissement CVE.org
                    cursor.execute('SELECT source FROM cves WHERE cve_id = ?', (cve_id,))
                    row = cursor.fetchone()
                    if row:
                        current_source = row['source'] or 'NVD'
                        if 'cveorg' not in current_source.lower():
                            new_source = f"{current_source},cveorg"
                            update_parts.append('source = ?')
                            params.append(new_source)
                    
                    query = f"UPDATE cves SET {', '.join(update_parts)} WHERE cve_id = ?"
                    params.append(cve_id)
                    
                    cursor.execute(query, params)
                    stats['dates_updated'] = 1
            
            conn.commit()
            
            # Respecter le rate limit
            time.sleep(CVEEnrichmentService.RATE_LIMIT_DELAY)
            
        except Exception as e:
            logger.error(f"Erreur enrichissement {cve_id}: {str(e)}")
            stats['errors'] = 1
            conn.rollback()
        
        return stats
    
    @staticmethod
    def enrich_all_pending_cves(limit: Optional[int] = None) -> Dict:
        """
        Enrichir tous les CVEs en attente avec les données de CVE.org
        
        Args:
            limit: Nombre maximum de CVEs à enrichir (None = tous)
            
        Returns:
            Dictionnaire avec les statistiques globales
        """
        logger.info("🚀 Démarrage de l'enrichissement CVE.org...")
        start_time = time.time()
        
        global_stats = {
            'total_processed': 0,
            'total_products_added': 0,
            'total_products_skipped': 0,
            'total_dates_updated': 0,
            'total_errors': 0,
            'duration': 0
        }
        
        try:
            conn = CVEEnrichmentService.get_db_connection()
            cursor = conn.cursor()
            
            # Récupérer les CVEs à enrichir (priorité: PENDING et récents)
            query = '''
                SELECT DISTINCT cve_id 
                FROM cves 
                WHERE status = 'PENDING'
                ORDER BY imported_at DESC
            '''
            
            if limit:
                query += f' LIMIT {limit}'
            
            cursor.execute(query)
            cves_to_enrich = [row['cve_id'] for row in cursor.fetchall()]
            
            logger.info(f"📊 {len(cves_to_enrich)} CVEs à enrichir")
            
            if not cves_to_enrich:
                logger.info("✅ Aucun CVE à enrichir")
                conn.close()
                return global_stats
            
            # Traiter par lots
            for i in range(0, len(cves_to_enrich), CVEEnrichmentService.BATCH_SIZE):
                batch = cves_to_enrich[i:i + CVEEnrichmentService.BATCH_SIZE]
                logger.info(f"📦 Traitement du lot {i//CVEEnrichmentService.BATCH_SIZE + 1}/{(len(cves_to_enrich)-1)//CVEEnrichmentService.BATCH_SIZE + 1}")
                
                for cve_id in batch:
                    stats = CVEEnrichmentService.enrich_single_cve(cve_id, conn)
                    
                    global_stats['total_processed'] += 1
                    global_stats['total_products_added'] += stats['products_added']
                    global_stats['total_products_skipped'] += stats['products_skipped']
                    global_stats['total_dates_updated'] += stats['dates_updated']
                    global_stats['total_errors'] += stats['errors']
                    
                    if stats['products_added'] > 0 or stats['dates_updated'] > 0:
                        logger.info(f"✅ {cve_id}: +{stats['products_added']} produits, dates: {stats['dates_updated']}")
            
            conn.close()
            
            duration = time.time() - start_time
            global_stats['duration'] = round(duration, 2)
            
            logger.info(f"✅ Enrichissement terminé en {duration:.2f}s")
            logger.info(f"📊 Statistiques: {global_stats['total_processed']} CVEs traités, "
                       f"{global_stats['total_products_added']} produits ajoutés, "
                       f"{global_stats['total_dates_updated']} dates mises à jour, "
                       f"{global_stats['total_errors']} erreurs")
            
        except Exception as e:
            logger.error(f"⚠️ Erreur enrichissement global: {str(e)}")
            global_stats['total_errors'] += 1
        
        return global_stats
    
    @staticmethod
    def enrich_specific_cves(cve_ids: List[str]) -> Dict:
        """
        Enrichir une liste spécifique de CVEs
        
        Args:
            cve_ids: Liste des identifiants CVE à enrichir
            
        Returns:
            Dictionnaire avec les statistiques
        """
        logger.info(f"🚀 Enrichissement de {len(cve_ids)} CVEs spécifiques...")
        start_time = time.time()
        
        global_stats = {
            'total_processed': 0,
            'total_products_added': 0,
            'total_products_skipped': 0,
            'total_dates_updated': 0,
            'total_errors': 0,
            'duration': 0
        }
        
        try:
            conn = CVEEnrichmentService.get_db_connection()
            
            for cve_id in cve_ids:
                stats = CVEEnrichmentService.enrich_single_cve(cve_id, conn)
                
                global_stats['total_processed'] += 1
                global_stats['total_products_added'] += stats['products_added']
                global_stats['total_products_skipped'] += stats['products_skipped']
                global_stats['total_dates_updated'] += stats['dates_updated']
                global_stats['total_errors'] += stats['errors']
                
                logger.info(f"✅ {cve_id}: +{stats['products_added']} produits, dates: {stats['dates_updated']}")
            
            conn.close()
            
            duration = time.time() - start_time
            global_stats['duration'] = round(duration, 2)
            
            logger.info(f"✅ Enrichissement terminé en {duration:.2f}s")
            
        except Exception as e:
            logger.error(f"⚠️ Erreur enrichissement: {str(e)}")
            global_stats['total_errors'] += 1
        
        return global_stats
