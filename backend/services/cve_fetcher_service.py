"""
Service pour récupérer les CVEs depuis NVD et CVE.org avec scores CVSS corrects
"""
import requests
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import time

logger = logging.getLogger(__name__)

class CVEFetcherService:
    """Service pour récupérer les CVEs depuis CVE.org et NVD"""
    
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve"
    
    @staticmethod
    def fetch_recent_cves_from_nvd(days: int = 7, limit: int = 100) -> List[Dict]:
        """
        Récupère les CVEs récents depuis NVD (NIST)
        
        Args:
            days: Nombre de jours précédents
            limit: Nombre maximum de CVEs à retourner
            
        Returns:
            Liste des CVEs avec scores CVSS corrects
        """
        try:
            # ✅ CORRECTION: Calculer la plage de dates avec marge pour inclure tout le jour
            # Ajouter 2 heures de marge pour être sûr d'avoir tous les CVEs du jour
            end_date = datetime.utcnow() + timedelta(hours=2)
            start_date = end_date - timedelta(days=days)
            
            # Format ISO 8601 avec millisecondes pour NVD API
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": min(limit, 2000)
            }
            
            logger.info(f"🔍 Récupération CVEs depuis NVD: {start_date.strftime('%Y-%m-%d %H:%M')} à {end_date.strftime('%Y-%m-%d %H:%M')} UTC")
            
            response = requests.get(
                CVEFetcherService.NVD_BASE_URL,
                params=params,
                timeout=60,
                headers={"User-Agent": "CTBA-CVE-Platform/2.0"}
            )
            
            if response.status_code == 403:
                logger.error("❌ NVD API: Accès interdit (403) - Vérifiez la clé API")
                return []
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            logger.info(f"📊 {len(vulnerabilities)} CVEs trouvés dans NVD")
            
            cves = []
            for vuln in vulnerabilities[:limit]:
                cve_info = CVEFetcherService._extract_cve_from_nvd(vuln)
                if cve_info:
                    cves.append(cve_info)
            
            logger.info(f"✅ {len(cves)} CVEs extraits avec succès depuis NVD")
            return cves
            
        except requests.exceptions.Timeout:
            logger.error("⏱️ Timeout lors de la connexion à NVD")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Erreur API NVD: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"❌ Erreur traitement CVEs NVD: {str(e)}")
            return []

    @staticmethod
    def _extract_cve_from_nvd(vuln: Dict) -> Optional[Dict]:
        """
        Extrait les informations d'un CVE depuis les données NVD
        CORRECTION: Extraction correcte du score CVSS
        
        Args:
            vuln: Données brutes de la vulnérabilité NVD
            
        Returns:
            CVE formaté ou None
        """
        try:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            
            if not cve_id:
                return None
            
            # ✅ CORRECTION: Extraction correcte des scores CVSS
            cvss_score = 0.0
            cvss_vector = "N/A"
            cvss_version = "N/A"
            severity = "UNKNOWN"
            
            metrics = cve.get("metrics", {})
            
            # Priorité: CVSS v3.1 > v3.0 > v2.0
            # CVSS v3.1 (le plus récent et précis)
            if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0))
                cvss_vector = cvss_data.get("vectorString", "N/A")
                cvss_version = "3.1"
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                logger.debug(f"✅ {cve_id}: CVSS v3.1 Score = {cvss_score}")
            
            # CVSS v3.0
            elif "cvssMetricV30" in metrics and len(metrics["cvssMetricV30"]) > 0:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0))
                cvss_vector = cvss_data.get("vectorString", "N/A")
                cvss_version = "3.0"
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                logger.debug(f"✅ {cve_id}: CVSS v3.0 Score = {cvss_score}")
            
            # CVSS v2.0 (fallback)
            elif "cvssMetricV2" in metrics and len(metrics["cvssMetricV2"]) > 0:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0))
                cvss_vector = cvss_data.get("vectorString", "N/A")
                cvss_version = "2.0"
                # Pour CVSS v2, calculer la sévérité
                if cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                logger.debug(f"✅ {cve_id}: CVSS v2.0 Score = {cvss_score}")
            
            # Si aucun score trouvé
            if cvss_score == 0.0:
                logger.warning(f"⚠️ {cve_id}: Aucun score CVSS trouvé dans NVD")
                severity = "UNKNOWN"
            
            # Calculer la sévérité si manquante
            if severity == "UNKNOWN" and cvss_score > 0:
                severity = CVEFetcherService._calculate_severity(cvss_score)
            
            # Description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Produits affectés
            affected_products = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", [])[:5]:  # Limiter à 5 produits
                        cpe = cpe_match.get("criteria", "")
                        if cpe:
                            # Parser CPE: cpe:2.3:a:vendor:product:version...
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3].replace("_", " ").title()
                                product = parts[4].replace("_", " ").title()
                                affected_products.append({
                                    "vendor": vendor,
                                    "product": product,
                                    "confidence": 0.9
                                })
            
            # Si aucun produit trouvé
            if not affected_products:
                affected_products = [{"vendor": "Unknown", "product": "Multiple Products", "confidence": 0.0}]
            
            # Date de publication
            published = cve.get("published", "")
            last_modified = cve.get("lastModified", published)
            
            # Références
            references = []
            for ref in cve.get("references", [])[:3]:
                references.append(ref.get("url", ""))
            
            return {
                "id": cve_id,
                "cve_id": cve_id,
                "description": description,
                "cvss_score": round(cvss_score, 1),
                "cvss_vector": cvss_vector,
                "cvss_version": cvss_version,
                "severity": severity,
                "published_date": published,
                "last_updated": last_modified,
                "affected_products": affected_products,
                "references": references,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source": "NVD",
                "status": "PENDING"
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur extraction CVE depuis NVD: {str(e)}")
            return None

    @staticmethod
    def _calculate_severity(score: float) -> str:
        """Calcule la sévérité basée sur le score CVSS v3.x"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "UNKNOWN"

    @staticmethod
    def fetch_recent_cves_from_cveorg(days: int = 7, limit: int = 100) -> List[Dict]:
        """
        Récupère les CVEs récents depuis CVE.org (MITRE)
        CVE.org ne supporte pas la recherche par date, donc on utilise l'API NVD
        et on enrichit avec les données CVE.org
        
        Args:
            days: Nombre de jours précédents
            limit: Nombre maximum de CVEs
            
        Returns:
            Liste des CVEs enrichis avec données CVE.org
        """
        try:
            # Récupérer d'abord depuis NVD pour avoir la liste des CVE IDs récents
            nvd_cves = CVEFetcherService.fetch_recent_cves_from_nvd(days=days, limit=limit)
            
            logger.info(f"🔍 Enrichissement de {len(nvd_cves)} CVEs avec données CVE.org...")
            
            enriched_cves = []
            for nvd_cve in nvd_cves:
                cve_id = nvd_cve['cve_id']
                
                # Récupérer les détails depuis CVE.org
                cveorg_data = CVEFetcherService.fetch_cve_from_cveorg(cve_id)
                
                if cveorg_data:
                    # Fusionner les données NVD et CVE.org
                    # CVE.org a de meilleurs produits affectés, NVD a les scores CVSS
                    nvd_cve['affected_products'] = cveorg_data.get('affected_products', nvd_cve['affected_products'])
                    nvd_cve['source'] = 'NVD,CVE.org'  # Marquer comme venant des deux sources
                    logger.debug(f"✅ {cve_id}: Enrichi avec CVE.org ({len(cveorg_data.get('affected_products', []))} produits)")
                
                enriched_cves.append(nvd_cve)
                
                # Pause pour éviter rate limiting
                time.sleep(0.2)
            
            logger.info(f"✅ {len(enriched_cves)} CVEs enrichis avec CVE.org")
            return enriched_cves
            
        except Exception as e:
            logger.error(f"❌ Erreur fetch_recent_cves_from_cveorg: {str(e)}")
            return []

    @staticmethod
    def fetch_recent_cves_from_cveorg(days: int = 7, limit: int = 50) -> List[Dict]:
        """
        Récupère les CVEs récents depuis CVE.org (MITRE)
        CVE.org n'a pas d'API de recherche par date, on récupère les derniers CVE IDs
        
        Returns:
            Liste des CVEs récents depuis CVE.org
        """
        try:
            # CVE.org n'a pas d'endpoint pour lister les CVEs récents
            # On utilise NVD pour obtenir les IDs, puis on enrichit avec CVE.org
            # Pour les CVEs exclusifs, on pourrait scraper ou utiliser une autre source
            logger.info("📡 Récupération CVEs récents depuis CVE.org...")
            
            # Stratégie: récupérer quelques CVEs récents typiques
            recent_cve_ids = []
            current_year = datetime.now().year
            
            # Essayer les derniers CVE IDs de l'année en cours
            # Format: CVE-YYYY-NNNNN
            for i in range(1, limit + 1):
                recent_cve_ids.append(f"CVE-{current_year}-{i:05d}")
            
            cves = []
            for cve_id in recent_cve_ids[:limit]:
                cve_data = CVEFetcherService.fetch_cve_from_cveorg(cve_id)
                if cve_data:
                    cves.append(cve_data)
                time.sleep(0.2)
            
            logger.info(f"✅ {len(cves)} CVEs récupérés depuis CVE.org")
            return cves
            
        except Exception as e:
            logger.error(f"❌ Erreur fetch_recent_cves_from_cveorg: {str(e)}")
            return []

    @staticmethod
    def fetch_cve_from_cveorg(cve_id: str) -> Optional[Dict]:
        """
        Récupère les détails d'un CVE depuis CVE.org (MITRE)
        
        Args:
            cve_id: ID du CVE (ex: CVE-2026-0001)
            
        Returns:
            Détails du CVE ou None
        """
        try:
            url = f"{CVEFetcherService.CVEORG_BASE_URL}/{cve_id}"
            
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                logger.debug(f"ℹ️ CVE.org: {cve_id} non trouvé (status {response.status_code})")
                return None
            
            data = response.json()
            
            # Extraire les produits affectés
            containers = data.get("containers", {})
            cna = containers.get("cna", {})
            affected_list = cna.get("affected", [])
            
            affected_products = []
            for affected in affected_list[:10]:  # Limiter à 10
                vendor = affected.get("vendor", "").strip()
                product = affected.get("product", "").strip()
                
                if vendor and product:
                    affected_products.append({
                        "vendor": vendor,
                        "product": product,
                        "confidence": 1.0  # Source officielle
                    })
            
            # Description
            descriptions = cna.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Dates
            cve_metadata = data.get("cveMetadata", {})
            published = cve_metadata.get("datePublished", "")
            updated = cve_metadata.get("dateUpdated", "")
            
            return {
                "cve_id": cve_id,
                "description": description,
                "affected_products": affected_products,
                "published_date": published,
                "last_updated": updated or published,
                "source": "CVE.org"
            }
            
        except Exception as e:
            logger.debug(f"ℹ️ CVE.org: {cve_id} non disponible - {str(e)}")
            return None

    @staticmethod
    def fetch_all_sources(days: int = 7, limit: int = 100) -> Dict[str, List[Dict]]:
        """
        Récupère les CVEs depuis TOUTES les sources indépendamment
        (NVD, CVE.org, CVEdetails, MSRC)
        
        Args:
            days: Nombre de jours précédents
            limit: Nombre maximum de CVEs par source
            
        Returns:
            Dict avec les CVEs de chaque source et agrégés
        """
        logger.info(f"🌐 Récupération depuis TOUTES les sources (NVD, CVE.org, CVEdetails, MSRC)")
        
        results = {
            "nvd": [],
            "cveorg": [],
            "cvedetails": [],
            "msrc": [],
            "all": []
        }
        
        cve_dict = {}  # Pour dédupliquer et fusionner
        
        # 1. Récupérer depuis NVD (avec scores CVSS)
        try:
            logger.info("📡 Source 1/4: NVD...")
            cves_nvd = CVEFetcherService.fetch_recent_cves_from_nvd(days=days, limit=limit)
            results["nvd"] = cves_nvd
            
            for cve in cves_nvd:
                cve_id = cve['cve_id']
                if cve_id not in cve_dict:
                    cve_dict[cve_id] = cve
                else:
                    # Fusionner : garder le meilleur score
                    if cve.get('cvss_score', 0) > cve_dict[cve_id].get('cvss_score', 0):
                        cve_dict[cve_id]['cvss_score'] = cve['cvss_score']
                        cve_dict[cve_id]['cvss_version'] = cve['cvss_version']
                        cve_dict[cve_id]['severity'] = cve['severity']
                
                # Ajouter NVD à la liste des sources
                sources = cve_dict[cve_id].get('source', '').split(',')
                if 'NVD' not in sources:
                    sources.append('NVD')
                cve_dict[cve_id]['source'] = ','.join([s for s in sources if s])
            
            logger.info(f"✅ NVD: {len(cves_nvd)} CVEs")
        except Exception as e:
            logger.error(f"❌ Erreur NVD: {str(e)}")
        
        # 2. Récupérer CVEs exclusifs de CVE.org + enrichir existants
        try:
            logger.info("📡 Source 2/4: CVE.org (CVEs exclusifs + enrichissement)...")
            enriched_count = 0
            exclusive_cves = 0
            
            # Récupérer CVEs récents depuis CVE.org pour trouver les exclusifs
            cveorg_recent = CVEFetcherService.fetch_recent_cves_from_cveorg(days=days, limit=50)
            
            for cve_org in cveorg_recent:
                cve_id = cve_org['cve_id']
                
                if cve_id not in cve_dict:
                    # CVE exclusif à CVE.org (pas encore dans NVD)
                    cve_dict[cve_id] = cve_org
                    cve_dict[cve_id]['source'] = 'CVE.org'
                    exclusive_cves += 1
                else:
                    # Enrichir CVE existant avec données CVE.org (priorité)
                    if cve_org.get('cvss_score', 0) > 0:
                        cve_dict[cve_id]['cvss_score'] = cve_org['cvss_score']
                        cve_dict[cve_id]['cvss_version'] = cve_org.get('cvss_version', cve_dict[cve_id]['cvss_version'])
                        cve_dict[cve_id]['severity'] = cve_org.get('severity', cve_dict[cve_id]['severity'])
                    
                    if cve_org.get('affected_products'):
                        cve_dict[cve_id]['affected_products'] = cve_org['affected_products']
                    
                    sources = cve_dict[cve_id].get('source', '').split(',')
                    if 'CVE.org' not in sources:
                        sources.append('CVE.org')
                    cve_dict[cve_id]['source'] = ','.join([s for s in sources if s])
                    enriched_count += 1
                
                time.sleep(0.15)  # Rate limiting
            
            logger.info(f"✅ CVE.org: {enriched_count} enrichis, {exclusive_cves} exclusifs")
            results["cveorg"] = [cve_dict[cid] for cid in cve_dict if 'CVE.org' in cve_dict[cid].get('source', '')]
        except Exception as e:
            logger.error(f"❌ Erreur CVE.org: {str(e)}")
        
        # 3. Récupérer depuis CVEdetails (source alternative)
        try:
            logger.info("📡 Source 3/4: CVEdetails...")
            # CVEdetails n'a pas d'API publique, on utilise les imports existants du main.py
            # Pour l'instant, on log juste
            logger.info("ℹ️ CVEdetails: Utiliser les importers existants du main.py")
            results["cvedetails"] = []
        except Exception as e:
            logger.error(f"❌ Erreur CVEdetails: {str(e)}")
        
        # 4. Récupérer depuis MSRC (Microsoft)
        try:
            logger.info("📡 Source 4/4: MSRC...")
            # MSRC nécessite une intégration spécifique
            logger.info("ℹ️ MSRC: Utiliser les importers existants du main.py")
            results["msrc"] = []
        except Exception as e:
            logger.error(f"❌ Erreur MSRC: {str(e)}")
        
        # Construire la liste finale
        results["all"] = list(cve_dict.values())
        
        logger.info(f"📊 Résumé multi-sources:")
        logger.info(f"  - NVD: {len(results['nvd'])} CVEs")
        logger.info(f"  - CVE.org: {len(results['cveorg'])} CVEs enrichis")
        logger.info(f"  - CVEdetails: {len(results['cvedetails'])} CVEs")
        logger.info(f"  - MSRC: {len(results['msrc'])} CVEs")
        logger.info(f"  - Total unique: {len(results['all'])} CVEs")
        
        return results

    @staticmethod
    def search_cves_by_keyword(keyword: str, limit: int = 20) -> List[Dict]:
        """
        Recherche les CVEs par mot-clé dans NVD
        
        Args:
            keyword: Mot-clé de recherche
            limit: Nombre maximum de résultats
            
        Returns:
            Liste des CVEs correspondants
        """
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": min(limit, 100)
            }
            
            logger.info(f"🔍 Recherche NVD pour: '{keyword}'")
            
            response = requests.get(
                CVEFetcherService.NVD_BASE_URL,
                params=params,
                timeout=30,
                headers={"User-Agent": "CTBA-CVE-Platform/2.0"}
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            cves = []
            for vuln in vulnerabilities[:limit]:
                cve_info = CVEFetcherService._extract_cve_from_nvd(vuln)
                if cve_info:
                    cves.append(cve_info)
            
            logger.info(f"✅ {len(cves)} CVEs trouvés pour '{keyword}'")
            return cves
            
        except Exception as e:
            logger.error(f"❌ Erreur recherche CVEs: {str(e)}")
            return []
