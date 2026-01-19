# learning_system.py
import sqlite3
import re
import threading
import logging
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

class ProductLearningSystem:
    """Système intelligent d'apprentissage des produits et vendeurs"""
    
    def __init__(self, db_file: str = "ctba_platform.db"):
        self.db_file = db_file
        self.known_vendors = set()
        self.known_products = set()
        self.vendor_product_pairs = defaultdict(int)  # {(vendor, product): count}
        self.patterns_learned = []  # Patterns appris
        self.lock = threading.Lock()
        self.initialized = False
        
    def initialize(self):
        """Initialiser le système avec les données existantes"""
        if self.initialized:
            return
            
        logger.info("🚀 Initialisation du système d'apprentissage...")
        
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # 1. Charger les vendeurs connus
            cursor.execute("""
                SELECT DISTINCT vendor 
                FROM affected_products 
                WHERE vendor != 'Unknown' 
                AND LENGTH(vendor) > 1
            """)
            for row in cursor.fetchall():
                self.known_vendors.add(row['vendor'])
            
            # 2. Charger les produits connus
            cursor.execute("""
                SELECT DISTINCT product 
                FROM affected_products 
                WHERE product != 'Multiple Products' 
                AND LENGTH(product) > 1
            """)
            for row in cursor.fetchall():
                self.known_products.add(row['product'])
            
            # 3. Charger les paires fréquentes
            cursor.execute("""
                SELECT vendor, product, COUNT(*) as frequency
                FROM affected_products
                WHERE vendor != 'Unknown' 
                AND product != 'Multiple Products'
                GROUP BY vendor, product
                ORDER BY frequency DESC
                LIMIT 200
            """)
            
            for row in cursor.fetchall():
                key = (row['vendor'], row['product'])
                self.vendor_product_pairs[key] = row['frequency']
            
            # 4. Apprendre des patterns depuis les descriptions réussies
            self._learn_from_successful_matches(cursor)
            
            conn.close()
            
            logger.info(f"✅ Système d'apprentissage initialisé")
            logger.info(f"   📊 Vendeurs connus: {len(self.known_vendors)}")
            logger.info(f"   📊 Produits connus: {len(self.known_products)}")
            logger.info(f"   📊 Paires fréquentes: {len(self.vendor_product_pairs)}")
            
            self.initialized = True
            
        except Exception as e:
            logger.error(f"❌ Erreur initialisation apprentissage: {e}")
    
    def _learn_from_successful_matches(self, cursor):
        """Apprendre des extractions réussies"""
        try:
            # Vérifier si la colonne 'source' existe
            cursor.execute("PRAGMA table_info(affected_products)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'source' in columns:
                # Si la colonne existe
                cursor.execute("""
                    SELECT c.description, ap.vendor, ap.product
                    FROM cves c
                    JOIN affected_products ap ON c.cve_id = ap.cve_id
                    WHERE ap.confidence > 0.7
                    AND ap.source NOT IN ('cpe', 'fallback')
                    AND c.description IS NOT NULL
                    AND LENGTH(c.description) > 50
                    LIMIT 50
                """)
            else:
                # Si la colonne n'existe pas, utiliser une approche différente
                cursor.execute("""
                    SELECT c.description, ap.vendor, ap.product
                    FROM cves c
                    JOIN affected_products ap ON c.cve_id = ap.cve_id
                    WHERE ap.confidence > 0.7
                    AND ap.vendor != 'Unknown'
                    AND ap.product != 'Multiple Products'
                    AND c.description IS NOT NULL
                    AND LENGTH(c.description) > 50
                    LIMIT 50
                """)
            
            for row in cursor.fetchall():
                description = row[0]  # description
                vendor = row[1]  # vendor
                product = row[2]  # product
                
                # Extraire des patterns
                patterns = self._extract_patterns_from_match(description, vendor, product)
                self.patterns_learned.extend(patterns)
                
        except Exception as e:
            logger.warning(f"Erreur lors de l'apprentissage des patterns: {e}")
            # Continuer même en cas d'erreur
    
    def _extract_patterns_from_match(self, description: str, vendor: str, product: str) -> List[str]:
        """Extraire des patterns depuis une correspondance réussie"""
        patterns = []
        try:
            if not description or not vendor or not product:
                return patterns
                
            desc_lower = description.lower()
            vendor_lower = vendor.lower()
            product_lower = product.lower()
            
            # Chercher le pattern "vendor product"
            vendor_product_pattern = f"{vendor_lower} {product_lower}"
            if vendor_product_pattern in desc_lower:
                patterns.append(f"{vendor} {product}")
            
            # Chercher le pattern "product by vendor"
            by_pattern = f"{product_lower} by {vendor_lower}"
            if by_pattern in desc_lower:
                patterns.append(f"{product} by {vendor}")
            
            # Chercher le pattern "vendor's product"
            possesive_pattern = f"{vendor_lower}'s {product_lower}"
            if possesive_pattern in desc_lower:
                patterns.append(f"{vendor}'s {product}")
                
        except Exception as e:
            logger.debug(f"Erreur extraction pattern: {e}")
            
        return patterns
    
    def learn_product(self, vendor: str, product: str):
        """Apprendre une nouvelle paire vendeur-produit"""
        with self.lock:
            if vendor and vendor != 'Unknown' and len(vendor) > 1:
                self.known_vendors.add(vendor)
            
            if product and product != 'Multiple Products' and len(product) > 1:
                self.known_products.add(product)
            
            if (vendor and product and 
                vendor != 'Unknown' and 
                product != 'Multiple Products' and
                len(vendor) > 1 and len(product) > 1):
                
                key = (vendor, product)
                self.vendor_product_pairs[key] += 1
    
    def learn_from_cpe(self, cpe_uri: str):
        """Apprendre d'un CPE URI"""
        vendor, product = self._extract_from_cpe(cpe_uri)
        if vendor and product:
            self.learn_product(vendor, product)
    
    def _extract_from_cpe(self, cpe_uri: str):
        """Extraire vendeur/produit depuis CPE"""
        try:
            if not cpe_uri or not isinstance(cpe_uri, str):
                return None, None
            
            cpe_uri = cpe_uri.strip()
            
            if cpe_uri.startswith('cpe:2.3:'):
                parts = cpe_uri.split(':')
                if len(parts) >= 6:
                    vendor_raw = parts[3]
                    product_raw = parts[4]
                    
                    if vendor_raw in ['-', '*', '', '~'] or product_raw in ['-', '*', '', '~']:
                        return None, None
                    
                    vendor = self._clean_cpe_value(vendor_raw)
                    product = self._clean_cpe_value(product_raw)
                    
                    return vendor, product
                    
        except Exception as e:
            logger.debug(f"Erreur extraction CPE: {e}")
        
        return None, None
    
    def _clean_cpe_value(self, value: str) -> str:
        """Nettoyer une valeur CPE"""
        if not value:
            return ""
        
        value = value.replace('_', ' ').replace('\\', '').strip()
        value = re.sub(r'[^\w\s\-\.]', ' ', value)
        value = re.sub(r'\s+', ' ', value)
        
        if value.isupper() or value.islower():
            value = value.title()
        
        return value.strip()
    
    def suggest_products(self, description: str, cve_id: str = "") -> List[Dict[str, Any]]:
        """
        Suggérer des produits basés sur l'apprentissage
        Retourne une liste de produits avec confiance
        """
        if not description:
            return []
        
        suggestions = []
        desc_lower = description.lower()
        
        # 1. Vérifier les patterns appris
        for pattern in self.patterns_learned:
            if pattern.lower() in desc_lower:
                # Découper le pattern
                parts = pattern.split()
                if len(parts) >= 2:
                    vendor = parts[0]
                    product = ' '.join(parts[1:])
                    
                    suggestions.append({
                        'vendor': vendor,
                        'product': product,
                        'confidence': 0.9,
                        'source': 'learned_pattern',
                        'cve_id': cve_id
                    })
        
        # 2. Chercher les vendeurs connus dans la description
        found_vendors = []
        for vendor in self.known_vendors:
            if vendor.lower() in desc_lower:
                found_vendors.append(vendor)
        
        # Pour chaque vendeur trouvé, chercher ses produits associés
        for vendor in found_vendors[:3]:  # Limiter à 3 vendeurs
            # Trouver les produits fréquents pour ce vendeur
            vendor_products = []
            for (v, product), count in self.vendor_product_pairs.items():
                if v.lower() == vendor.lower() and count > 1:
                    vendor_products.append((product, count))
            
            # Trier par fréquence
            vendor_products.sort(key=lambda x: x[1], reverse=True)
            
            # Vérifier si ces produits sont dans la description
            for product, frequency in vendor_products[:3]:  # Top 3 produits
                if product.lower() in desc_lower:
                    confidence = min(0.8 + (frequency * 0.05), 0.95)
                    suggestions.append({
                        'vendor': vendor,
                        'product': product,
                        'confidence': confidence,
                        'source': 'learned_pair',
                        'frequency': frequency,
                        'cve_id': cve_id
                    })
                else:
                    # Produit pas dans la description mais fréquent avec ce vendeur
                    suggestions.append({
                        'vendor': vendor,
                        'product': product,
                        'confidence': 0.6,
                        'source': 'frequent_pair',
                        'frequency': frequency,
                        'cve_id': cve_id
                    })
            
            # Si pas de produits spécifiques trouvés
            if not any(p.get('vendor') == vendor for p in suggestions):
                suggestions.append({
                    'vendor': vendor,
                    'product': 'Various Products',
                    'confidence': 0.5,
                    'source': 'vendor_only',
                    'cve_id': cve_id
                })
        
        # 3. Chercher des patterns communs
        common_patterns = self._extract_common_patterns(description)
        suggestions.extend(common_patterns)
        
        # 4. Trier par confiance et dédupliquer
        return self._deduplicate_suggestions(suggestions)
    
    def _extract_common_patterns(self, description: str) -> List[Dict]:
        """Extraire avec des patterns communs"""
        patterns = [
            # Pattern: [Vendor] [Product]
            (r'\b([A-Z][A-Za-z0-9&\.\-]+(?: [A-Z][A-Za-z0-9&\.\-]+)*) ([A-Z][A-Za-z0-9]+(?: [A-Za-z0-9]+)+)', (1, 2)),
            
            # Pattern: [Product] from [Vendor]
            (r'([A-Z][A-Za-z0-9\s]+) from ([A-Z][A-Za-z0-9]+)', (2, 1)),
            
            # Pattern: [Vendor]'s [Product]
            (r"([A-Z][A-Za-z0-9]+)'s ([A-Z][A-Za-z0-9\s]+)", (1, 2)),
        ]
        
        extracted = []
        for pattern, (vendor_idx, product_idx) in patterns:
            try:
                matches = re.finditer(pattern, description, re.IGNORECASE)
                for match in matches:
                    vendor = match.group(vendor_idx).strip()
                    product = match.group(product_idx).strip()
                    
                    # Valider
                    if self._is_valid_vendor(vendor) and self._is_valid_product(product):
                        extracted.append({
                            'vendor': vendor,
                            'product': product,
                            'confidence': 0.7,
                            'source': 'pattern_match'
                        })
            except Exception as e:
                continue
        
        return extracted
    
    def _is_valid_vendor(self, name: str) -> bool:
        """Valider un nom de vendeur"""
        if not name or len(name) < 2 or len(name) > 50:
            return False
        
        name_lower = name.lower()
        
        # Mots interdits
        invalid_words = {'vulnerability', 'security', 'issue', 'problem', 
                        'allows', 'enables', 'could', 'would', 'should',
                        'this', 'that', 'these', 'those', 'which'}
        
        if any(word in name_lower for word in invalid_words):
            return False
        
        # Doit contenir des lettres
        if not re.search(r'[A-Za-z]', name):
            return False
        
        return True
    
    def _is_valid_product(self, name: str) -> bool:
        """Valider un nom de produit"""
        if not name or len(name) < 2 or len(name) > 80:
            return False
        
        name_lower = name.lower()
        
        # Mots interdits
        invalid_words = {'vulnerability', 'vulnerable', 'security', 
                        'allows', 'enables', 'could', 'would',
                        'this', 'that', 'these', 'those'}
        
        if any(word in name_lower for word in invalid_words):
            return False
        
        # Doit contenir des lettres
        if not re.search(r'[A-Za-z]', name):
            return False
        
        return True
    
    def _deduplicate_suggestions(self, suggestions: List[Dict]) -> List[Dict]:
        """Dédupliquer les suggestions"""
        seen = set()
        unique = []
        
        for suggestion in suggestions:
            try:
                key = (suggestion['vendor'].lower(), suggestion['product'].lower())
                if key not in seen:
                    seen.add(key)
                    unique.append(suggestion)
            except Exception:
                continue
        
        # Trier par confiance décroissante
        unique.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        return unique[:5]  # Retourner max 5 suggestions
    
    def get_stats(self) -> Dict:
        """Obtenir les statistiques du système"""
        try:
            # Préparer les top paires
            top_pairs_list = []
            for (vendor, product), count in self.vendor_product_pairs.items():
                top_pairs_list.append(((vendor, product), count))
            
            top_pairs_list.sort(key=lambda x: x[1], reverse=True)
            
            return {
                'initialized': self.initialized,
                'known_vendors': len(self.known_vendors),
                'known_products': len(self.known_products),
                'vendor_product_pairs': len(self.vendor_product_pairs),
                'learned_patterns': len(self.patterns_learned),
                'top_vendors': list(self.known_vendors)[:10],
                'top_pairs': top_pairs_list[:10]
            }
        except Exception as e:
            logger.error(f"Erreur get_stats: {e}")
            return {
                'initialized': self.initialized,
                'error': str(e)
            }

# Instance globale
product_learner = ProductLearningSystem()