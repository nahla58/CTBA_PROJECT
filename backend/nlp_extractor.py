"""
nlp_extractor.py
NLP Product Extractor - Traitement parallèle sans modifier l'existant
"""
import spacy
from typing import List, Dict, Any, Optional
import logging
import re

logger = logging.getLogger(__name__)

class ProductNLP:
    """Classe NLP pour extraction parallèle des produits"""
    
    def __init__(self):
        self.nlp = None
        self.initialized = False
        
    def initialize(self):
        """Initialiser spaCy (optionnel)"""
        try:
            self.nlp = spacy.load("en_core_web_sm")
            self.initialized = True
            logger.info("✅ NLP extractor initialized successfully")
        except Exception as e:
            logger.warning(f"⚠️ Could not load spaCy: {e}. Using rule-based fallback.")
            self.nlp = None
            self.initialized = False
    
    def extract_products(self, description: str, cve_id: str = "") -> List[Dict[str, Any]]:
        """
        Extract products from description using NLP and CPE URIs.
        Returns: [{'vendor': '...', 'product': '...', 'confidence': 0.9, 'source': 'nlp'}]
        """
        if not description:
            return []
        
        results = []
        
        # 1. ESSAYER spaCy SI DISPONIBLE
        if self.nlp and self.initialized:
            nlp_results = self._extract_with_spacy(description)
            results.extend(nlp_results)
        
        # 2. RÈGLES AVANCÉES (fallback)
        rule_results = self._extract_with_rules(description)
        results.extend(rule_results)

        # 3. Extraire des URI CPE
        cpe_results = self._extract_with_cpe_uris(description)
        results.extend(cpe_results)
        
        # 4. DÉDUPLICATION
        unique_results = self._deduplicate_results(results)

        # Ajouter le CVE ID pour référence
        for res in unique_results:
            res['cve_id'] = cve_id
        
        return unique_results[:3]  # Retourner top 3
    
    def _extract_with_spacy(self, description: str) -> List[Dict[str, Any]]:
        """Extraction avec spaCy NLP"""
        try:
            # Limiter la taille pour performance
            text = description[:1500] if len(description) > 1500 else description
            doc = self.nlp(text)
            
            products = []
            
            # Pattern 1: Entities (ORG, PRODUCT)
            for ent in doc.ents:
                if ent.label_ in ['ORG', 'PRODUCT']:
                    vendor, product = self._parse_entity(ent.text, doc)
                    if vendor and product:
                        confidence = self._calculate_confidence(ent.label_, ent.text)
                        products.append({
                            'vendor': vendor,
                            'product': product,
                            'confidence': confidence,
                            'source': f'spacy_{ent.label_.lower()}'
                        })
            
            # Pattern 2: Noun phrases avec marque
            for chunk in doc.noun_chunks:
                if self._is_product_chunk(chunk.text):
                    vendor, product = self._extract_from_chunk(chunk.text)
                    if vendor and product:
                        products.append({
                            'vendor': vendor,
                            'product': product,
                            'confidence': 0.65,
                            'source': 'spacy_noun_chunk'
                        })
            
            return products
            
        except Exception as e:
            logger.error(f"spaCy extraction error: {e}")
            return []
    
    def _extract_with_rules(self, description: str) -> List[Dict[str, Any]]:
        """Règles heuristiques avancées pour extraction vendor/produit"""
        products = []
        seen = set()
        
        # Vendors réels et leurs products associés
        vendors_database = {
            'Microsoft': ['Windows', 'Office', 'Exchange', 'SQL Server', 'Azure', 'Outlook', 'Excel', 'Word', 'Internet Explorer', 'Edge', 'Server'],
            'Google': ['Chrome', 'Android', 'Gmail', 'Cloud', 'Workspace', 'Pixel'],
            'Apple': ['iOS', 'macOS', 'Safari', 'iTunes', 'iCloud', 'XCode'],
            'Adobe': ['Reader', 'Flash', 'Acrobat', 'Photoshop', 'InDesign', 'Premiere', 'Creative'],
            'Oracle': ['Java', 'MySQL', 'VirtualBox', 'Database', 'WebLogic', 'Coherence'],
            'IBM': ['WebSphere', 'Cognos', 'MQ', 'Notes', 'Domino', 'AIX'],
            'Cisco': ['IOS', 'ASA', 'Nexus', 'Catalyst', 'Router', 'Switch'],
            'Apache': ['HTTP Server', 'Tomcat', 'Log4j', 'Struts', 'Kafka', 'Hadoop'],
            'VMware': ['vSphere', 'ESXi', 'Workstation', 'Fusion', 'NSX', 'vCenter'],
            'Red Hat': ['Enterprise Linux', 'OpenStack', 'Ansible', 'Kubernetes', 'Fedora'],
            'WordPress': ['Core', 'Plugin', 'Theme', 'Jetpack'],
            'SAP': ['ERP', 'HANA', 'NetWeaver', 'BusinessObjects', 'SuccessFactors'],
            'Siemens': ['STEP 7', 'TIA Portal', 'SCADA', 'Automation', 'S7-1200'],
            'Linux': ['Kernel', 'Ubuntu', 'CentOS', 'Debian', 'RHEL'],
            'Python': ['Core', 'Runtime', 'Interpreter', 'pip'],
            'PHP': ['Core', 'Runtime', 'Interpreter', 'Laravel'],
            'Node.js': ['Runtime', 'NPM', 'Express'],
            'Django': ['Framework', 'ORM', 'Web'],
            'Flask': ['Framework', 'Werkzeug', 'Jinja'],
            'Ruby': ['Runtime', 'Rails', 'Gem'],
            'Java': ['Runtime', 'Development Kit', 'JVM'],
            'OpenSSL': ['Library', 'OpenSSL'],
            'Nginx': ['HTTP Server', 'Reverse Proxy'],
            'PostgreSQL': ['Database', 'PostgreSQL'],
            'MongoDB': ['Database', 'MongoDB'],
            'Docker': ['Container', 'Engine'],
            'Kubernetes': ['Container', 'Orchestration'],
            'Assimp': ['Library', 'Model Loader'],
            'Curl': ['libcurl', 'Tool'],
            'OpenStack': ['Cloud', 'Nova', 'Neutron'],
            'Jenkins': ['CI/CD', 'Automation'],
            'Git': ['Version Control', 'GitHub'],
            'Elasticsearch': ['Search', 'Analytics'],
            'Zend': ['Framework', 'Engine'],
        }
        
        # Pattern 1: Vendor mention suivi de description de produit
        # "vulnerability in [VENDOR] [PRODUCT]" ou "vulnerability in the [PRODUCT] component of [VENDOR]"
        vendor_product_patterns = [
            r'(?:vulnerability|flaw|weakness|issue|bug|defect)\s+(?:in|within|affecting)\s+(?:the\s+)?([A-Z][A-Za-z0-9&\.\-]+)(?:\s+([A-Z][A-Za-z0-9&\.\-\s]+?))?(?:\s+(?:version|v\.|release|before|through|component|module|function))',
            r'(?:in|affecting|found in)\s+([A-Z][A-Za-z0-9&\.\-]+)\s+([A-Z][A-Za-z0-9&\.\-\s]+?)(?:\s+(?:version|v\.|before|through))',
            r'discovered\s+in\s+(?:the\s+)?([A-Z][A-Za-z0-9&\.\-]+)\s+(?:runtime|engine|framework|library|server|database|module)?\s*(?:([A-Z][A-Za-z0-9&\.\-\s]+?))?',
        ]
        
        for pattern in vendor_product_patterns:
            matches = re.finditer(pattern, description, re.IGNORECASE)
            for match in matches:
                vendor = match.group(1).strip()
                product = match.group(2).strip() if match.lastindex >= 2 else None
                
                # Validate vendor
                if vendor.lower() in [v.lower() for v in vendors_database.keys()]:
                    vendor_real = next(v for v in vendors_database.keys() if v.lower() == vendor.lower())
                    
                    if product:
                        key = (vendor_real.lower(), product.lower())
                        if key not in seen and len(product) < 80 and product.lower() not in ['programming language', 'framework', 'library', 'tool']:
                            seen.add(key)
                            products.append({
                                'vendor': vendor_real,
                                'product': product,
                                'confidence': 0.85,
                                'source': 'rule_vendor_product'
                            })
                    else:
                        # Pas de product trouvé, utiliser le premier keyword du vendor
                        product = vendors_database[vendor_real][0]
                        key = (vendor_real.lower(), product.lower())
                        if key not in seen:
                            seen.add(key)
                            products.append({
                                'vendor': vendor_real,
                                'product': product,
                                'confidence': 0.75,
                                'source': 'rule_vendor_default'
                            })
        
        # Pattern 2: Known vendor detection by keyword
        for vendor, keywords in vendors_database.items():
            # Check if vendor name appears in description
            if re.search(r'\b' + re.escape(vendor) + r'\b', description, re.IGNORECASE):
                # Find associated products
                found = False
                for keyword in keywords:
                    if re.search(r'\b' + re.escape(keyword) + r'\b', description, re.IGNORECASE):
                        key = (vendor.lower(), keyword.lower())
                        if key not in seen:
                            seen.add(key)
                            products.append({
                                'vendor': vendor,
                                'product': keyword,
                                'confidence': 0.80,
                                'source': 'rule_known_vendor'
                            })
                            found = True
                            break
                
                # Si aucun keyword trouvé mais vendor trouvé, ajouter le premier keyword comme default
                if not found:
                    key = (vendor.lower(), keywords[0].lower())
                    if key not in seen:
                        seen.add(key)
                        products.append({
                            'vendor': vendor,
                            'product': keywords[0],
                            'confidence': 0.70,
                            'source': 'rule_vendor_inferred'
                        })
        
        # Pattern 3: Version-based extraction
        # "[VENDOR] [PRODUCT] version X.Y" or "[VENDOR] [PRODUCT] vX.Y"
        version_pattern = r'([A-Z][A-Za-z0-9&\.\-]+)\s+([A-Z][A-Za-z0-9&\.\-\s]+?)\s+(?:version|v\.?)\s+[0-9]'
        matches = re.finditer(version_pattern, description, re.IGNORECASE)
        for match in matches:
            vendor = match.group(1).strip()
            product = match.group(2).strip()
            
            # Verify vendor exists
            if any(vendor.lower() == v.lower() for v in vendors_database.keys()):
                vendor_real = next(v for v in vendors_database.keys() if v.lower() == vendor.lower())
                key = (vendor_real.lower(), product.lower())
                if key not in seen and len(product) < 80:
                    seen.add(key)
                    products.append({
                        'vendor': vendor_real,
                        'product': product,
                        'confidence': 0.78,
                        'source': 'rule_version_pattern'
                    })
        
        return products
    
    def _extract_with_cpe_uris(self, description: str) -> List[Dict[str, Any]]:
        """
        Extract products from CPE URIs in the description.
        Supports multiple CPE formats:
        - cpe:2.3:a:vendor:product:version:...
        - cpe:2.3:o:vendor:product:version:...
        - cpe:2.3:h:vendor:product:version:...
        Returns: [{'vendor': '...', 'product': '...', 'confidence': 1.0, 'source': 'cpe_uri'}]
        """
        results = []
        
        # Pattern for CPE 2.3 URIs: cpe:2.3:TYPE:VENDOR:PRODUCT:...
        cpe_pattern = r'cpe:2\.3:[aho]:([^:]+):([^:]+)'
        matches = re.finditer(cpe_pattern, description)
        
        seen = set()
        for match in matches:
            vendor = match.group(1).strip()
            product = match.group(2).strip()
            
            # Normalize: replace URL encoding
            vendor = vendor.replace('%', '').replace('_', ' ').strip()
            product = product.replace('%', '').replace('_', ' ').strip()
            
            # Avoid duplicates
            key = (vendor.lower(), product.lower())
            if key not in seen and vendor and product:
                seen.add(key)
                results.append({
                    'vendor': vendor,
                    'product': product,
                    'confidence': 1.0,
                    'source': 'cpe_uri'
                })
        
        # Also try CPE 2.2 format (older): cpe:/a:vendor:product:version
        cpe_v2_pattern = r'cpe:/[aho]:([^/:]+):([^/:]+)'
        matches_v2 = re.finditer(cpe_v2_pattern, description)
        
        for match in matches_v2:
            vendor = match.group(1).strip()
            product = match.group(2).strip()
            
            vendor = vendor.replace('%', '').replace('_', ' ').strip()
            product = product.replace('%', '').replace('_', ' ').strip()
            
            key = (vendor.lower(), product.lower())
            if key not in seen and vendor and product:
                seen.add(key)
                results.append({
                    'vendor': vendor,
                    'product': product,
                    'confidence': 0.95,  # Slightly lower for older CPE format
                    'source': 'cpe_v2_uri'
                })
        
        return results

    def _parse_entity(self, entity_text: str, doc) -> tuple:
        """Parser une entité pour extraire vendor/product"""
        # Cas 1: "Microsoft Windows" -> Microsoft, Windows
        words = entity_text.split()
        if len(words) >= 2:
            vendor = words[0]
            product = ' '.join(words[1:])
            return vendor, product
        
        # Cas 2: Chercher dans le contexte
        for token in doc:
            if token.text in entity_text:
                # Regarder les dépendances
                if token.dep_ == 'compound' and token.head.text:
                    return token.head.text, entity_text
        
        return "Unknown", entity_text
    
    def _is_product_chunk(self, text: str) -> bool:
        """Vérifier si un chunk ressemble à un produit"""
        if not text or len(text) < 2:
            return False
        
        text_lower = text.lower()
        
        # Blacklist
        blacklist = [
            'vulnerability', 'vulnerable', 'security', 'allows', 'could',
            'would', 'might', 'attack', 'exploit', 'issue', 'problem'
        ]
        
        for word in blacklist:
            if word in text_lower:
                return False
        
        # Doit contenir au moins une majuscule (nom propre)
        if not any(c.isupper() for c in text):
            return False
        
        return True
    
    def _extract_from_chunk(self, chunk: str) -> tuple:
        """Extraire vendor/product d'un chunk"""
        words = chunk.split()
        if len(words) >= 2:
            # Prendre premier mot comme vendor potentiel
            vendor = words[0]
            product = ' '.join(words[1:])
            
            # Nettoyer
            product = re.sub(r'\s+(?:vulnerability|vulnerable|security).*$', '', product, flags=re.IGNORECASE)
            
            return vendor, product
        
        return None, None
    
    def _split_vendor_product(self, text: str) -> tuple:
        """Séparer vendor et product"""
        words = text.split()
        if len(words) >= 2:
            # Prendre le premier mot comme vendor
            vendor = words[0]
            
            # Le reste comme product (limité)
            product_words = []
            for word in words[1:]:
                if len(word) >= 2 and not word.isdigit():
                    product_words.append(word)
                if len(' '.join(product_words)) > 30:  # Limite
                    break
            
            product = ' '.join(product_words) if product_words else "Unknown"
            return vendor, product
        
        return None, None
    
    def _calculate_confidence(self, label: str, text: str) -> float:
        """Calculer la confiance basée sur plusieurs facteurs"""
        confidence = 0.7  # Base
        
        # Ajustement par label
        if label == 'PRODUCT':
            confidence += 0.15
        elif label == 'ORG':
            confidence += 0.1
        
        # Ajustement par longueur
        words = text.split()
        if len(words) == 1:
            confidence -= 0.1
        elif len(words) >= 3:
            confidence += 0.05
        
        # Ajustement par casse
        if text.isupper() or text[0].isupper():
            confidence += 0.05
        
        return min(max(confidence, 0.1), 1.0)
    
    def _deduplicate_results(self, results: List[Dict]) -> List[Dict]:
        """Dédupliquer et normaliser les résultats"""
        seen = set()
        unique = []
        
        for result in results:
            # Normaliser vendor et product
            vendor = result['vendor'].strip()
            product = result['product'].strip()
            
            # Nettoyer les formats incorrects
            vendor, product = self._clean_vendor_product(vendor, product)
            
            # Filtrer les mauvaises extractions
            if not self._is_valid_extraction(vendor, product):
                continue
            
            key = f"{vendor.lower()}|{product.lower()}"
            if key not in seen:
                seen.add(key)
                result['vendor'] = vendor
                result['product'] = product
                unique.append(result)
        
        # Trier par confiance
        unique.sort(key=lambda x: x['confidence'], reverse=True)
        return unique
    
    def _clean_vendor_product(self, vendor: str, product: str) -> tuple:
        """Nettoyer et normaliser vendor et product"""
        # Enlever les prefixes incorrects
        if ":" in vendor:
            parts = vendor.split(":")
            vendor = parts[0].strip()
        
        if ":" in product:
            parts = product.split(":")
            product = parts[0].strip()
        
        # Enlever les descriptions génériques du product
        generic_suffixes = [
            "programming language", "language", "framework", "library",
            "tool", "software", "platform", "database", "server",
            "client", "application", "system", "module"
        ]
        
        product_lower = product.lower()
        for suffix in generic_suffixes:
            if product_lower.endswith(suffix):
                # Enlever le suffix
                product = product[:-len(suffix)].strip()
                break
        
        # Enlever les caractères spéciaux de Vuldb
        product = product.replace("?Ctiid.", "").replace("?Id.", "").replace("?Submit.", "")
        product = product.replace("?", "").strip()
        
        # Nettoyer les espaces multiples
        vendor = " ".join(vendor.split())
        product = " ".join(product.split())
        
        # Capitalize proprement
        vendor = vendor.title() if vendor else "Unknown"
        product = product.title() if product else "Unknown"
        
        return vendor, product
    
    def _is_valid_extraction(self, vendor: str, product: str) -> bool:
        """Vérifier si une extraction est valide"""
        # Filtrer les unknown ou trop courts
        if not vendor or not product:
            return False
        
        if vendor.lower() == "unknown" or product.lower() == "unknown":
            return False
        
        # Trop courts (moins de 2 caractères)
        if len(vendor) < 2 or len(product) < 2:
            return False
        
        # Produit = vendor (mauvaise extraction)
        if vendor.lower() == product.lower():
            return False
        
        # Ne pas contenir seulement des caractères spéciaux
        if not any(c.isalnum() for c in vendor) or not any(c.isalnum() for c in product):
            return False
        
        # Trop longs (probablement mauvaise extraction)
        if len(vendor) > 100 or len(product) > 100:
            return False
        
        # Whitelist des vendors réels
        known_vendors = [
            'Microsoft', 'Google', 'Apple', 'Adobe', 'Oracle', 'IBM', 'Cisco', 'Apache',
            'VMware', 'Red Hat', 'WordPress', 'SAP', 'Siemens', 'Linux', 'Python', 'PHP',
            'Node.js', 'Django', 'Flask', 'Ruby', 'Java', 'OpenSSL', 'Nginx', 'PostgreSQL',
            'MongoDB', 'Docker', 'Kubernetes', 'Assimp', 'Curl', 'OpenStack', 'Jenkins',
            'Git', 'Elasticsearch', 'Zend', 'Tomcat', 'MySQL', 'SQLite', 'MariaDB',
            'Express', 'React', 'Vue', 'Angular', 'Webpack', 'Babel', 'ESLint'
        ]
        
        vendor_lower = vendor.lower()
        if not any(vendor_lower == v.lower() for v in known_vendors):
            # Rejeter les vendors inconnus (Github, Vuldb, Esm Dev, Prior, System, User Attachments, etc.)
            return False
        
        # Blacklist des mauvaises patterns de products
        bad_patterns = [
            'programming language', 'framework', 'library', 'tool', 'component',
            'module', 'plugin', 'theme', 'file', 'attachment', 'files',
            'upgrade', 'upgrade-related', 'system', 'prior', 'to', 'dev',
            'esm.sh', 'lx 66 lx', 'davcloudz',
            'ctiid', 'submit', 'vuldb', 'github', 'user attachments'
        ]
        
        product_lower = product.lower()
        for bad_pattern in bad_patterns:
            if bad_pattern in product_lower:
                return False
        
        # Product must start with alphanumeric
        if not product[0].isalnum():
            return False
        
        return True
        
        # Blacklist des mauvaises sources
        blacklist_patterns = [
            "ctiid", "submit", "id.",
            "lx 66 lx", "davcloudz", "programming language", 
            "framework", "library", "tool"
        ]
        
        full_text = f"{vendor} {product}".lower()
        for pattern in blacklist_patterns:
            if pattern in full_text:
                return False
        
        return True

# Instance globale
nlp_extractor = ProductNLP()