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
        Extract products from description using NLP
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
        
        # 3. DÉDUPICATION
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
        """Règles heuristiques avancées (sans NLP)"""
        products = []
        
        # Pattern 1: "in [Vendor] [Product]"
        pattern1 = r'\b(?:in|of|for|on)\s+([A-Z][A-Za-z0-9&\.\-]+\s+[A-Z][A-Za-z0-9&\.\-]+)'
        matches1 = re.finditer(pattern1, description, re.IGNORECASE)
        for match in matches1:
            full_text = match.group(1)
            vendor, product = self._split_vendor_product(full_text)
            if vendor and product:
                products.append({
                    'vendor': vendor,
                    'product': product,
                    'confidence': 0.7,
                    'source': 'rule_pattern1'
                })
        
        # Pattern 2: "[Vendor]'s [Product]"
        pattern2 = r'([A-Z][A-Za-z0-9&\.\-]+)\'s\s+([A-Za-z0-9&\.\-]+)'
        matches2 = re.finditer(pattern2, description)
        for match in matches2:
            products.append({
                'vendor': match.group(1),
                'product': match.group(2),
                'confidence': 0.8,
                'source': 'rule_pattern2'
            })
        
        # Pattern 3: Known vendors
        known_vendors = [
            'Microsoft', 'Google', 'Apple', 'Adobe', 'Oracle', 'IBM',
            'Cisco', 'Intel', 'AMD', 'NVIDIA', 'Dell', 'HP', 'Lenovo',
            'VMware', 'Red Hat', 'Apache', 'WordPress', 'SAP', 'Siemens'
        ]
        
        for vendor in known_vendors:
            if vendor.lower() in description.lower():
                # Chercher le produit après le vendeur
                pattern = re.escape(vendor) + r'\s+([A-Z][A-Za-z0-9\s&\.\-]+)'
                match = re.search(pattern, description, re.IGNORECASE)
                if match:
                    product = match.group(1).strip()
                    products.append({
                        'vendor': vendor,
                        'product': product[:50],
                        'confidence': 0.75,
                        'source': 'rule_known_vendor'
                    })
        
        return products
    
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
        """Dédupliquer les résultats"""
        seen = set()
        unique = []
        
        for result in results:
            key = f"{result['vendor'].lower()}|{result['product'].lower()}"
            if key not in seen:
                seen.add(key)
                unique.append(result)
        
        # Trier par confiance
        unique.sort(key=lambda x: x['confidence'], reverse=True)
        return unique

# Instance globale
nlp_extractor = ProductNLP()