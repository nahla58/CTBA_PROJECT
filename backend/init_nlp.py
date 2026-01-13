#!/usr/bin/env python3
"""
Script d'initialisation NLP séparé
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from nlp_extractor import nlp_extractor
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Initialiser et tester NLP"""
    logger.info("Initializing NLP extractor...")
    
    nlp_extractor.initialize()
    
    if nlp_extractor.initialized:
        logger.info("✅ NLP extractor ready")
        
        # Test avec un exemple
        test_text = "A vulnerability in Microsoft Windows allows remote code execution."
        results = nlp_extractor.extract_products(test_text, "TEST-2024-0001")
        
        logger.info(f"Test extraction: {len(results)} products found")
        for prod in results:
            logger.info(f"  - {prod['vendor']} / {prod['product']} (confidence: {prod['confidence']})")
    else:
        logger.warning("⚠️ NLP extractor not available. Using rule-based fallback.")

if __name__ == "__main__":
    main()