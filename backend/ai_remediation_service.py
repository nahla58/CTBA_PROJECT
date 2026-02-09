"""
Service IA pour la remédiation automatique des CVEs
Utilise Hugging Face Transformers avec modèle Phi-3-mini
"""

from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class AIRemediationService:
    """Service de remédiation IA pour les CVEs"""
    
    def __init__(self, model_name: str = "microsoft/Phi-3-mini-4k-instruct"):
        """
        Initialise le service IA
        
        Args:
            model_name: Nom du modèle Hugging Face à utiliser
                       Options recommandées:
                       - microsoft/Phi-3-mini-4k-instruct (léger, 4GB)
                       - mistralai/Mistral-7B-Instruct-v0.2 (performant, 7GB)
        """
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.loaded = False
        
    def load_model(self):
        """Charge le modèle en mémoire (peut prendre 1-2 minutes)"""
        if self.loaded:
            logger.info("Modèle déjà chargé")
            return
            
        try:
            logger.info(f"Chargement du modèle {self.model_name}...")
            
            # Charger le tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            # Charger le modèle avec optimisations
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype="auto",  # Détection automatique du type
                device_map="auto",  # GPU si disponible, sinon CPU
                trust_remote_code=True,
                low_cpu_mem_usage=True  # Optimisation mémoire
            )
            
            self.loaded = True
            logger.info("✓ Modèle chargé avec succès!")
            
        except Exception as e:
            logger.error(f"Erreur chargement modèle: {e}", exc_info=True)  # Afficher traceback complet
            raise
    
    def generate_remediation(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Génère des recommandations de remédiation pour un CVE
        
        Args:
            cve_id: Identifiant du CVE (ex: CVE-2024-1234)
            description: Description de la vulnérabilité
            severity: Niveau de sévérité (CRITICAL, HIGH, MEDIUM, LOW)
            cvss_score: Score CVSS (0.0 - 10.0)
            affected_products: Produits affectés (optionnel)
            
        Returns:
            Dict avec sections de remédiation structurées
        """
        if not self.loaded:
            self.load_model()
        
        # Construire le prompt
        prompt = self._build_prompt(
            cve_id, description, severity, cvss_score, affected_products
        )
        
        # Générer la réponse
        response = self._generate_text(prompt)
        
        # Parser la réponse en sections
        parsed = self._parse_response(response)
        
        return parsed
    
    def _build_prompt(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: Optional[str]
    ) -> str:
        """Construit le prompt pour le modèle"""
        
        products_text = f"\nProduits affectés: {affected_products}" if affected_products else ""
        
        prompt = f"""Tu es un expert en cybersécurité spécialisé en remédiation de vulnérabilités.

Analyse cette vulnérabilité et fournis des recommandations détaillées de remédiation:

CVE: {cve_id}
Sévérité: {severity} (Score CVSS: {cvss_score}/10){products_text}
Description: {description}

Fournis une réponse structurée en français avec ces sections:

## 1. ACTIONS IMMÉDIATES
Liste les actions prioritaires à effectuer immédiatement

## 2. CORRECTIFS ET PATCHES
Détaille les patches disponibles et comment les appliquer

## 3. SOLUTIONS DE CONTOURNEMENT
Si pas de patch immédiat, propose des workarounds temporaires

## 4. VÉRIFICATION
Comment vérifier que la remédiation est effective

Réponds de manière concise, technique et actionnable."""

        return prompt
    
    def _generate_text(self, prompt: str, max_tokens: int = 600) -> str:
        """Génère du texte avec le modèle"""
        
        try:
            # Tokeniser le prompt
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=2048
            ).to(self.model.device)
            
            # Générer la réponse
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_tokens,
                    temperature=0.7,
                    do_sample=True,
                    top_p=0.9,
                    repetition_penalty=1.1,
                    pad_token_id=self.tokenizer.eos_token_id,
                    use_cache=False  # Désactiver cache pour éviter erreur
                )
            
            # Décoder la réponse
            full_response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extraire seulement la réponse (enlever le prompt)
            response = full_response.split(prompt)[-1].strip()
            
            return response
            
        except Exception as e:
            logger.error(f"Erreur génération: {e}")
            return f"Erreur lors de la génération: {str(e)}"
    
    def _parse_response(self, response: str) -> Dict[str, str]:
        """Parse la réponse en sections structurées"""
        
        sections = {
            "immediate_actions": "",
            "patches": "",
            "workarounds": "",
            "verification": "",
            "full_response": response
        }
        
        # Extraire les sections
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line_lower = line.lower()
            
            if "actions immédiates" in line_lower or "## 1." in line:
                current_section = "immediate_actions"
                continue
            elif "correctifs" in line_lower or "patches" in line_lower or "## 2." in line:
                current_section = "patches"
                continue
            elif "contournement" in line_lower or "workaround" in line_lower or "## 3." in line:
                current_section = "workarounds"
                continue
            elif "vérification" in line_lower or "## 4." in line:
                current_section = "verification"
                continue
            
            if current_section and line.strip():
                sections[current_section] += line + "\n"
        
        # Nettoyer les sections
        for key in sections:
            if key != "full_response":
                sections[key] = sections[key].strip()
        
        return sections
    
    def get_model_info(self) -> Dict[str, any]:
        """Retourne les informations sur le modèle chargé"""
        return {
            "model_name": self.model_name,
            "loaded": self.loaded,
            "device": str(self.model.device) if self.model else None,
            "dtype": str(self.model.dtype) if self.model else None
        }


# Instance globale du service (lazy loading)
_ai_service_instance = None


def get_ai_service() -> AIRemediationService:
    """Retourne l'instance du service IA (singleton)"""
    global _ai_service_instance
    
    if _ai_service_instance is None:
        _ai_service_instance = AIRemediationService()
        # Le modèle sera chargé au premier appel de generate_remediation
    
    return _ai_service_instance
