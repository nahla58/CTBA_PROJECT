"""
Service IA pour la remédiation automatique des CVEs
Utilise Hugging Face Inference API (GRATUIT avec limites raisonnables)
"""

import requests
import json
import logging
from typing import Dict, Optional
import time

logger = logging.getLogger(__name__)


class HuggingFaceRemediationService:
    """Service de remédiation IA utilisant Hugging Face Inference API"""
    
    # Modèles recommandés (tous gratuits via Inference API)
    RECOMMENDED_MODELS = {
        "mistral-7b": "mistralai/Mistral-7B-Instruct-v0.2",  # ⭐ Excellent pour le français
        "mixtral-8x7b": "mistralai/Mixtral-8x7B-Instruct-v0.1",  # 🚀 Très puissant
        "zephyr-7b": "HuggingFaceH4/zephyr-7b-beta",  # ⚡ Rapide et bon
        "llama2-7b": "meta-llama/Llama-2-7b-chat-hf",  # 🦙 Classique
        "openchat": "openchat/openchat-3.5-0106"  # 💬 Bon pour le dialogue
    }
    
    def __init__(self, api_key: str, model: str = "mistral-7b"):
        """
        Initialise le service Hugging Face
        
        Args:
            api_key: Clé API Hugging Face (gratuite sur https://huggingface.co/settings/tokens)
            model: Modèle à utiliser (voir RECOMMENDED_MODELS)
        """
        self.api_key = api_key
        
        # Résoudre le nom du modèle
        if model in self.RECOMMENDED_MODELS:
            self.model = self.RECOMMENDED_MODELS[model]
            self.model_short = model
        else:
            self.model = model
            self.model_short = model.split('/')[-1]
        
        # 🔧 Nouvelle API Hugging Face compatible OpenAI
        self.base_url = "https://api-inference.huggingface.co/models"
        self.chat_url = f"{self.base_url}/{self.model}/v1/chat/completions"
        self.loaded = True
        
        logger.info(f"✓ Hugging Face service initialized with model: {self.model}")
    
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
        
        Returns:
            Dict avec sections de remédiation structurées
        """
        try:
            # Construire le prompt
            prompt = self._build_prompt(
                cve_id, description, severity, cvss_score, affected_products
            )
            
            # Appeler Hugging Face Inference API
            response_text = self._call_huggingface_api(prompt)
            
            # Parser la réponse
            parsed = self._parse_response(response_text)
            
            # Vérifier que le parsing a réussi
            if parsed["immediate_actions"] and parsed["patches"]:
                logger.info(f"✅ Remediation générée avec succès pour {cve_id}")
                return parsed
            else:
                logger.warning(f"⚠️ Parsing incomplet pour {cve_id}, utilisation du fallback")
                return self._get_enhanced_fallback(cve_id, description, severity, cvss_score, affected_products)
            
        except Exception as e:
            logger.error(f"❌ Erreur génération remediation pour {cve_id}: {e}")
            return self._get_enhanced_fallback(cve_id, description, severity, cvss_score, affected_products)
    
    def _build_prompt(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: Optional[str]
    ) -> str:
        """Construit un prompt optimisé pour Hugging Face"""
        
        products_info = f"\nProduits affectés: {affected_products}" if affected_products else ""
        
        # Format pour modèles Instruct (Mistral, Mixtral, etc.)
        prompt = f"""<s>[INST] Tu es un expert en cybersécurité spécialisé dans la remédiation de vulnérabilités.

Analyse cette vulnérabilité et fournis un plan de remédiation CONCRET:

**CVE:** {cve_id}
**Sévérité:** {severity} (Score CVSS: {cvss_score}/10){products_info}
**Description:** {description[:300]}

Fournis une réponse structurée en français avec EXACTEMENT ces 2 sections:

## ACTIONS IMMEDIATES
Liste 4-5 actions prioritaires et CONCRETES à effectuer immédiatement.

## CORRECTIFS ET PATCHES
Liste 4-5 recommandations PRECISES sur les patches à appliquer.

Sois CONCIS, TECHNIQUE et ACTIONNABLE. [/INST]

"""
        return prompt
    
    def _call_huggingface_api(self, prompt: str, max_retries: int = 3) -> str:
        """Appelle l'Inference API de Hugging Face avec retry logic"""
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Format OpenAI-compatible pour Hugging Face
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 600,
            "temperature": 0.7,
            "top_p": 0.9
        }
        
        for attempt in range(max_retries):
            try:
                logger.info(f"📡 Appel Hugging Face API (tentative {attempt + 1}/{max_retries})...")
                
                response = requests.post(
                    self.chat_url,
                    headers=headers,
                    json=payload,
                    timeout=120
                )
                
                logger.info(f"📊 Status: {response.status_code}")
                
                # Gérer les erreurs spécifiques
                if response.status_code == 503:
                    # Modèle en cours de chargement
                    data = response.json()
                    estimated_time = data.get("estimated_time", 20)
                    logger.info(f"⏳ Modèle en cours de chargement, attente de {estimated_time}s...")
                    time.sleep(min(estimated_time + 5, 30))  # Max 30s
                    continue
                
                response.raise_for_status()
                
                result = response.json()
                
                # Extraire la réponse
                # Format OpenAI-compatible
                if 'choices' in result and len(result['choices']) > 0:
                    response_text = result['choices'][0]['message']['content']
                    logger.info(f"✅ Hugging Face API call successful ({len(response_text)} chars)")
                    return response_text
                else:
                    logger.error(f"❌ Format de réponse invalide: {result}")
                    raise Exception("Format de réponse invalide")
                    
            except requests.exceptions.Timeout:
                logger.error(f"⏱️ Timeout (tentative {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                raise Exception("Timeout après plusieurs tentatives")
                
            except requests.exceptions.HTTPError as e:
                logger.error(f"❌ Erreur HTTP {response.status_code}: {response.text[:200]}")
                
                # Si quota dépassé, lever une exception spécifique
                if response.status_code == 429:
                    raise Exception("Quota Hugging Face dépassé. Réessayez dans quelques minutes.")
                
                if attempt < max_retries - 1 and response.status_code == 503:
                    time.sleep(10)
                    continue
                    
                raise Exception(f"Erreur HTTP {response.status_code}: {str(e)}")
                
            except Exception as e:
                logger.error(f"❌ Erreur inattendue: {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                raise
        
        raise Exception("Échec après plusieurs tentatives")
    
    def _parse_response(self, response: str) -> Dict[str, str]:
        """Parse la réponse en sections structurées"""
        
        sections = {
            "immediate_actions": "",
            "patches": "",
            "full_response": response
        }
        
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line_lower = line.lower()
            
            # Détecter les sections
            if "actions immediates" in line_lower or "actions immédiates" in line_lower:
                current_section = "immediate_actions"
                continue
            elif "correctifs" in line_lower or "patches" in line_lower:
                current_section = "patches"
                continue
            
            # Ajouter le contenu à la section active
            if current_section and line.strip():
                if not line.strip().startswith('##'):
                    sections[current_section] += line + "\n"
        
        # Nettoyer les sections
        for key in ["immediate_actions", "patches"]:
            sections[key] = sections[key].strip()
        
        return sections
    
    def _get_enhanced_fallback(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: Optional[str] = None
    ) -> Dict[str, str]:
        """Génère une réponse de secours contextualisée"""
        
        products_text = affected_products if affected_products else "systèmes affectés"
        
        # Actions immédiates selon sévérité
        if severity in ["CRITICAL", "HIGH"]:
            immediate = f"""1. **Identifier urgemment** tous les systèmes utilisant {products_text}
   ```bash
   nmap -sV <network_range> | grep -i "{products_text[:20]}"
   ```

2. **Isoler immédiatement** les systèmes critiques (CVSS: {cvss_score}/10)
   ```bash
   iptables -A INPUT -p tcp --dport <service_port> -j DROP
   ```

3. **Activer surveillance renforcée** des tentatives d'exploitation
   ```bash
   tail -f /var/log/syslog | grep -iE "error|attack|exploit"
   ```

4. **Consulter** les bulletins officiels:
   - CVE.org: https://cve.org/CVERecord?id={cve_id}
   - NVD: https://nvd.nist.gov/vuln/detail/{cve_id}

5. **Préparer plan d'urgence** de déploiement des correctifs"""
        else:
            immediate = f"""1. **Inventorier** tous les systèmes utilisant {products_text}
   ```bash
   dpkg -l | grep -i "{products_text[:20]}"
   ```

2. **Évaluer l'exposition** réelle au risque (CVSS: {cvss_score}/10)

3. **Planifier** les actions selon priorité métier

4. **Consulter documentation** officielle du CVE {cve_id}

5. **Surveiller** les annonces de correctifs"""
        
        # Correctifs
        patches = f"""1. **Vérifier disponibilité** des patches officiels
   ```bash
   apt update && apt list --upgradable | grep -i security
   ```

2. **Tester en pré-production**
   ```bash
   lvcreate -L 10G -s -n backup_snap /dev/vg0/root
   ```

3. **Planifier déploiement** avec fenêtre de maintenance

4. **Appliquer correctifs** selon recommandations éditeur
   ```bash
   apt upgrade --only-upgrade <package_name>
   ```

5. **Vérifier efficacité** post-déploiement
   ```bash
   nmap --script vuln <target_ip>
   ```

⚠️ **Note**: Consultez les bulletins officiels pour {cve_id}."""
        
        full_response = f"""## ACTIONS IMMEDIATES

{immediate}

## CORRECTIFS ET PATCHES

{patches}

---
**CVE**: {cve_id} | **Sévérité**: {severity} ({cvss_score}/10)
**Description**: {description[:150]}...

⚠️ Réponse générée en mode fallback. Consultez les ressources officielles."""
        
        return {
            "immediate_actions": immediate,
            "patches": patches,
            "full_response": full_response
        }
    
    def get_model_info(self) -> Dict[str, any]:
        """Retourne les informations sur le modèle"""
        return {
            "provider": "Hugging Face",
            "model": self.model,
            "model_short": self.model_short,
            "loaded": self.loaded,
            "api_available": True,
            "cost": "FREE (with rate limits)"
        }


# Instance globale
_huggingface_service_instance = None


def get_huggingface_service(api_key: str = None, model: str = "mistral-7b") -> HuggingFaceRemediationService:
    """
    Retourne l'instance du service Hugging Face (singleton)
    
    Args:
        api_key: Clé API Hugging Face (gratuite sur https://huggingface.co/settings/tokens)
        model: Modèle à utiliser (défaut: mistral-7b)
    """
    global _huggingface_service_instance
    
    if _huggingface_service_instance is None:
        if not api_key:
            raise ValueError("API key required for first initialization. Get it free at https://huggingface.co/settings/tokens")
        _huggingface_service_instance = HuggingFaceRemediationService(api_key, model)
    
    return _huggingface_service_instance
