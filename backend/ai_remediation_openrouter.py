"""
Service IA pour la remédiation automatique des CVEs
Utilise OpenRouter API pour accéder à GPT-4, Claude, et autres modèles
"""

import requests
import json
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class OpenRouterRemediationService:
    """Service de remédiation IA utilisant OpenRouter"""
    
    def __init__(self, api_key: str, model: str = "anthropic/claude-3.5-sonnet"):
        """
        Initialise le service OpenRouter
        
        Args:
            api_key: Clé API OpenRouter
            model: Modèle à utiliser. Options populaires:
                   - anthropic/claude-3.5-sonnet (recommandé, excellent qualité/prix)
                   - openai/gpt-4-turbo
                   - openai/gpt-4o
                   - anthropic/claude-3-opus (le plus puissant)
                   - google/gemini-pro
        """
        self.api_key = api_key
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.loaded = True  # API-based, toujours prêt
        
        logger.info(f"✓ OpenRouter service initialized with model: {model}")
    
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
            cve_id: Identifiant du CVE
            description: Description de la vulnérabilité
            severity: Niveau de sévérité
            cvss_score: Score CVSS
            affected_products: Produits affectés
            
        Returns:
            Dict avec sections de remédiation structurées
        """
        try:
            # Construire le prompt
            prompt = self._build_prompt(
                cve_id, description, severity, cvss_score, affected_products
            )
            
            # Appeler OpenRouter API avec moins de tokens
            response_text = self._call_openrouter(prompt, max_tokens=600)
            
            # Parser la réponse
            parsed = self._parse_response(response_text)
            
            # Vérifier que le parsing a réussi
            if parsed["immediate_actions"] and parsed["patches"]:
                return parsed
            else:
                logger.warning(f"⚠️ Parsing incomplet pour {cve_id}, utilisation du fallback amélioré")
                return self._get_enhanced_fallback(cve_id, description, severity, cvss_score, affected_products)
            
        except Exception as e:
            logger.error(f"❌ Error generating remediation for {cve_id}: {e}")
            return self._get_enhanced_fallback(cve_id, description, severity, cvss_score, affected_products)
    
    def _build_prompt(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: Optional[str]
    ) -> str:
        """Construit un prompt optimisé pour la remédiation"""
        
        products_info = f"\nProduits affectés: {affected_products}" if affected_products else ""
        
        prompt = f"""Tu es un expert en cybersécurité spécialisé dans la remédiation de vulnérabilités critiques.

Analyse cette vulnérabilité et fournis un plan de remédiation CONCRET et ACTIONNABLE:

**CVE:** {cve_id}
**Sévérité:** {severity} (Score CVSS: {cvss_score}/10){products_info}
**Description:** {description}

**IMPORTANT:** Fournis une réponse structurée en français avec EXACTEMENT ces 2 sections:

## ACTIONS IMMEDIATES
Liste 4-6 actions prioritaires et CONCRETES à effectuer immédiatement.
Chaque action doit être technique, spécifique et directement applicable.

## CORRECTIFS ET PATCHES
Liste 4-6 recommandations PRECISES sur les patches à appliquer et comment les déployer.
Inclus les commandes ou procédures spécifiques quand possible.

**REGLES DE SECURITE CRITIQUES:**
- JAMAIS recommander de désactiver SSL/TLS ou utiliser HTTP au lieu de HTTPS
- JAMAIS suggérer de désactiver l'authentification ou les contrôles de sécurité
- JAMAIS proposer de solutions qui augmentent la surface d'attaque
- Toujours privilégier les correctifs officiels des éditeurs
- Si pas de patch disponible, proposer des workarounds temporaires SECURISES

Sois précis, technique et actionnable. Fournis des commandes et procédures concrètes."""

        return prompt
    
    def _call_openrouter(self, prompt: str, max_tokens: int = 800) -> str:
        """Appelle l'API OpenRouter"""
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://ctba-platform.com",
            "X-Title": "CTBA Security Platform"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Tu es un expert en cybersécurité spécialisé dans la remédiation de vulnérabilités. Tu fournis des recommandations techniques, précises et sécurisées."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": max_tokens,
            "temperature": 0.7,
            "top_p": 0.9
        }
        
        try:
            logger.info(f"📡 Calling OpenRouter API with model: {self.model}")
            
            response = requests.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=60
            )
            
            # Log du code de statut
            logger.info(f"📊 OpenRouter API response status: {response.status_code}")
            
            response.raise_for_status()
            
            result = response.json()
            
            # Extraire la réponse
            if 'choices' in result and len(result['choices']) > 0:
                response_text = result['choices'][0]['message']['content']
                logger.info(f"✅ OpenRouter API call successful ({len(response_text)} chars)")
                return response_text
            else:
                logger.error(f"❌ Invalid response format: {result}")
                raise Exception("Invalid response format from OpenRouter")
                
        except requests.exceptions.Timeout:
            logger.error("⏱️ OpenRouter API timeout (60s)")
            raise Exception("API timeout - veuillez réessayer dans quelques instants")
        except requests.exceptions.HTTPError as e:
            logger.error(f"❌ OpenRouter HTTP error {response.status_code}: {response.text[:200]}")
            raise Exception(f"Erreur HTTP {response.status_code}: {str(e)}")
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ OpenRouter API network error: {e}")
            raise Exception(f"Erreur réseau: {str(e)}")
        except Exception as e:
            logger.error(f"❌ OpenRouter unexpected error: {e}")
            raise Exception(f"Erreur inattendue: {str(e)}")
    
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
                # Ne pas ajouter les lignes de titre (##)
                if not line.strip().startswith('##'):
                    sections[current_section] += line + "\n"
        
        # Nettoyer les sections
        for key in ["immediate_actions", "patches"]:
            sections[key] = sections[key].strip()
        
        # Validation: vérifier que les sections ne sont pas vides
        if not sections["immediate_actions"] or not sections["patches"]:
            logger.warning("⚠️ Sections incomplètes détectées")
        
        return sections
    
    def _get_enhanced_fallback(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: Optional[str] = None
    ) -> Dict[str, str]:
        """Génère une réponse de secours améliorée et contextualisée"""
        
        products_text = affected_products if affected_products else "systèmes affectés"
        
        # Actions immédiates contextualisées selon la sévérité
        if severity in ["CRITICAL", "HIGH"]:
            immediate = f"""1. **Identifier urgemment** tous les systèmes utilisant {products_text}
   ```bash
   # Scan des systèmes affectés
   nmap -p- --open <network_range> | grep -i "{products_text[:20]}"
   ```

2. **Isoler immédiatement** les systèmes critiques exposés (CVSS: {cvss_score}/10)
   ```bash
   # Bloquer l'accès réseau temporairement
   iptables -A INPUT -p tcp --dport <service_port> -j DROP
   ```

3. **Activer la surveillance renforcée** des tentatives d'exploitation
   ```bash
   # Monitoring en temps réel
   tail -f /var/log/syslog | grep -i "error\\|attack\\|exploit"
   ```

4. **Consulter** les bulletins de sécurité officiels pour {cve_id}
   - CVE.org: https://cve.org/CVERecord?id={cve_id}
   - NVD: https://nvd.nist.gov/vuln/detail/{cve_id}

5. **Préparer un plan d'urgence** de déploiement des correctifs"""
        else:
            immediate = f"""1. **Inventorier** tous les systèmes utilisant {products_text}
   ```bash
   # Liste des systèmes concernés
   dpkg -l | grep -i "{products_text[:20]}" || rpm -qa | grep -i "{products_text[:20]}"
   ```

2. **Évaluer l'exposition** réelle au risque (CVSS: {cvss_score}/10)

3. **Planifier** les actions de remédiation selon priorité métier

4. **Consulter** la documentation officielle du CVE {cve_id}

5. **Surveiller** les annonces de correctifs des éditeurs"""
        
        # Correctifs et patches
        patches = f"""1. **Vérifier la disponibilité** des patches officiels pour {cve_id}
   ```bash
   # Mise à jour du catalogue de sécurité
   apt update && apt list --upgradable 2>/dev/null | grep -i security
   # ou
   yum check-update --security
   ```

2. **Tester les correctifs** en environnement de pré-production
   ```bash
   # Créer un snapshot avant patch
   lvcreate -L 10G -s -n backup_snap /dev/vg0/root
   ```

3. **Planifier le déploiement** pendant une fenêtre de maintenance
   - Préparer un plan de rollback
   - Notifier les équipes concernées
   - Documenter les changements

4. **Appliquer les correctifs** selon les recommandations éditeur
   ```bash
   # Installation des mises à jour de sécurité
   apt upgrade --only-upgrade <package_name>
   # ou
   yum update <package_name>
   ```

5. **Vérifier l'efficacité** après déploiement
   ```bash
   # Test de vulnérabilité post-patch
   nmap --script vuln <target_ip>
   ```

6. **Documenter** toutes les actions dans le système de gestion des changements

⚠️ **Note**: Ce plan est générique. Consultez impérativement les bulletins de sécurité officiels pour {cve_id} et les recommandations spécifiques de l'éditeur."""
        
        full_response = f"""## ACTIONS IMMEDIATES

{immediate}

## CORRECTIFS ET PATCHES

{patches}

---
**CVE**: {cve_id}
**Sévérité**: {severity} (Score CVSS: {cvss_score}/10)
**Description**: {description[:200]}...

Cette réponse a été générée automatiquement en mode fallback. Pour des recommandations plus spécifiques, consultez les ressources officielles."""
        
        return {
            "immediate_actions": immediate,
            "patches": patches,
            "full_response": full_response
        }
    
    def get_model_info(self) -> Dict[str, any]:
        """Retourne les informations sur le modèle"""
        return {
            "provider": "OpenRouter",
            "model": self.model,
            "loaded": self.loaded,
            "api_available": True
        }


# Instance globale (sera initialisée avec la clé API)
_openrouter_service_instance = None


def get_openrouter_service(api_key: str = None, model: str = "anthropic/claude-3.5-sonnet") -> OpenRouterRemediationService:
    """
    Retourne l'instance du service OpenRouter (singleton)
    
    Args:
        api_key: Clé API OpenRouter (requis au premier appel)
        model: Modèle à utiliser (optionnel)
    """
    global _openrouter_service_instance
    
    if _openrouter_service_instance is None:
        if not api_key:
            raise ValueError("API key required for first initialization")
        _openrouter_service_instance = OpenRouterRemediationService(api_key, model)
    
    return _openrouter_service_instance
