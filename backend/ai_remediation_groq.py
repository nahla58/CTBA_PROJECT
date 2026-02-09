"""
Service IA pour la remédiation automatique des CVEs
Utilise Groq API (ultra-rapide, gratuit) - Mixtral-8x7B-Instruct
"""

import requests
import json
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class GroqRemediationService:
    """Service de remédiation IA utilisant Groq (gratuit, très rapide)"""
    
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        """
        Initialise le service Groq
        
        Args:
            api_key: Clé API Groq (gratuite sur https://console.groq.com)
            model: Modèle à utiliser. Options:
                   - llama-3.3-70b-versatile (recommandé, puissant)
                   - llama-3.1-8b-instant (plus léger, ultra-rapide)
                   - qwen/qwen3-32b (alternatif)
        """
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.loaded = True
        
        logger.info(f"✓ Groq service initialized with model: {model}")
    
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
            
            # Appeler Groq API
            response_text = self._call_groq(prompt, max_tokens=1024)
            
            # Parser la réponse
            parsed = self._parse_response(response_text)
            
            # Vérifier que le parsing a réussi
            if parsed["immediate_actions"] and parsed["patches"]:
                logger.info(f"✅ Groq AI remediation generated for {cve_id}")
                return parsed
            else:
                logger.warning(f"⚠️ Parsing incomplet pour {cve_id}, utilisation du fallback")
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
        
        products_info = f"\nAffected Products: {affected_products}" if affected_products else ""
        
        prompt = f"""You are a senior cybersecurity expert specializing in vulnerability remediation.

Analyze this vulnerability and provide a CONCISE, PROFESSIONAL remediation plan:

**CVE:** {cve_id}
**Severity:** {severity} (CVSS Score: {cvss_score}/10){products_info}
**Description:** {description}

**CRITICAL:** Provide a structured response in ENGLISH with EXACTLY these 2 sections:

## IMMEDIATE ACTIONS
List 3-4 HIGH-PRIORITY actions to execute immediately.
Each action must be technical, specific, and directly actionable.

## FIXES AND PATCHES
List 3-4 PRECISE recommendations for patches and deployment procedures.
Include specific commands or procedures when applicable.

**SECURITY RULES:**
- NEVER recommend disabling SSL/TLS or using HTTP instead of HTTPS
- NEVER suggest disabling authentication or security controls
- NEVER propose solutions that increase attack surface
- Always prioritize official vendor patches
- If no patch available, propose SECURE temporary workarounds

Be concise, technical, and actionable. Provide specific commands and procedures."""

        return prompt
    
    def _call_groq(self, prompt: str, max_tokens: int = 1024) -> str:
        """Appelle l'API Groq (ultra-rapide)"""
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity expert specializing in vulnerability remediation. You provide technical, precise, and secure recommendations in a concise professional format."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": max_tokens,
            "temperature": 0.7
        }
        
        try:
            logger.info(f"📡 Calling Groq API with model: {self.model}")
            
            response = requests.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=30  # Groq est ultra-rapide, 30s suffit
            )
            
            logger.info(f"📊 Groq API response status: {response.status_code}")
            
            # Si erreur, afficher les détails AVANT raise_for_status
            if response.status_code != 200:
                try:
                    error_json = response.json()
                    logger.error(f"❌ Groq error details: {json.dumps(error_json, indent=2)}")
                except:
                    logger.error(f"❌ Groq error response: {response.text[:1000]}")
            
            response.raise_for_status()
            
            result = response.json()
            
            # Extraire la réponse
            if 'choices' in result and len(result['choices']) > 0:
                response_text = result['choices'][0]['message']['content']
                logger.info(f"✅ Groq API call successful ({len(response_text)} chars)")
                return response_text
            else:
                logger.error(f"❌ Invalid response format: {result}")
                raise Exception("Invalid response format from Groq")
                
        except requests.exceptions.Timeout:
            logger.error("⏱️ Groq API timeout (30s)")
            raise Exception("API timeout - veuillez réessayer")
        except requests.exceptions.HTTPError as e:
            error_detail = response.text[:500] if response else str(e)
            logger.error(f"❌ Groq HTTP error {response.status_code}: {error_detail}")
            
            if response.status_code == 401:
                raise Exception("Clé API Groq invalide - vérifiez votre configuration")
            elif response.status_code == 429:
                raise Exception("Quota Groq dépassé - attendez quelques minutes")
            else:
                raise Exception(f"Erreur HTTP {response.status_code}: {str(e)}")
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Groq API network error: {e}")
            raise Exception(f"Erreur réseau: {str(e)}")
        except Exception as e:
            logger.error(f"❌ Groq unexpected error: {e}")
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
            
            # Détecter les sections (anglais et français)
            if "immediate action" in line_lower or "actions immediates" in line_lower or "actions immédiates" in line_lower:
                current_section = "immediate_actions"
                continue
            elif "fixes" in line_lower or "correctifs" in line_lower or "patches" in line_lower:
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

⚠️ **Note**: Ce plan est générique. Consultez impérativement les bulletins de sécurité officiels pour {cve_id}."""
        
        full_response = f"""## ACTIONS IMMEDIATES

{immediate}

## CORRECTIFS ET PATCHES

{patches}

---
**CVE**: {cve_id}
**Sévérité**: {severity} (Score CVSS: {cvss_score}/10)
**Description**: {description[:200]}...

⚠️ Réponse générée en mode fallback. Consultez les ressources officielles."""
        
        return {
            "immediate_actions": immediate,
            "patches": patches,
            "full_response": full_response
        }
    
    def get_model_info(self) -> Dict[str, any]:
        """Retourne les informations sur le modèle"""
        return {
            "provider": "Groq",
            "model": self.model,
            "loaded": self.loaded,
            "api_available": True
        }


# Instance globale (singleton)
_groq_service_instance = None


def get_groq_service(api_key: str = None, model: str = "llama-3.3-70b-versatile") -> GroqRemediationService:
    """
    Retourne l'instance du service Groq (singleton)
    
    Args:
        api_key: Clé API Groq (gratuite sur https://console.groq.com)
        model: Modèle à utiliser (llama-3.3-70b-versatile par défaut)
    """
    global _groq_service_instance
    
    if _groq_service_instance is None:
        if not api_key:
            raise ValueError("API key required for first initialization")
        _groq_service_instance = GroqRemediationService(api_key, model)
    
    return _groq_service_instance
