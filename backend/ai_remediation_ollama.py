"""
Service IA avec Ollama + Llama 3
Utilise l'API REST locale d'Ollama
"""

import requests
from typing import Dict
import logging
import json

logger = logging.getLogger(__name__)


class OllamaRemediationService:
    """Service de remédiation utilisant Ollama + Llama 3"""
    
    def __init__(self, model_name: str = "qwen2.5:3b"):
        """
        Initialise avec Ollama
        
        Models recommandés:
        - qwen2.5:3b: 3B paramètres, RAPIDE et structuré (~2GB) ✅ RECOMMANDÉ
        - llama3.1:8b: 8B paramètres, excellente qualité mais lent (~5GB)
        - qwen2.5:7b: 7B paramètres, très bon compromis (~4GB)
        
        Note: qwen2.5:3b sera téléchargé automatiquement (~2GB) si non présent
        """
        self.model_name = model_name
        self.base_url = "http://localhost:11434"
        self.loaded = False
        
    def check_ollama_running(self) -> bool:
        """Vérifie si Ollama est en cours d'exécution"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def check_model_available(self) -> bool:
        """Vérifie si le modèle est téléchargé"""
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                models = response.json().get('models', [])
                return any(self.model_name in model['name'] for model in models)
            return False
        except:
            return False
    
    def load_model(self):
        """Vérifie que Ollama et le modèle sont prêts"""
        if self.loaded:
            return
            
        # Vérifier Ollama
        if not self.check_ollama_running():
            raise Exception(
                "❌ Ollama n'est pas en cours d'exécution!\n"
                "Installez Ollama: https://ollama.ai\n"
                "Puis lancez: ollama serve"
            )
        
        logger.info("✓ Ollama détecté")
        
        # Vérifier modèle
        if not self.check_model_available():
            logger.warning(f"⚠️ Modèle {self.model_name} non trouvé")
            logger.info(f"Téléchargement automatique de {self.model_name}...")
            
            # Télécharger le modèle
            try:
                response = requests.post(
                    f"{self.base_url}/api/pull",
                    json={"name": self.model_name},
                    stream=True,
                    timeout=600
                )
                
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line)
                        if 'status' in data:
                            logger.info(f"  {data['status']}")
                
                logger.info(f"✓ Modèle {self.model_name} téléchargé!")
                
            except Exception as e:
                raise Exception(f"❌ Erreur téléchargement: {e}")
        
        logger.info(f"✓ Modèle {self.model_name} prêt")
        self.loaded = True
    
    def generate_remediation(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: str = None
    ) -> Dict[str, str]:
        """Génère des recommandations avec Ollama"""
        
        if not self.loaded:
            self.load_model()
        
        # Construire le prompt
        prompt = self._build_prompt(cve_id, description, severity, cvss_score, affected_products)
        
        try:
            logger.info(f"🤖 Génération avec Ollama {self.model_name} pour {cve_id}...")
            
            # Appel API Ollama avec paramètres optimisés
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.7,  # Équilibré pour qwen2.5:3b
                        "top_p": 0.9,  # Permissif pour générer plus de contenu
                        "top_k": 50,
                        "repeat_penalty": 1.15,
                        "num_predict": 700,  # Optimisé pour qwen2.5:3b (plus petit)
                        "stop": ["</s>", "USER:", "HUMAN:"]
                    }
                },
                timeout=120  # 2 minutes suffisantes pour qwen2.5:3b (plus rapide)
            )
            
            if response.status_code != 200:
                raise Exception(f"Ollama error: {response.status_code}")
            
            result = response.json()
            generated_text = result.get('response', '')
            
            # ✅ VALIDATION: Détecter recommandations dangereuses
            is_safe, warning = self._validate_security(generated_text)
            if not is_safe:
                logger.warning(f"⚠️ Recommandation dangereuse détectée: {warning}")
                logger.warning(f"Utilisation du template de secours pour {cve_id}")
                return self._fallback_template(description, severity)
            
            # Parser la réponse
            parsed = self._parse_response(generated_text, cve_id, severity, cvss_score)
            
            # ✅ VALIDATION: Vérifier complétude (2 sections critiques uniquement)
            critical_sections = ['immediate_actions', 'patches']
            missing_sections = [k for k in critical_sections 
                               if not parsed.get(k) or len(parsed[k].strip()) < 30]
            
            if len(missing_sections) >= 1:  # Au moins 1 section critique manquante
                logger.warning(f"⚠️ Section(s) critique(s) manquante(s): {missing_sections}")
                logger.info("Utilisation du template de secours")
                return self._fallback_template(description, severity)
            
            return parsed
            
        except Exception as e:
            logger.error(f"❌ Erreur génération: {e}")
            return self._fallback_template(description, severity)
    
    def _validate_security(self, text: str) -> tuple[bool, str]:
        """
        Valide que le texte généré ne contient pas de recommandations dangereuses
        Returns: (is_safe, warning_message)
        """
        text_lower = text.lower()
        
        # ❌ Patterns dangereux à bloquer
        DANGEROUS_PATTERNS = [
            ("use http://", "Recommande HTTP au lieu de HTTPS"),
            ("proxy_pass http://", "Désactive TLS dans proxy NGINX"),
            ("disable tls", "Recommande désactivation TLS"),
            ("disable ssl", "Recommande désactivation SSL"),
            ("turn off encryption", "Recommande désactivation chiffrement"),
            ("remove https", "Recommande suppression HTTPS"),
            ("disable certificate validation", "Désactive validation certificats"),
            ("skip verification", "Recommande ignorer vérification sécurité"),
            ("set verify=false", "Désactive vérification SSL/TLS"),
            ("bypass authentication", "Recommande contournement authentification"),
            ("disable firewall", "Recommande désactivation firewall"),
            ("allow all traffic", "Recommande autoriser tout le trafic"),
        ]
        
        for pattern, reason in DANGEROUS_PATTERNS:
            if pattern in text_lower:
                return False, reason
        
        # ⚠️ Vérifier présence de bons mots-clés sécurité
        SECURITY_KEYWORDS = ["patch", "update", "upgrade", "security", "verify", "monitor"]
        has_security_context = any(keyword in text_lower for keyword in SECURITY_KEYWORDS)
        
        if not has_security_context:
            return False, "Manque de contexte sécurité dans la réponse"
        
        return True, "OK"
    
    def _build_prompt(self, cve_id: str, description: str, severity: str, cvss_score: float, affected_products: str) -> str:
        """Construit un prompt structuré pour Llama 3"""
        
        products_info = f" in {affected_products}" if affected_products else ""
        
        # Extraire type de vulnérabilité pour contexte
        vuln_type = "security vulnerability"
        desc_lower = description.lower()
        if "command injection" in desc_lower or "os command" in desc_lower:
            vuln_type = "command injection vulnerability"
        elif "mitm" in desc_lower or "man-in-the-middle" in desc_lower:
            vuln_type = "MITM attack vulnerability"
        elif "certificate" in desc_lower and "validation" in desc_lower:
            vuln_type = "certificate validation bypass"
        elif "buffer overflow" in desc_lower:
            vuln_type = "buffer overflow"
        elif "denial of service" in desc_lower or "dos" in desc_lower:
            vuln_type = "denial of service"
        elif "sql injection" in desc_lower:
            vuln_type = "SQL injection vulnerability"
        elif "xss" in desc_lower or "cross-site scripting" in desc_lower:
            vuln_type = "cross-site scripting (XSS)"
        
        # Extraire produit et version affectée de la description
        product_version = ""
        if "affects" in desc_lower or "this issue affects" in desc_lower:
            parts = description.split("This issue affects")
            if len(parts) > 1:
                product_version = f"\nAffected: {parts[1].strip()}"
        
        # Utiliser toute la description (pas seulement 250 caractères)
        full_description = description.strip()
        
        prompt = f"""You are a senior cybersecurity expert providing detailed vulnerability remediation guidance.

VULNERABILITY DETAILS:
CVE ID: {cve_id}
Severity: {severity} (CVSS {cvss_score}/10) - {'HIGH PRIORITY' if cvss_score >= 7.0 else 'MODERATE'}
Type: {vuln_type}{products_info}
Description: {full_description}

TASK: Provide comprehensive, actionable remediation in 2 sections. Be specific and detailed.

SECTION 1 - IMMEDIATE ACTIONS (Priority Response Steps):
List 6-8 concrete actions to take immediately:
1. System Identification: Which exact systems/versions are affected?
2. Risk Assessment: What is the immediate threat level?
3. Containment: Should systems be isolated or access restricted?
4. Monitoring: What additional logging/monitoring to enable?
5. Detection: How to check for active exploitation or compromise?
6. Temporary Measures: Any immediate workarounds before patching?
7. Communication: Who to notify (security team, CISO, users)?
8. Documentation: What to log for incident response?

SECTION 2 - FIXES AND PATCHES (Permanent Resolution):
Provide 6-8 detailed steps for permanent remediation:
1. Patch Availability: Specify exact fixed versions (e.g., "Upgrade from 5.x to 5.13.3+")
2. Vendor Advisory: Official security bulletin or vendor link
3. Backup Procedure: What to backup before patching
4. Upgrade Steps: Step-by-step upgrade/patch procedure
5. Configuration: Any config changes needed after patch
6. Verification: Commands to verify patch applied (version check, test)
7. Testing: How to test that vulnerability is fixed
8. Rollback Plan: What if patch causes issues

SECURITY CONSTRAINTS:
- NEVER disable security features (TLS, HTTPS, encryption, firewalls)
- NEVER recommend HTTP instead of HTTPS or insecure protocols
- ALWAYS prioritize official patches over workarounds
- Include specific commands, version numbers, and vendor links when available

FORMAT: Use bullet points with clear, technical language. Each section must have 6-8 detailed points."""
        
        return prompt
    
    def _parse_response(self, generated_text: str, cve_id: str, severity: str, cvss_score: float) -> Dict[str, str]:
        """Parse la réponse de Llama 3"""
        
        sections = {
            "immediate_actions": "",
            "patches": "",
            "workarounds": "",  # Non utilisé (simplification à 2 sections)
            "verification": "",  # Non utilisé (simplification à 2 sections)
            "full_response": generated_text
        }
        
        # Parser par sections
        lines = generated_text.split('\n')
        current_section = None
        current_content = []
        
        for line in lines:
            line_clean = line.strip()
            line_lower = line_clean.lower()
            
            # Détecter sections
            if 'immediate action' in line_lower or line_clean.startswith('1.'):
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = "immediate_actions"
                current_content = []
                if not line_clean.startswith('1.') and 'immediate' in line_lower:
                    continue  # Skip header
            elif 'patch' in line_lower or line_clean.startswith('2.'):
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = "patches"
                current_content = []
                if not line_clean.startswith('2.') and 'patch' in line_lower:
                    continue
            elif 'workaround' in line_lower or line_clean.startswith('3.'):
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = "workarounds"
                current_content = []
                if not line_clean.startswith('3.') and 'workaround' in line_lower:
                    continue
            elif 'verification' in line_lower or 'verify' in line_lower or line_clean.startswith('4.'):
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = "verification"
                current_content = []
                if not line_clean.startswith('4.') and 'verif' in line_lower:
                    continue
            elif current_section and line_clean:
                current_content.append(line_clean)
        
        # Dernière section
        if current_section and current_content:
            sections[current_section] = '\n'.join(current_content).strip()
        
        # Fallback si parsing échoue (2 sections critiques uniquement)
        if not sections["immediate_actions"]:
            text_lines = [l.strip() for l in generated_text.split('\n') if l.strip()]
            sections["immediate_actions"] = '\n'.join(text_lines[:10])  # Plus de lignes pour Immediate Actions
            sections["patches"] = '\n'.join(text_lines[10:20]) if len(text_lines) > 10 else "Consulter l'éditeur pour patches et mises à jour"
        
        # Sections workarounds/verification laissées vides (simplification à 2 sections)
        sections["workarounds"] = ""
        sections["verification"] = ""
        
        sections["note"] = f"🤖 Généré par Ollama {self.model_name}"
        
        return sections
    
    def _fallback_template(self, description: str, severity: str) -> Dict[str, str]:
        """
        Template de secours intelligent basé sur la description
        Analyse le type de vulnérabilité pour fournir recommandations pertinentes
        """
        desc_lower = description.lower()
        
        # Templates simplifiés à 2 sections
        vuln_templates = {
            "sql injection": {
                "immediate_actions": """Bloquer requetes suspectes via WAF
Auditer logs base de donnees pour tentatives injection
Restreindre permissions comptes DB au minimum necessaire
Isoler applications web affectees si exploitation active
Activer WAF avec regles anti-SQL injection ModSecurity
Filtrer caracteres speciaux SQL""",
                "patches": """Utiliser requetes parametrees PreparedStatements
Mettre a jour ORM framework vers version securisee
Implementer validation stricte des entrees utilisateur
Appliquer patches de securite disponibles
Tester avec SQLMap ou OWASP ZAP apres patch
Verifier impossibilite injection via formulaires"""
            },
            "xss": {
                "immediate_actions": """Activer Content Security Policy CSP strict
Verifier sessions utilisateurs pour activite suspecte
Analyser logs pour tentatives XSS recentes
Nettoyer donnees stockees contenant scripts
Implementer CSP avec regles strictes
Utiliser HTTPOnly et Secure flags sur cookies""",
                "patches": """Encoder toutes sorties HTML htmlspecialchars DOMPurify
Mettre a jour bibliotheques sanitization
Utiliser framework avec protection XSS native
Appliquer patches composants frontend
Scanner avec Burp Suite ou OWASP ZAP
Verifier en-tetes CSP dans reponses HTTP"""
            },
            "remote code execution": {
                "immediate_actions": f"""CRITIQUE Action immediate requise Severite {severity}
Isoler IMMEDIATEMENT systemes affectes du reseau
Bloquer acces externe aux services vulnerables
Activer surveillance comportementale intensive EDR
Verifier compromission processus suspects connexions reseau
Desactiver totalement la fonctionnalite si possible
Isoler service dans conteneur VM avec restrictions""",
                "patches": """Appliquer patch securite en URGENCE ABSOLUE
Mettre a jour vers version non vulnerable
Desactiver fonctions endpoints dangereux
Restreindre execution code dynamique au strict minimum
Test exploitation controle Metasploit en lab
Scanner avec Nessus OpenVAS Qualys"""
            },
            "buffer overflow": {
                "immediate_actions": """Redemarrer services en mode isole restreint
Activer ASLR DEP stack canaries si desactives
Surveiller utilisation memoire et crashes anormaux
Bloquer vecteurs attaque ports formats fichiers
Limiter taille fichiers inputs acceptes
Valider dimensions avant traitement""",
                "patches": """Mettre a jour bibliotheque vers version patchee
Recompiler avec flags fstack-protector-strong
Utiliser fonctions securisees strncpy snprintf
Implementer verifications limites strictes
Fuzzing avec AFL ou libFuzzer apres patch
Scanner memoire avec Valgrind AddressSanitizer"""
            }
        }
        
        # Sélectionner template approprié
        selected_template = None
        for vuln_type, template in vuln_templates.items():
            if vuln_type in desc_lower:
                selected_template = template
                break
        
        # Template générique si type non reconnu
        if not selected_template:
            selected_template = {
                "immediate_actions": f"""Evaluer impact immediat Severite {severity}
Identifier systemes et versions affectes
Isoler systemes critiques si necessaire
Activer surveillance et logging renforces
Informer equipes securite et CISO
Restreindre acces reseau aux systemes affectes""",
                "patches": """Consulter advisory officiel du vendor
Verifier disponibilite patches de securite
Tester patches en environnement staging
Planifier deploiement en production
Documenter tous les changements
Scanner avec outils de securite Nessus Qualys"""
            }
        
        # Ajouter sections vides pour compatibilité frontend
        selected_template["workarounds"] = ""
        selected_template["verification"] = ""
        selected_template["full_response"] = f"Template automatique - {severity}"
        selected_template["note"] = "Template de secours generation IA echouee ou bloquee"
        
        return selected_template
    
    def get_model_info(self) -> Dict:
        """Infos modèle"""
        return {
            "model_name": self.model_name,
            "loaded": self.loaded,
            "framework": "Ollama",
            "backend": "llama.cpp",
            "device": "cpu/gpu (auto)"
        }


# Instance globale
_ollama_service = None


def get_ollama_service() -> OllamaRemediationService:
    """Instance singleton"""
    global _ollama_service
    
    if _ollama_service is None:
        _ollama_service = OllamaRemediationService()
    
    return _ollama_service
