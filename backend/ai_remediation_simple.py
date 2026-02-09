"""
Service IA SIMPLIFIÉ pour remédiation CVE - Version Template
Alternative quand le modèle local est trop lent
"""

from typing import Dict
import logging

logger = logging.getLogger(__name__)


class SimpleAIRemediationService:
    """
    Service de remédiation basé sur templates intelligents
    Alternative légère si modèle LLM trop lourd
    """
    
    def __init__(self):
        self.templates = self._load_templates()
        logger.info("Service IA simplifié initialisé")
    
    def _load_templates(self) -> Dict:
        """Charge les templates de remédiation par type de vulnérabilité"""
        return {
            "SQL Injection": {
                "immediate_actions": """- Désactiver temporairement les fonctionnalités affectées
- Activer le WAF (Web Application Firewall) en mode blocage
- Analyser les logs pour identifier tentatives d'exploitation
- Isoler les systèmes critiques si compromission suspectée""",
                
                "patches": """- Utiliser des requêtes paramétrées (Prepared Statements)
- Implémenter validation stricte des entrées utilisateur
- Appliquer le principe du moindre privilège pour comptes DB
- Mettre à jour framework/ORM vers dernière version sécurisée""",
                
                "workarounds": """- Filtrer les caractères spéciaux SQL: ', ", ;, --, /*, */
- Implémenter validation Whitelist stricte
- Utiliser fonction d'échappement (ex: mysqli_real_escape_string)
- Limiter permissions DB au strict minimum""",
                
                "verification": """- Tester avec OWASP ZAP ou SQLMap
- Vérifier impossibilité injection via formulaires
- Analyser requêtes SQL dans logs applicatifs
- Audit code avec outils SAST (Bandit, SonarQube)"""
            },
            
            "Buffer Overflow": {
                "immediate_actions": """- Redémarrer services affectés en mode isolé
- Activer ASLR et DEP si désactivés
- Surveiller utilisation mémoire anormale
- Bloquer vecteurs d'attaque identifiés (ports, fichiers)""",
                
                "patches": """- Mettre à jour bibliothèque vers version patchée
- Recompiler avec flags de sécurité (-fstack-protector)
- Utiliser fonctions sécurisées (strncpy vs strcpy)
- Implémenter vérifications de limites strictes""",
                
                "workarounds": """- Limiter taille maximale fichiers acceptés
- Valider dimensions/taille avant traitement
- Utiliser sandbox pour traitement fichiers
- Activer mécanismes protection mémoire système""",
                
                "verification": """- Fuzzing avec AFL ou libFuzzer
- Test fichiers malformés de tailles extrêmes
- Vérifier stack canaries activés
- Scanner avec Valgrind pour fuites mémoire"""
            },
            
            "Remote Code Execution": {
                "immediate_actions": """- Isoler IMMÉDIATEMENT systèmes affectés du réseau
- Bloquer accès externe aux services vulnérables
- Activer surveillance comportementale intensive
- Préparer restauration depuis backup vérifié""",
                
                "patches": """- Appliquer patch sécurité en URGENCE
- Mettre à jour vers version non vulnérable
- Désactiver fonctions/endpoints dangereux
- Restreindre exécution code dynamique""",
                
                "workarounds": """- Désactiver totalement fonctionnalité si possible
- Implémenter whitelist stricte commandes autorisées
- Isoler service dans conteneur/VM restreint
- Bloquer exécution scripts non signés""",
                
                "verification": """- Test exploitation avec Metasploit
- Vérifier impossibilité exécution commandes OS
- Scanner avec Nessus/OpenVAS
- Audit permissions exécution fichiers système"""
            },
            
            "Cross-Site Scripting": {
                "immediate_actions": """- Activer Content Security Policy (CSP) strict
- Vérifier sessions utilisateurs pour anomalies
- Analyser logs pour tentatives XSS récentes
- Nettoyer données stockées de scripts injectés""",
                
                "patches": """- Encoder toutes sorties utilisateur (HTML entities)
- Implémenter bibliothèque sanitization (DOMPurify)
- Utiliser framework avec protection XSS native
- Mettre à jour composants frontend""",
                
                "workarounds": """- Activer HTTPOnly et Secure flags sur cookies
- Implémenter validation input/output stricte
- Utiliser templates avec auto-escape
- Filtrer balises HTML/JavaScript dangereuses""",
                
                "verification": """- Test avec payload XSS OWASP
- Scanner avec Burp Suite ou OWASP ZAP
- Vérifier CSP headers correctement configurés
- Test injection dans tous champs input"""
            },
            
            "Default": {
                "immediate_actions": """- Évaluer niveau de risque immédiat (CVSS score)
- Isoler systèmes critiques si sévérité haute
- Activer monitoring renforcé pour détection exploitation
- Informer équipes sécurité et réponse incidents""",
                
                "patches": """- Consulter avis sécurité éditeur (MSRC, RedHat, etc.)
- Appliquer patches disponibles en suivant priorité
- Mettre à jour composants vers versions corrigées
- Documenter changements dans registre patches""",
                
                "workarounds": """- Désactiver fonctionnalités vulnérables non-essentielles
- Implémenter contrôles compensatoires (WAF, IPS)
- Restreindre accès réseau aux services affectés
- Renforcer authentification et autorisation""",
                
                "verification": """- Scanner systèmes avec outils détection vulnérabilités
- Tester exploitation avec environnement isolé
- Vérifier logs pour tentatives exploitation
- Valider efficacité contrôles avec pentest"""
            }
        }
    
    def generate_remediation(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: str = None
    ) -> Dict[str, str]:
        """Génère remédiation basée sur templates intelligents ET contexte"""
        
        # Détecter type de vulnérabilité
        vuln_type = self._detect_vulnerability_type(description)
        
        # Récupérer template de base
        template = self.templates.get(vuln_type, self.templates["Default"])
        
        # NOUVEAU: Personnaliser selon le contexte
        personalized = self._personalize_remediation(
            template, description, severity, cvss_score, vuln_type
        )
        
        # Personnaliser avec contexte CVE
        context_note = self._build_context(cve_id, severity, cvss_score, affected_products)
        
        return {
            "immediate_actions": personalized["immediate_actions"],
            "patches": personalized["patches"],
            "workarounds": personalized["workarounds"],
            "verification": personalized["verification"],
            "full_response": f"{context_note}\n\n" + 
                            f"## ACTIONS IMMÉDIATES\n{personalized['immediate_actions']}\n\n" +
                            f"## CORRECTIFS ET PATCHES\n{personalized['patches']}\n\n" +
                            f"## SOLUTIONS DE CONTOURNEMENT\n{personalized['workarounds']}\n\n" +
                            f"## VÉRIFICATION\n{personalized['verification']}",
            "note": "⚠️ Recommandations personnalisées basées sur l'analyse du CVE."
        }
    
    def _detect_vulnerability_type(self, description: str) -> str:
        """Détecte le type de vulnérabilité depuis la description"""
        description_lower = description.lower()
        
        if any(kw in description_lower for kw in ['sql injection', 'sqli', 'injection sql']):
            return "SQL Injection"
        elif any(kw in description_lower for kw in ['buffer overflow', 'débordement', 'heap overflow']):
            return "Buffer Overflow"
        elif any(kw in description_lower for kw in ['remote code execution', 'rce', 'code arbitraire']):
            return "Remote Code Execution"
        elif any(kw in description_lower for kw in ['xss', 'cross-site scripting', 'injection script']):
            return "Cross-Site Scripting"
        else:
            return "Default"
    
    def _personalize_remediation(self, template: Dict, description: str, severity: str, cvss_score: float, vuln_type: str) -> Dict:
        """Personnalise le template selon le contexte"""
        # Pour Simple AI, on retourne le template tel quel
        # (la personnalisation avancée se fait avec les vrais modèles IA)
        return {
            "immediate_actions": template["immediate_actions"],
            "patches": template["patches"],
            "workarounds": template.get("workarounds", "Consultez la documentation officielle."),
            "verification": template.get("verification", "Vérifiez que les correctifs sont appliqués correctement.")
        }
    
    def _build_context(self, cve_id: str, severity: str, cvss_score: float, affected_products: str) -> str:
        """Construit note contextuelle"""
        context = f"**CVE:** {cve_id} | **Sévérité:** {severity} ({cvss_score}/10)"
        
        if affected_products:
            context += f"\n**Produits affectés:** {affected_products}"
        
        return context
    
    def get_model_info(self) -> Dict:
        """Informations sur le service"""
        return {
            "model_name": "Template-Based Remediation Engine",
            "loaded": True,
            "device": "cpu",
            "type": "rule-based",
            "templates_count": len(self.templates)
        }


# Instance globale
_simple_ai_service = None


def get_simple_ai_service() -> SimpleAIRemediationService:
    """Retourne instance du service simplifié"""
    global _simple_ai_service
    
    if _simple_ai_service is None:
        _simple_ai_service = SimpleAIRemediationService()
    
    return _simple_ai_service
