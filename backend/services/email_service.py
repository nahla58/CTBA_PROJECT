"""
Email Service - HTML templates, SMTP, and email composition
"""
import logging
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Dict, Optional
from datetime import datetime
from jinja2 import Template

logger = logging.getLogger(__name__)


class EmailTemplate:
    """HTML email template for bulletins with enhanced formatting and styling"""
    
    # Enhanced bulletin template with better styling
    BULLETIN_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Bulletin - {{ title }}</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                line-height: 1.6; 
                color: #333; 
                background-color: #f5f5f5;
            }
            .container { 
                max-width: 800px; 
                margin: 0 auto; 
                background-color: white; 
                border-radius: 8px; 
                overflow: hidden; 
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .header { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; 
                padding: 40px 20px; 
                text-align: center;
            }
            .header h1 { 
                font-size: 24px; 
                margin-bottom: 10px; 
                font-weight: 600;
            }
            .header-meta { 
                font-size: 14px; 
                opacity: 0.9;
            }
            .content { 
                background: #ffffff; 
                padding: 30px; 
            }
            .content-title { 
                font-size: 20px; 
                color: #333; 
                margin-bottom: 20px;
                font-weight: 600;
            }
            .content-description {
                font-size: 14px;
                line-height: 1.8;
                color: #555;
                margin-bottom: 20px;
                padding: 15px;
                background-color: #f9f9f9;
                border-radius: 4px;
                border-left: 4px solid #667eea;
            }
            .section-title { 
                font-size: 16px; 
                color: #333; 
                margin-top: 25px; 
                margin-bottom: 15px;
                font-weight: 600;
                border-bottom: 2px solid #667eea;
                padding-bottom: 8px;
            }
            .cve-group { 
                background: #f8f9fa; 
                padding: 15px; 
                margin: 12px 0; 
                border-left: 4px solid #667eea; 
                border-radius: 4px;
                page-break-inside: avoid;
            }
            .cve-group-header {
                font-size: 14px;
                font-weight: 600;
                color: #333;
                margin-bottom: 10px;
            }
            .cve-group-count {
                font-size: 12px;
                color: #666;
                margin-bottom: 10px;
            }
            .cve-item { 
                margin: 10px 0; 
                padding: 12px; 
                background: white; 
                border-radius: 3px; 
                font-family: 'Courier New', monospace;
                font-size: 13px;
                border: 1px solid #e0e0e0;
            }
            .cve-id {
                font-weight: 600;
                color: #333;
            }
            .severity-critical { 
                background-color: #ffebee; 
                color: #d32f2f; 
                font-weight: bold;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 11px;
            }
            .severity-high { 
                background-color: #fff3e0; 
                color: #f57c00; 
                font-weight: bold;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 11px;
            }
            .severity-medium { 
                background-color: #fffde7; 
                color: #f9a825; 
                font-weight: bold;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 11px;
            }
            .severity-low { 
                background-color: #f1f8e9; 
                color: #689f38; 
                font-weight: bold;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 11px;
            }
            .remediation {
                background: #fff3cd;
                padding: 12px;
                border-left: 4px solid #ffc107;
                border-radius: 3px;
                margin: 10px 0;
                font-size: 13px;
                color: #333;
            }
            .remediation strong {
                display: block;
                margin-bottom: 8px;
                color: #333;
            }
            table { 
                width: 100%; 
                border-collapse: collapse; 
                margin: 15px 0;
                font-size: 13px;
            }
            th { 
                background: #667eea; 
                color: white;
                padding: 12px;
                text-align: left;
                font-weight: 600;
            }
            td { 
                padding: 10px 12px; 
                border-bottom: 1px solid #ddd;
            }
            tr:nth-child(even) {
                background-color: #f9f9f9;
            }
            .footer { 
                background: #f5f5f5; 
                color: #666; 
                padding: 20px; 
                text-align: center; 
                font-size: 12px;
                border-top: 1px solid #ddd;
            }
            .footer p {
                margin: 5px 0;
            }
            .alert {
                background: #f8d7da;
                border: 1px solid #f5c6cb;
                color: #721c24;
                padding: 12px;
                border-radius: 4px;
                margin: 10px 0;
                font-size: 13px;
            }
            .divider {
                border: 0;
                border-top: 1px solid #ddd;
                margin: 20px 0;
            }
            .region-label {
                display: inline-block;
                background-color: #667eea;
                color: white;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                margin: 5px 0;
                font-weight: 500;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Security Bulletin</h1>
                <div class="header-meta">
                    <div class="region-label">{{ region }}</div>
                    <div>{{ sent_date }}</div>
                </div>
            </div>
            
            <div class="content">
                <div class="content-title">{{ title }}</div>
                
                {% if body %}
                <div class="content-description">{{ body }}</div>
                {% endif %}
                
                {% if grouped_cves %}
                <div class="section-title">Affected Technologies & CVEs</div>
                {% for group in grouped_cves %}
                <div class="cve-group">
                    <div class="cve-group-header">{{ group.vendor }}:{{ group.product }}</div>
                    <div class="cve-group-count">📊 {{ group.cve_count }} CVE(s) | Severity: {% for sev, count in group.severity_levels.items() %}{{ sev }}({{ count }}) {% endfor %}</div>
                    
                    {% for cve in group.cves %}
                    <div class="cve-item">
                        <span class="cve-id">{{ cve.cve_id }}</span> 
                        <span class="severity-{{ cve.severity|lower }}">{{ cve.severity }}</span>
                        <span style="color: #888;"> | CVSS: {{ cve.cvss_score }}</span>
                        <br>
                        <small style="color: #666;">{{ cve.description[:120] }}...</small>
                    </div>
                    {% endfor %}
                    
                    {% if group.remediation %}
                    <div class="remediation">
                        <strong>⚙️ Remediation Guidance:</strong>
                        {{ group.remediation }}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
                {% endif %}
                
                <div class="section-title">Summary & Statistics</div>
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Total CVEs</td>
                        <td><strong>{{ total_cves }}</strong></td>
                    </tr>
                    <tr>
                        <td>Critical Vulnerabilities</td>
                        <td><span class="severity-critical">{{ critical_count }}</span></td>
                    </tr>
                    <tr>
                        <td>High Severity</td>
                        <td><span class="severity-high">{{ high_count }}</span></td>
                    </tr>
                    <tr>
                        <td>Medium Severity</td>
                        <td><span class="severity-medium">{{ medium_count }}</span></td>
                    </tr>
                    <tr>
                        <td>Target Region</td>
                        <td>{{ region }}</td>
                    </tr>
                    <tr>
                        <td>Bulletin ID</td>
                        <td>#{{ bulletin_id }}</td>
                    </tr>
                </table>
                
                <hr class="divider">
                <div class="alert">
                    <strong>⚠️ Important:</strong> This is a confidential security bulletin intended for authorized recipients only. 
                    For questions or escalations, contact your security team immediately.
                </div>
            </div>
            
            <div class="footer">
                <p><strong>CTBA Security Platform</strong></p>
                <p>© 2026 CTBA Security Operations | Confidential</p>
                <p>{{ footer_message }}</p>
                <p style="margin-top: 10px; font-size: 11px; color: #999;">
                    Bulletin ID: {{ bulletin_id }} | Generated: {{ sent_date }}
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    @staticmethod
    def render_bulletin(
        title: str,
        region: str,
        bulletin_id: int,
        grouped_cves: List[Dict] = None,
        body: Optional[str] = None,
        total_cves: int = 0,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        footer_message: str = "This is an automated security bulletin"
    ) -> str:
        """Render bulletin to HTML string with enhanced formatting"""
        template = Template(EmailTemplate.BULLETIN_TEMPLATE)
        
        return template.render(
            title=title,
            body=body or "",
            region=region,
            bulletin_id=bulletin_id,
            grouped_cves=grouped_cves or [],
            total_cves=total_cves,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            sent_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            footer_message=footer_message
        )


class EmailService:
    """Email sending service with SMTP support"""
    
    def __init__(
        self,
        smtp_server: str = None,
        smtp_port: int = 587,
        sender_email: str = None,
        sender_password: str = None,
        use_tls: bool = True
    ):
        """Initialize email service"""
        self.smtp_server = smtp_server or os.getenv('SMTP_SERVER', 'localhost')
        self.smtp_port = smtp_port or int(os.getenv('SMTP_PORT', 587))
        self.sender_email = sender_email or os.getenv('SMTP_FROM_EMAIL', 'noreply@ctba.local')
        self.sender_password = sender_password or os.getenv('SMTP_PASSWORD', '')
        self.use_tls = use_tls
        
        logger.info(f"EmailService initialized: {self.smtp_server}:{self.smtp_port}")
    
    def send_bulletin(
        self,
        to_emails: List[str],
        subject: str,
        html_content: str,
        cc_emails: List[str] = None,
        bcc_emails: List[str] = None,
        attachments: List[tuple] = None,
        test_mode: bool = False
    ) -> Dict[str, any]:
        """
        Send bulletin email
        
        Args:
            to_emails: List of recipient emails
            subject: Email subject
            html_content: HTML email body
            cc_emails: CC recipients
            bcc_emails: BCC recipients
            attachments: List of (filename, filepath) tuples
            test_mode: If True, only log without sending
        
        Returns:
            Dict with status, sent_count, failed_count, errors
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(to_emails)
            
            if cc_emails:
                msg['Cc'] = ', '.join(cc_emails)
            
            # Attach HTML content
            msg.attach(MIMEText(html_content, 'html'))
            
            # Attach files if any
            if attachments:
                for filename, filepath in attachments:
                    try:
                        self._attach_file(msg, filepath, filename)
                    except Exception as e:
                        logger.warning(f"Failed to attach {filename}: {e}")
            
            all_recipients = to_emails.copy()
            if cc_emails:
                all_recipients.extend(cc_emails)
            if bcc_emails:
                all_recipients.extend(bcc_emails)
            
            # Test mode: just log
            if test_mode:
                logger.info(f"TEST MODE - Would send email to {len(all_recipients)} recipients")
                return {
                    'status': 'test',
                    'sent_count': len(to_emails),
                    'failed_count': 0,
                    'errors': []
                }
            
            # Send email
            try:
                if self.use_tls:
                    server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                    server.starttls()
                else:
                    server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
                
                if self.sender_password:
                    server.login(self.sender_email, self.sender_password)
                
                server.sendmail(self.sender_email, all_recipients, msg.as_string())
                server.quit()
                
                logger.info(f"✅ Bulletin sent successfully to {len(all_recipients)} recipients")
                
                return {
                    'status': 'success',
                    'sent_count': len(to_emails),
                    'cc_count': len(cc_emails) if cc_emails else 0,
                    'bcc_count': len(bcc_emails) if bcc_emails else 0,
                    'failed_count': 0,
                    'errors': []
                }
                
            except smtplib.SMTPAuthenticationError as e:
                logger.error(f"SMTP Authentication failed: {e}")
                return {
                    'status': 'failed',
                    'sent_count': 0,
                    'failed_count': len(all_recipients),
                    'errors': [f"Authentication error: {str(e)}"]
                }
            except Exception as e:
                logger.error(f"Failed to send email: {e}")
                return {
                    'status': 'failed',
                    'sent_count': 0,
                    'failed_count': len(all_recipients),
                    'errors': [str(e)]
                }
        
        except Exception as e:
            logger.error(f"Email preparation failed: {e}")
            return {
                'status': 'failed',
                'sent_count': 0,
                'failed_count': len(to_emails),
                'errors': [str(e)]
            }
    
    @staticmethod
    def _attach_file(msg: MIMEMultipart, filepath: str, filename: str):
        """Attach file to email message"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Attachment not found: {filepath}")
        
        with open(filepath, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename= {filename}')
        msg.attach(part)
