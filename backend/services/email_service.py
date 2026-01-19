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
    """HTML email template for bulletins"""
    
    BULLETIN_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 800px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                      color: white; padding: 20px; border-radius: 5px 5px 0 0; }
            .content { background: #f9f9f9; padding: 20px; }
            .footer { background: #333; color: #fff; padding: 15px; text-align: center; 
                      font-size: 12px; border-radius: 0 0 5px 5px; }
            .cve-group { background: white; padding: 15px; margin: 10px 0; 
                         border-left: 4px solid #667eea; border-radius: 3px; }
            .cve-item { margin: 8px 0; padding: 8px; background: #f0f0f0; 
                        border-radius: 3px; font-family: monospace; }
            .button { background: #667eea; color: white; padding: 10px 20px; 
                      text-decoration: none; border-radius: 3px; display: inline-block; }
            .warning { background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; 
                       margin: 10px 0; }
            table { width: 100%; border-collapse: collapse; margin: 15px 0; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #667eea; color: white; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Security Bulletin</h1>
                <p>{{ region }} Region | {{ sent_date }}</p>
            </div>
            
            <div class="content">
                <h2>{{ title }}</h2>
                
                {% if body %}
                <div class="description">{{ body }}</div>
                {% endif %}
                
                {% if grouped_cves %}
                <h3>Affected Technologies</h3>
                {% for group in grouped_cves %}
                <div class="cve-group">
                    <h4>{{ group.technology }}</h4>
                    <p><strong>Count:</strong> {{ group.count }} CVE(s)</p>
                    
                    <h5>Affected CVEs:</h5>
                    {% for cve in group.cves %}
                    <div class="cve-item">
                        <strong>{{ cve.cve_id }}</strong> - 
                        <span style="color: {% if cve.severity == 'CRITICAL' %}#d32f2f{% elif cve.severity == 'HIGH' %}#f57c00{% elif cve.severity == 'MEDIUM' %}#fbc02d{% else %}#689f38{% endif %}">
                            {{ cve.severity }}
                        </span>
                        (CVSS: {{ cve.cvss_score }})
                        <br>
                        <small>{{ cve.description[:150] }}...</small>
                    </div>
                    {% endfor %}
                    
                    {% if group.remediation %}
                    <div class="warning">
                        <strong>Remediation Guidance:</strong>
                        <p>{{ group.remediation }}</p>
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
                {% endif %}
                
                <h3>Summary</h3>
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Total CVEs</td>
                        <td>{{ total_cves }}</td>
                    </tr>
                    <tr>
                        <td>Critical Issues</td>
                        <td>{{ critical_count }}</td>
                    </tr>
                    <tr>
                        <td>High Issues</td>
                        <td>{{ high_count }}</td>
                    </tr>
                    <tr>
                        <td>Region</td>
                        <td>{{ region }}</td>
                    </tr>
                    <tr>
                        <td>Bulletin ID</td>
                        <td>#{{ bulletin_id }}</td>
                    </tr>
                </table>
                
                <hr>
                <p style="font-size: 12px; color: #666;">
                    <strong>For questions or escalations, contact your security team.</strong>
                </p>
            </div>
            
            <div class="footer">
                <p>© 2026 CTBA Security Platform | Confidential</p>
                <p>{{ footer_message }}</p>
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
        footer_message: str = "This is an automated security bulletin"
    ) -> str:
        """Render bulletin to HTML string"""
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
            sent_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
