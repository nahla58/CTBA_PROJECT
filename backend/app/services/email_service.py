"""
Email Service - SMTP integration with HTML templates for bulletin delivery
"""
import os
import smtplib
import logging
from typing import List, Optional, Dict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import base64
from jinja2 import Template

logger = logging.getLogger(__name__)


class EmailTemplate:
    """HTML email template for bulletins"""
    
    BULLETIN_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ title }}</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 700px;
                margin: 0 auto;
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
                font-weight: 600;
            }
            .region-badge {
                display: inline-block;
                background: rgba(255,255,255,0.2);
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                margin-top: 10px;
            }
            .content {
                padding: 30px;
            }
            .body-text {
                margin-bottom: 30px;
                line-height: 1.8;
            }
            .cve-section {
                margin: 30px 0;
            }
            .cve-section h3 {
                margin-top: 0;
                margin-bottom: 15px;
                color: #667eea;
                font-size: 18px;
                border-bottom: 2px solid #f0f0f0;
                padding-bottom: 10px;
            }
            .cve-group {
                margin: 20px 0;
                padding: 15px;
                background: #f9f9f9;
                border-left: 4px solid #667eea;
                border-radius: 4px;
            }
            .cve-group-title {
                font-weight: 600;
                margin-bottom: 10px;
                color: #333;
            }
            .cve-list {
                list-style: none;
                padding: 0;
                margin: 0;
            }
            .cve-list li {
                padding: 8px 0;
                border-bottom: 1px solid #eee;
            }
            .cve-list li:last-child {
                border-bottom: none;
            }
            .cve-id {
                font-family: 'Courier New', monospace;
                font-weight: 600;
                color: #333;
            }
            .severity {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 11px;
                font-weight: 600;
                margin-left: 10px;
            }
            .severity-critical {
                background-color: #d32f2f;
                color: white;
            }
            .severity-high {
                background-color: #f57c00;
                color: white;
            }
            .severity-medium {
                background-color: #fbc02d;
                color: #333;
            }
            .severity-low {
                background-color: #689f38;
                color: white;
            }
            .summary-table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            .summary-table th {
                background: #f0f0f0;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                border-bottom: 2px solid #ddd;
            }
            .summary-table td {
                padding: 12px;
                border-bottom: 1px solid #eee;
            }
            .summary-table tr:hover {
                background: #f9f9f9;
            }
            .footer {
                background: #f5f5f5;
                padding: 20px 30px;
                border-top: 1px solid #eee;
                font-size: 12px;
                color: #666;
                text-align: center;
            }
            .button {
                display: inline-block;
                padding: 10px 20px;
                background: #667eea;
                color: white;
                text-decoration: none;
                border-radius: 4px;
                margin: 20px 0;
            }
            .stats {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
                margin: 20px 0;
            }
            .stat-card {
                background: #f9f9f9;
                padding: 15px;
                border-radius: 4px;
                border-left: 4px solid #667eea;
            }
            .stat-card strong {
                display: block;
                color: #667eea;
                font-size: 20px;
                margin-bottom: 5px;
            }
            .stat-card em {
                display: block;
                color: #666;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Header -->
            <div class="header">
                <h1>{{ title }}</h1>
                <div class="region-badge">📍 {{ region }}</div>
            </div>
            
            <!-- Content -->
            <div class="content">
                <!-- Body Text -->
                {% if body %}
                <div class="body-text">
                    {{ body }}
                </div>
                {% endif %}
                
                <!-- CVE Groups -->
                {% if grouped_cves %}
                <div class="cve-section">
                    <h3>📋 Affected Products & CVEs</h3>
                    {% for group in grouped_cves %}
                    <div class="cve-group">
                        <div class="cve-group-title">
                            {{ group.vendor }}: {{ group.product }}
                            <span style="color: #999; font-weight: normal;">({{ group.cve_count }} CVE{{ group.cve_count != 1 and 's' or '' }})</span>
                        </div>
                        <ul class="cve-list">
                            {% for cve in group.cves %}
                            <li>
                                <span class="cve-id">{{ cve.cve_id }}</span>
                                <span class="severity severity-{{ cve.severity.lower() }}">{{ cve.severity }}</span>
                            </li>
                            {% endfor %}
                        </ul>
                        {% if group.remediation %}
                        <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #eee; font-size: 13px; color: #666;">
                            <strong>Remediation:</strong> {{ group.remediation }}
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
                
                <!-- Statistics -->
                {% if statistics %}
                <div class="cve-section">
                    <h3>📊 Summary</h3>
                    <div class="stats">
                        <div class="stat-card">
                            <strong>{{ statistics.critical_count }}</strong>
                            <em>Critical CVEs</em>
                        </div>
                        <div class="stat-card">
                            <strong>{{ statistics.high_count }}</strong>
                            <em>High Severity CVEs</em>
                        </div>
                    </div>
                </div>
                {% endif %}
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <p>
                    <strong>CTBA Security Bulletin</strong> | Bulletin ID: {{ bulletin_id }}<br>
                    This is an automated security notification. Do not reply to this email.<br>
                    For questions, contact your security team.
                </p>
                <p style="margin-top: 15px; color: #999; font-size: 11px;">
                    © 2024 CTBA Platform. All rights reserved.
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
        body: Optional[str] = None,
        grouped_cves: Optional[list] = None,
        statistics: Optional[dict] = None
    ) -> str:
        """Render bulletin HTML using Jinja2 template"""
        try:
            template = Template(EmailTemplate.BULLETIN_TEMPLATE)
            html = template.render(
                title=title,
                region=region,
                bulletin_id=bulletin_id,
                body=body or '',
                grouped_cves=grouped_cves or [],
                statistics=statistics or {}
            )
            return html
        except Exception as e:
            logger.error(f"Error rendering bulletin template: {e}")
            # Fallback to plain text
            return f"<html><body><h2>{title}</h2><p>{body}</p></body></html>"


class EmailService:
    """SMTP email service for sending bulletins"""
    
    def __init__(self):
        """Initialize SMTP configuration from environment"""
        self.smtp_server = os.environ.get('SMTP_SERVER', 'localhost')
        self.smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        self.from_email = os.environ.get('SMTP_FROM_EMAIL', 'noreply@ctba.local')
        self.password = os.environ.get('SMTP_PASSWORD', '')
        self.use_tls = os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true'
        self.test_mode = False
        
        logger.info(f"EmailService initialized: {self.smtp_server}:{self.smtp_port} (TLS: {self.use_tls})")
    
    def send_bulletin(
        self,
        to_list: List[str],
        subject: str,
        html_body: str,
        cc_list: Optional[List[str]] = None,
        bcc_list: Optional[List[str]] = None,
        attachments: Optional[List[str]] = None,
        test_mode: bool = False
    ) -> Dict[str, any]:
        """
        Send HTML email bulletin
        
        Args:
            to_list: List of recipient emails
            subject: Email subject
            html_body: HTML email body
            cc_list: Optional CC recipients
            bcc_list: Optional BCC recipients
            attachments: Optional list of file paths to attach
            test_mode: If True, log instead of sending
        
        Returns:
            Dict with status, sent_count, failed_count
        """
        
        self.test_mode = test_mode
        
        if not to_list:
            return {
                'status': 'failed',
                'sent_count': 0,
                'failed_count': 0,
                'errors': ['No recipients specified']
            }
        
        if self.test_mode:
            logger.info(f"[TEST MODE] Would send email to {to_list} with subject '{subject}'")
            return {
                'status': 'test',
                'sent_count': len(to_list),
                'failed_count': 0,
                'message': 'Test mode - email logged instead of sent'
            }
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = ', '.join(to_list)
            
            if cc_list:
                msg['Cc'] = ', '.join(cc_list)
            
            # Add plain text version as fallback
            text_part = MIMEText("This email contains HTML content. Please use an HTML-capable email client.", 'plain')
            msg.attach(text_part)
            
            # Add HTML version
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Add attachments
            if attachments:
                for file_path in attachments:
                    try:
                        self._attach_file(msg, file_path)
                    except Exception as e:
                        logger.warning(f"Failed to attach {file_path}: {e}")
            
            # Connect and send
            recipients = to_list + (cc_list or []) + (bcc_list or [])
            
            if not self.password:
                logger.warning("SMTP password not configured - email logging only")
                logger.info(f"Email would be sent to: {recipients}")
                return {
                    'status': 'success',
                    'sent_count': len(to_list),
                    'failed_count': 0,
                    'message': 'SMTP not configured - email logged'
                }
            
            # Send via SMTP
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=30)
            
            if self.password:
                server.login(self.from_email, self.password)
            
            server.send_message(msg, from_addr=self.from_email, to_addrs=recipients)
            server.quit()
            
            logger.info(f"✅ Email sent to {len(to_list)} recipients")
            
            return {
                'status': 'success',
                'sent_count': len(to_list),
                'failed_count': 0,
                'message': f'Email sent to {len(to_list)} recipients'
            }
        
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
            return {
                'status': 'failed',
                'sent_count': 0,
                'failed_count': len(to_list),
                'errors': [f'Authentication failed: {str(e)}']
            }
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return {
                'status': 'failed',
                'sent_count': 0,
                'failed_count': len(to_list),
                'errors': [f'SMTP error: {str(e)}']
            }
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return {
                'status': 'failed',
                'sent_count': 0,
                'failed_count': len(to_list),
                'errors': [str(e)]
            }
    
    @staticmethod
    def _attach_file(msg: MIMEMultipart, file_path: str) -> None:
        """Attach a file to the email"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            with open(file_path, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {os.path.basename(file_path)}'
                )
                msg.attach(part)
        except Exception as e:
            logger.warning(f"Error attaching file {file_path}: {e}")
            raise
