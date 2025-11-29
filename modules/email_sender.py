#!/usr/bin/env python3
"""
email_sender.py - SecuriForge Email Notification Module

Sends security analysis reports via SMTP email with SecuriForge branding.
Supports attachments (PDF, JSON) and HTML/text email bodies.

Dependencies:
    Built-in smtplib, email modules (no extra deps needed)
"""

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional, Dict, Any
from datetime import datetime

LOG = logging.getLogger(__name__)


class EmailSender:
    """Send security reports via email with SecuriForge branding"""
    
    # Default SMTP configurations
    SMTP_CONFIGS = {
        'gmail': {
            'server': 'smtp.gmail.com',
            'port': 587,
            'use_tls': True
        },
        'outlook': {
            'server': 'smtp-mail.outlook.com',
            'port': 587,
            'use_tls': True
        },
        'yahoo': {
            'server': 'smtp.mail.yahoo.com',
            'port': 587,
            'use_tls': True
        }
    }
    
    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        from_email: str,
        password: str,
        use_tls: bool = True
    ):
        """
        Initialize email sender
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP port (typically 587 for TLS, 465 for SSL)
            from_email: Sender email address
            password: Email password or app password
            use_tls: Use TLS encryption (recommended)
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.from_email = from_email
        self.password = password
        self.use_tls = use_tls
        
        LOG.info(f"Email sender initialized: {from_email} via {smtp_server}:{smtp_port}")
    
    @classmethod
    def from_preset(
        cls,
        preset: str,
        from_email: str,
        password: str
    ) -> 'EmailSender':
        """
        Create EmailSender from preset configuration
        
        Args:
            preset: 'gmail', 'outlook', or 'yahoo'
            from_email: Sender email
            password: Email password
            
        Returns:
            EmailSender instance
        """
        if preset not in cls.SMTP_CONFIGS:
            raise ValueError(f"Unknown preset: {preset}. Choose from: {list(cls.SMTP_CONFIGS.keys())}")
        
        config = cls.SMTP_CONFIGS[preset]
        return cls(
            config['server'],
            config['port'],
            from_email,
            password,
            config['use_tls']
        )
    
    def _build_html_body(
        self,
        binary_name: str,
        summary: Dict[str, Any],
        include_full_report: bool = False,
        ai_report_html: Optional[str] = None
    ) -> str:
        """Build HTML email body with SecuriForge branding"""
        
        # Extract summary information
        malware_risk = summary.get('malware_risk', 'N/A')
        malware_interpretation = summary.get('malware_risk_interpretation', 'Unknown')
        re_risk = summary.get('re_risk', 'N/A')
        re_interpretation = summary.get('re_risk_interpretation', 'Unknown')
        hardening_passed = summary.get('hardening_passed', 'N/A')
        hardening_total = summary.get('hardening_total', 'N/A')
        timestamp = summary.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'))
        
        # Determine overall status color
        if malware_interpretation == 'High' or re_interpretation == 'High':
            status_color = '#e74c3c'
            status_emoji = '🔴'
        elif malware_interpretation == 'Medium' or re_interpretation == 'Medium':
            status_color = '#f39c12'
            status_emoji = '🟡'
        else:
            status_color = '#27ae60'
            status_emoji = '🟢'
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                }}
                .header .tagline {{
                    margin-top: 10px;
                    font-size: 14px;
                    opacity: 0.9;
                }}
                .content {{
                    background: white;
                    padding: 30px;
                    border: 1px solid #ddd;
                }}
                .status-box {{
                    background: #f8f9fa;
                    border-left: 4px solid {status_color};
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 4px;
                }}
                .status-box h2 {{
                    margin-top: 0;
                    color: {status_color};
                }}
                .summary-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                .summary-table th {{
                    background: #34495e;
                    color: white;
                    padding: 12px;
                    text-align: left;
                }}
                .summary-table td {{
                    padding: 12px;
                    border-bottom: 1px solid #ddd;
                }}
                .summary-table tr:nth-child(even) {{
                    background: #f2f2f2;
                }}
                .risk-high {{ color: #e74c3c; font-weight: bold; }}
                .risk-medium {{ color: #f39c12; font-weight: bold; }}
                .risk-low {{ color: #27ae60; font-weight: bold; }}
                .footer {{
                    background: #ecf0f1;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #7f8c8d;
                    border-radius: 0 0 10px 10px;
                }}
                .button {{
                    display: inline-block;
                    background: #3498db;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-top: 15px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ SecuriForge</h1>
                <div class="tagline">Binary Security Analysis Report</div>
            </div>
            
            <div class="content">
                <div class="status-box">
                    <h2>{status_emoji} Analysis Complete</h2>
                    <p><strong>Binary:</strong> {binary_name}</p>
                    <p><strong>Analyzed:</strong> {timestamp}</p>
                </div>
                
                <h3>📊 Security Summary</h3>
                <table class="summary-table">
                    <tr>
                        <th>Check</th>
                        <th>Result</th>
                    </tr>
                    <tr>
                        <td><strong>Malware Risk</strong></td>
                        <td class="risk-{malware_interpretation.lower()}">{malware_interpretation} ({malware_risk})</td>
                    </tr>
                    <tr>
                        <td><strong>Reverse Engineering Risk</strong></td>
                        <td class="risk-{re_interpretation.lower()}">{re_interpretation} ({re_risk})</td>
                    </tr>
                    <tr>
                        <td><strong>Hardening Checks</strong></td>
                        <td>{hardening_passed}/{hardening_total} passed</td>
                    </tr>
                </table>
                
                <p><strong>📎 Attachments:</strong> This email includes detailed analysis reports. Please review the attached PDF and JSON files for complete information.</p>
        """
        
        if include_full_report and ai_report_html:
            html += f"""
                <hr style="margin: 30px 0; border: none; border-top: 2px solid #ddd;">
                <h3>🤖 AI-Generated Analysis</h3>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px;">
                    {ai_report_html}
                </div>
            """
        
        html += """
            </div>
            
            <div class="footer">
                <p>Generated by <strong>SecuriForge</strong> Binary Analysis Tool</p>
                <p>Advanced Security Analysis | Powered by AI</p>
                <p style="margin-top: 15px; font-size: 11px;">
                    This is an automated report. Please do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _build_text_body(
        self,
        binary_name: str,
        summary: Dict[str, Any]
    ) -> str:
        """Build plain text email body"""
        
        text = f"""
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  SecuriForge                          ║
║              Binary Security Analysis Report                 ║
╚══════════════════════════════════════════════════════════════╝

Binary: {binary_name}
Analyzed: {summary.get('timestamp', 'N/A')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Malware Risk:         {summary.get('malware_risk_interpretation', 'N/A')} ({summary.get('malware_risk', 'N/A')})
RE Risk:              {summary.get('re_risk_interpretation', 'N/A')} ({summary.get('re_risk', 'N/A')})
Hardening Checks:     {summary.get('hardening_passed', 'N/A')}/{summary.get('hardening_total', 'N/A')} passed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📎 ATTACHMENTS:
This email includes detailed analysis reports in PDF and JSON format.
Please review the attached files for complete information.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Generated by SecuriForge Binary Analysis Tool
Advanced Security Analysis | Powered by AI

This is an automated report. Please do not reply to this email.
        """
        
        return text.strip()
    
    def send_report(
        self,
        to_emails: List[str],
        binary_name: str,
        summary: Dict[str, Any],
        subject: Optional[str] = None,
        attachments: Optional[List[str]] = None,
        cc_emails: Optional[List[str]] = None,
        bcc_emails: Optional[List[str]] = None,
        include_ai_report: bool = False,
        ai_report_html: Optional[str] = None
    ) -> bool:
        """
        Send security analysis report via email
        
        Args:
            to_emails: List of recipient email addresses
            binary_name: Name of analyzed binary
            summary: Summary dictionary with risk scores
            subject: Email subject (auto-generated if None)
            attachments: List of file paths to attach
            cc_emails: CC recipients
            bcc_emails: BCC recipients
            include_ai_report: Include full AI report in email body
            ai_report_html: HTML content of AI report
            
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            
            # Set subject
            if subject is None:
                risk_level = summary.get('malware_risk_interpretation', 'Unknown')
                subject = f"🛡️ SecuriForge Security Report - {binary_name} [{risk_level} Risk]"
            
            msg['Subject'] = subject
            msg['From'] = f"SecuriForge <{self.from_email}>"
            msg['To'] = ', '.join(to_emails)
            
            if cc_emails:
                msg['Cc'] = ', '.join(cc_emails)
            
            # Build email bodies
            text_body = self._build_text_body(binary_name, summary)
            html_body = self._build_html_body(
                binary_name,
                summary,
                include_ai_report,
                ai_report_html
            )
            
            # Attach bodies
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Attach files
            if attachments:
                for file_path in attachments:
                    if not os.path.exists(file_path):
                        LOG.warning(f"Attachment not found: {file_path}")
                        continue
                    
                    try:
                        with open(file_path, 'rb') as f:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(f.read())
                        
                        encoders.encode_base64(part)
                        filename = os.path.basename(file_path)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {filename}'
                        )
                        msg.attach(part)
                        LOG.info(f"Attached file: {filename}")
                    
                    except Exception as e:
                        LOG.error(f"Failed to attach {file_path}: {e}")
            
            # Prepare recipient list
            all_recipients = to_emails.copy()
            if cc_emails:
                all_recipients.extend(cc_emails)
            if bcc_emails:
                all_recipients.extend(bcc_emails)
            
            # Send email
            LOG.info(f"Connecting to SMTP server: {self.smtp_server}:{self.smtp_port}")
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                    LOG.info("TLS encryption enabled")
                
                server.login(self.from_email, self.password)
                LOG.info("SMTP authentication successful")
                
                server.send_message(msg)
                LOG.info(f"Email sent successfully to {len(all_recipients)} recipient(s)")
            
            return True
            
        except smtplib.SMTPAuthenticationError:
            LOG.error("SMTP authentication failed. Check email/password.")
            return False
        except smtplib.SMTPException as e:
            LOG.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            LOG.error(f"Failed to send email: {e}")
            return False


# Standalone CLI for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SecuriForge Email Sender Test")
    parser.add_argument("--to", required=True, help="Recipient email")
    parser.add_argument("--from", required=True, dest="from_email", help="Sender email")
    parser.add_argument("--password", required=True, help="Email password")
    parser.add_argument("--preset", choices=['gmail', 'outlook', 'yahoo'], default='gmail')
    parser.add_argument("--binary", default="test.bin", help="Binary name for test")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    # Test with dummy data
    sender = EmailSender.from_preset(args.preset, args.from_email, args.password)
    
    test_summary = {
        'malware_risk': 0.45,
        'malware_risk_interpretation': 'Medium',
        're_risk': 0.3,
        're_risk_interpretation': 'Low',
        'hardening_passed': 5,
        'hardening_total': 8,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    }
    
    success = sender.send_report(
        to_emails=[args.to],
        binary_name=args.binary,
        summary=test_summary,
        subject="SecuriForge Test Report"
    )
    
    exit(0 if success else 1)