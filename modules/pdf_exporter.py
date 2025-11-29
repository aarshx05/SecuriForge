#!/usr/bin/env python3
"""
pdf_exporter.py - AI Report to PDF Converter

Converts AI-generated HTML reports to styled PDF documents.
Uses WeasyPrint for HTML to PDF conversion.

Dependencies:
    pip install weasyprint
"""

import os
import logging
from typing import Optional
from datetime import datetime

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

LOG = logging.getLogger(__name__)


class PDFExporter:
    """Export AI reports to PDF with SecuriForge branding"""
    
    # SecuriForge branded CSS
    SECURIFORGE_STYLE = """
    @page {
        size: A4;
        margin: 2cm;
        @top-center {
            content: "SecuriForge Security Analysis Report";
            font-family: 'Arial', sans-serif;
            font-size: 10pt;
            color: #666;
        }
        @bottom-right {
            content: "Page " counter(page) " of " counter(pages);
            font-size: 9pt;
            color: #666;
        }
    }
    
    body {
        font-family: 'Arial', 'Helvetica', sans-serif;
        line-height: 1.6;
        color: #333;
        font-size: 11pt;
    }
    
    h1 {
        color: #2c3e50;
        border-bottom: 3px solid #3498db;
        padding-bottom: 10px;
        margin-top: 0;
        font-size: 24pt;
    }
    
    h2 {
        color: #34495e;
        border-bottom: 2px solid #95a5a6;
        padding-bottom: 5px;
        margin-top: 20px;
        font-size: 18pt;
    }
    
    h3 {
        color: #7f8c8d;
        font-size: 14pt;
        margin-top: 15px;
    }
    
    code {
        background-color: #f4f4f4;
        padding: 2px 6px;
        border-radius: 3px;
        font-family: 'Courier New', monospace;
        font-size: 10pt;
    }
    
    pre {
        background-color: #f8f9fa;
        border-left: 4px solid #3498db;
        padding: 15px;
        overflow-x: auto;
        border-radius: 4px;
    }
    
    pre code {
        background-color: transparent;
        padding: 0;
    }
    
    table {
        border-collapse: collapse;
        width: 100%;
        margin: 15px 0;
    }
    
    th, td {
        border: 1px solid #ddd;
        padding: 12px;
        text-align: left;
    }
    
    th {
        background-color: #3498db;
        color: white;
        font-weight: bold;
    }
    
    tr:nth-child(even) {
        background-color: #f2f2f2;
    }
    
    .header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 30px;
        margin: -2cm -2cm 20px -2cm;
        text-align: center;
    }
    
    .header h1 {
        color: white;
        border: none;
        margin: 0;
        font-size: 28pt;
    }
    
    .header .subtitle {
        font-size: 12pt;
        margin-top: 10px;
        opacity: 0.9;
    }
    
    .metadata {
        background-color: #ecf0f1;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 20px;
        font-size: 10pt;
    }
    
    .metadata table {
        margin: 0;
    }
    
    .metadata th {
        background-color: #95a5a6;
    }
    
    .risk-high {
        color: #e74c3c;
        font-weight: bold;
    }
    
    .risk-medium {
        color: #f39c12;
        font-weight: bold;
    }
    
    .risk-low {
        color: #27ae60;
        font-weight: bold;
    }
    
    ul, ol {
        margin: 10px 0;
        padding-left: 25px;
    }
    
    li {
        margin: 5px 0;
    }
    
    blockquote {
        border-left: 4px solid #95a5a6;
        margin: 15px 0;
        padding: 10px 20px;
        background-color: #f9f9f9;
        font-style: italic;
    }
    
    .footer {
        margin-top: 30px;
        padding-top: 20px;
        border-top: 2px solid #bdc3c7;
        text-align: center;
        font-size: 9pt;
        color: #7f8c8d;
    }
    """
    
    def __init__(self, binary_path: str, custom_css: Optional[str] = None):
        """
        Initialize PDF exporter
        
        Args:
            binary_path: Path to analyzed binary
            custom_css: Optional custom CSS to override defaults
        """
        if not WEASYPRINT_AVAILABLE:
            raise ImportError(
                "WeasyPrint is required for PDF export. "
                "Install it with: pip install weasyprint"
            )
        
        self.binary_path = binary_path
        self.custom_css = custom_css
        LOG.info("PDF Exporter initialized")
    
    def _build_html_document(self, ai_report_html: str, metadata: dict) -> str:
        """Build complete HTML document with header and metadata"""
        
        binary_name = os.path.basename(self.binary_path)
        timestamp = metadata.get('analysis_timestamp', datetime.utcnow().isoformat())
        
        # Build metadata table
        metadata_rows = f"""
        <tr><th>Binary</th><td>{binary_name}</td></tr>
        <tr><th>Path</th><td>{self.binary_path}</td></tr>
        <tr><th>Analysis Date</th><td>{timestamp}</td></tr>
        <tr><th>Tool Version</th><td>{metadata.get('tool_version', '1.0.0')}</td></tr>
        """
        
        # Add risk scores if available
        if 'malware_risk' in metadata:
            risk_class = self._get_risk_class(metadata.get('malware_risk_interpretation', 'Unknown'))
            metadata_rows += f"""
            <tr><th>Malware Risk</th><td class="{risk_class}">{metadata.get('malware_risk_interpretation', 'N/A')} ({metadata.get('malware_risk', 'N/A')})</td></tr>
            """
        
        if 're_risk' in metadata:
            risk_class = self._get_risk_class(metadata.get('re_risk_interpretation', 'Unknown'))
            metadata_rows += f"""
            <tr><th>RE Risk</th><td class="{risk_class}">{metadata.get('re_risk_interpretation', 'N/A')} ({metadata.get('re_risk', 'N/A')})</td></tr>
            """
        
        html_doc = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>SecuriForge Security Report - {binary_name}</title>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ SecuriForge</h1>
                <div class="subtitle">Binary Security Analysis Report</div>
            </div>
            
            <div class="metadata">
                <h3>Analysis Metadata</h3>
                <table>
                    {metadata_rows}
                </table>
            </div>
            
            <div class="content">
                {ai_report_html}
            </div>
            
            <div class="footer">
                Generated by SecuriForge Binary Analysis Tool<br>
                © {datetime.now().year} SecuriForge - Advanced Security Analysis
            </div>
        </body>
        </html>
        """
        
        return html_doc
    
    def _get_risk_class(self, interpretation: str) -> str:
        """Get CSS class for risk level"""
        interpretation_lower = interpretation.lower()
        if 'high' in interpretation_lower or 'critical' in interpretation_lower:
            return 'risk-high'
        elif 'medium' in interpretation_lower:
            return 'risk-medium'
        else:
            return 'risk-low'
    
    def export_to_pdf(
        self,
        ai_report_html: str,
        output_path: str,
        metadata: Optional[dict] = None
    ) -> bool:
        """
        Export AI report HTML to PDF
        
        Args:
            ai_report_html: HTML content from AI report
            output_path: Path to save PDF file
            metadata: Optional metadata to include in header
            
        Returns:
            True if successful, False otherwise
        """
        try:
            LOG.info(f"Generating PDF report: {output_path}")
            
            # Prepare metadata
            if metadata is None:
                metadata = {
                    'analysis_timestamp': datetime.utcnow().isoformat() + 'Z',
                    'tool_version': '1.0.0'
                }
            
            # Build complete HTML document
            full_html = self._build_html_document(ai_report_html, metadata)
            
            # Use custom CSS if provided, otherwise use default
            css_content = self.custom_css if self.custom_css else self.SECURIFORGE_STYLE
            
            # Generate PDF
            html_obj = HTML(string=full_html)
            css_obj = CSS(string=css_content)
            
            html_obj.write_pdf(output_path, stylesheets=[css_obj])
            
            LOG.info(f"PDF report successfully generated: {output_path}")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to generate PDF: {e}")
            return False
    
    def export_from_file(
        self,
        html_file: str,
        output_path: str,
        metadata: Optional[dict] = None
    ) -> bool:
        """
        Export AI report from HTML file to PDF
        
        Args:
            html_file: Path to HTML file
            output_path: Path to save PDF file
            metadata: Optional metadata to include
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(html_file, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            return self.export_to_pdf(html_content, output_path, metadata)
            
        except Exception as e:
            LOG.error(f"Failed to read HTML file: {e}")
            return False


# Standalone CLI for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SecuriForge PDF Exporter")
    parser.add_argument("html_file", help="Input HTML file")
    parser.add_argument("output_pdf", help="Output PDF file")
    parser.add_argument("--binary", help="Binary path for metadata", default="unknown")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    exporter = PDFExporter(args.binary)
    success = exporter.export_from_file(args.html_file, args.output_pdf)
    
    exit(0 if success else 1)