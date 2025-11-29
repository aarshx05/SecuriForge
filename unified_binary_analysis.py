#!/usr/bin/env python3
"""
unified_binary_analysis.py - Comprehensive Binary Analysis CLI Tool

Integrates all analysis modules:
  - SBOM Generation (SPDX/CycloneDX)
  - Risk Assessment
  - Malware Detection
  - Hardening Checks
  - AI-Powered Report Generation

Usage:
    python unified_binary_analysis.py [binary] [options]
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger("unified_analysis")

from datetime import datetime, timezone

class UnifiedBinaryAnalyzer:
    """Unified interface for all binary analysis tools"""
    
    def __init__(self, binary_path: str, config: Dict[str, Any]):
        self.binary_path = os.path.abspath(binary_path)
        self.config = config
        self.results = {
            "_meta": {
                "binary_path": self.binary_path,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "tool_version": "1.0.0"
            }
        }
        
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")
    
    def run_sbom(self) -> Dict[str, Any]:
        """Run SBOM generation"""
        try:
            from modules.sbom_gen import SBOMGenerator
            LOG.info("Running SBOM generation...")
            
            generator = SBOMGenerator(self.binary_path)
            
            if self.config.get('sbom_format') == 'both':
                result = generator.run_all()
            elif self.config.get('sbom_format') == 'cyclonedx':
                result = {"cyclonedx": generator.generate_cyclonedx()}
            else:  # spdx-json (default)
                result = {"spdx": generator.generate_spdx()}
            
            self.results['sbom'] = result
            LOG.info("SBOM generation completed")
            return result
            
        except Exception as e:
            LOG.error(f"SBOM generation failed: {e}")
            self.results['sbom'] = {"error": str(e)}
            return {"error": str(e)}
    
    def run_hardening(self) -> Dict[str, Any]:
        """Run hardening checks"""
        try:
            from modules.hardening_checker import BinaryHardeningChecker
            LOG.info("Running hardening checks...")
            
            checker = BinaryHardeningChecker(self.binary_path)
            result = checker.run_all()
            
            self.results['hardening'] = result
            LOG.info("Hardening checks completed")
            return result
            
        except Exception as e:
            LOG.error(f"Hardening checks failed: {e}")
            self.results['hardening'] = {"error": str(e)}
            return {"error": str(e)}
    
    def run_malware_check(self) -> Dict[str, Any]:
        """Run malware detection"""
        try:
            from modules.mal_checker import MalwareChecker
            LOG.info("Running malware detection...")
            
            checker = MalwareChecker(
                self.binary_path,
                yara_rules=self.config.get('yara_rules'),
                high_entropy_threshold=self.config.get('high_entropy', 7.5),
                low_entropy_threshold=self.config.get('low_entropy', 1.0),
                verbose=self.config.get('verbose', False),
                extract_utf16=self.config.get('extract_utf16', True)
            )
            result = checker.run_all()
            
            self.results['malware'] = result
            LOG.info("Malware detection completed")
            return result
            
        except Exception as e:
            LOG.error(f"Malware detection failed: {e}")
            self.results['malware'] = {"error": str(e)}
            return {"error": str(e)}
    
    def run_risk_assessment(self) -> Dict[str, Any]:
        """Run risk assessment"""
        try:
            from modules.risk_assessment import ReverseEngineeringRisk
            LOG.info("Running risk assessment...")
            
            # Use hardening report if available
            hardening_report = self.results.get('hardening', {})
            
            rar = ReverseEngineeringRisk(
                self.binary_path,
                hardening_report=hardening_report if hardening_report else None
            )
            result = rar.run_all()
            
            self.results['risk_assessment'] = result
            LOG.info("Risk assessment completed")
            return result
            
        except Exception as e:
            LOG.error(f"Risk assessment failed: {e}")
            self.results['risk_assessment'] = {"error": str(e)}
            return {"error": str(e)}
    
    def run_ai_report(self) -> Dict[str, Any]:
        """Run AI-powered report generation"""
        try:
            import subprocess
            import tempfile
            LOG.info("Running AI report generation...")
            
            # Save combined results to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(self.results, f, indent=2)
                temp_path = f.name
            
            try:
                # Build command
                cmd = [
                    sys.executable,
                    'modules/report_gen.py',
                    temp_path,
                    '--mode', self.config.get('report_mode', 'report'),
                    '--json-type', 'combined',
                    '--top-k', str(self.config.get('top_k', 5))
                ]
                
                # Add API key if provided
                api_key = self.config.get('groq_api_key') or os.getenv('GROQ_API_KEY')
                if api_key:
                    cmd.extend(['--api-key', api_key])
                
                if self.config.get('verbose'):
                    cmd.append('--verbose')
                
                # Run report generator
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode == 0:
                    try:
                        report_data = json.loads(result.stdout)
                        self.results['ai_report'] = report_data
                        LOG.info("AI report generation completed")
                        return report_data
                    except json.JSONDecodeError:
                        # Fallback to text output
                        self.results['ai_report'] = {"text": result.stdout}
                        return {"text": result.stdout}
                else:
                    error_msg = f"Report generation failed: {result.stderr}"
                    LOG.error(error_msg)
                    self.results['ai_report'] = {"error": error_msg}
                    return {"error": error_msg}
                    
            finally:
                # Cleanup temp file
                try:
                    os.unlink(temp_path)
                except:
                    pass
                    
        except Exception as e:
            LOG.error(f"AI report generation failed: {e}")
            self.results['ai_report'] = {"error": str(e)}
            return {"error": str(e)}
    
    def export_pdf(self, output_path: str) -> bool:
        """Export AI report to PDF"""
        try:
            from modules.pdf_exporter import PDFExporter
            LOG.info("Exporting AI report to PDF...")
            
            # Check if AI report exists
            ai_report = self.results.get('ai_report', {})
            if not ai_report or 'html' not in ai_report:
                LOG.error("No AI report HTML available for PDF export")
                return False
            
            # Prepare metadata
            metadata = {
                'analysis_timestamp': self.results['_meta']['analysis_timestamp'],
                'tool_version': self.results['_meta']['tool_version']
            }
            
            # Add risk scores if available
            if 'malware' in self.results and 'findings' in self.results['malware']:
                overall_risk = self.results['malware']['findings'].get('overall_risk', {})
                metadata['malware_risk'] = overall_risk.get('score', 'N/A')
                metadata['malware_risk_interpretation'] = overall_risk.get('interpretation', 'N/A')
            
            if 'risk_assessment' in self.results and 'overall_risk' in self.results['risk_assessment']:
                risk = self.results['risk_assessment']['overall_risk']
                metadata['re_risk'] = risk.get('score', 'N/A')
                metadata['re_risk_interpretation'] = risk.get('interpretation', 'N/A')
            
            # Export to PDF
            exporter = PDFExporter(self.binary_path)
            success = exporter.export_to_pdf(
                ai_report['html'],
                output_path,
                metadata
            )
            
            if success:
                LOG.info(f"PDF exported successfully: {output_path}")
            return success
            
        except Exception as e:
            LOG.error(f"PDF export failed: {e}")
            return False
    
    def send_email(self) -> bool:
        """Send analysis report via email"""
        try:
            from modules.email_sender import EmailSender
            LOG.info("Preparing to send email report...")
            
            # Get email configuration
            email_config = self.config.get('email_config', {})
            if not email_config:
                LOG.error("Email configuration not provided")
                return False
            
            # Create email sender
            if email_config.get('preset'):
                sender = EmailSender.from_preset(
                    email_config['preset'],
                    email_config['from_email'],
                    email_config['password']
                )
            else:
                sender = EmailSender(
                    email_config['smtp_server'],
                    email_config['smtp_port'],
                    email_config['from_email'],
                    email_config['password'],
                    email_config.get('use_tls', True)
                )
            
            # Prepare summary
            summary = {
                'timestamp': self.results['_meta']['analysis_timestamp']
            }
            
            if 'malware' in self.results and 'findings' in self.results['malware']:
                overall_risk = self.results['malware']['findings'].get('overall_risk', {})
                summary['malware_risk'] = overall_risk.get('score', 'N/A')
                summary['malware_risk_interpretation'] = overall_risk.get('interpretation', 'N/A')
            
            if 'risk_assessment' in self.results and 'overall_risk' in self.results['risk_assessment']:
                risk = self.results['risk_assessment']['overall_risk']
                summary['re_risk'] = risk.get('score', 'N/A')
                summary['re_risk_interpretation'] = risk.get('interpretation', 'N/A')
            
            if 'hardening' in self.results:
                hardening = self.results['hardening']
                checks = [k for k in hardening.keys() if k != '_meta']
                passed = sum(1 for k in checks if hardening[k].get('passed', False))
                summary['hardening_passed'] = passed
                summary['hardening_total'] = len(checks)
            
            # Get AI report HTML if available
            ai_report_html = None
            if 'ai_report' in self.results:
                ai_report_html = self.results['ai_report'].get('html')
            
            # Send email
            success = sender.send_report(
                to_emails=email_config['to_emails'],
                binary_name=os.path.basename(self.binary_path),
                summary=summary,
                subject=email_config.get('subject'),
                attachments=email_config.get('attachments', []),
                cc_emails=email_config.get('cc_emails'),
                bcc_emails=email_config.get('bcc_emails'),
                include_ai_report=email_config.get('include_ai_report', False),
                ai_report_html=ai_report_html
            )
            
            if success:
                LOG.info("Email sent successfully")
            return success
            
        except Exception as e:
            LOG.error(f"Email sending failed: {e}")
            return False
    
    def calculate_overall_risk(self) -> tuple:
        """
        Calculate overall weighted risk score
        Returns: (score, interpretation)
        """
        scores = []
        weights = []
        
        # Malware risk (weight: 40%)
        if 'malware' in self.results and 'findings' in self.results['malware']:
            malware_risk = self.results['malware']['findings'].get('overall_risk', {}).get('score', 0)
            scores.append(malware_risk)
            weights.append(0.40)
        
        # Hardening risk (weight: 30%)
        if 'hardening' in self.results:
            hardening = self.results['hardening']
            checks = [k for k in hardening.keys() if k != '_meta']
            if checks:
                passed = sum(1 for k in checks if hardening[k].get('passed', False))
                hardening_risk = 1.0 - (passed / len(checks))
                scores.append(hardening_risk)
                weights.append(0.30)
        
        # RE risk (weight: 30%)
        if 'risk_assessment' in self.results and 'overall_risk' in self.results['risk_assessment']:
            re_risk = self.results['risk_assessment']['overall_risk'].get('score', 0)
            scores.append(re_risk)
            weights.append(0.30)
        
        # Calculate weighted average
        if not scores:
            return (0.0, 'Unknown')
        
        total_weight = sum(weights)
        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        overall_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        # Determine interpretation (3-tier)
        if overall_score <= 0.4:
            interpretation = 'Low'
        elif overall_score <= 0.7:
            interpretation = 'Medium'
        else:
            interpretation = 'High'
        
        return (round(overall_score, 3), interpretation)
    
    def run_all(self) -> Dict[str, Any]:
        """Run all enabled analyses"""
        if self.config.get('run_sbom', True):
            self.run_sbom()
        
        if self.config.get('run_hardening', True):
            self.run_hardening()
        
        if self.config.get('run_malware', True):
            self.run_malware_check()
        
        if self.config.get('run_risk', True):
            self.run_risk_assessment()
        
        if self.config.get('run_ai_report', False):
            self.run_ai_report()
        
        return self.results
    
    def save_results(self, output_path: str):
        """Save results to JSON file"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        LOG.info(f"Results saved to: {output_path}")
    
    def save_individual_reports(self, output_dir: str):
        """Save individual reports to separate files"""
        os.makedirs(output_dir, exist_ok=True)
        
        for module, data in self.results.items():
            if module == "_meta":
                continue
            
            output_file = os.path.join(output_dir, f"{module}.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            LOG.info(f"Saved {module} report to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Unified Binary Analysis Tool - Comprehensive security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all analyses on a binary
  %(prog)s /path/to/binary -o results.json
  
  # Run only specific analyses
  %(prog)s /path/to/binary --only-sbom --only-hardening
  
  # Run with YARA rules and generate AI report
  %(prog)s /path/to/binary -y rules.yar --ai-report --groq-key YOUR_KEY
  
  # Save individual reports to directory
  %(prog)s /path/to/binary --output-dir ./reports/
  
  # Full analysis with custom settings
  %(prog)s /path/to/binary -o full.json --high-entropy 7.0 --sbom-format both --report-mode remediation
        """
    )
    
    # Positional argument
    parser.add_argument(
        'binary',
        help='Path to binary file (ELF/PE/Mach-O)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        help='Output JSON file for combined results',
        default=None
    )
    output_group.add_argument(
        '--output-dir',
        help='Directory to save individual module reports',
        default=None
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    # Module selection
    module_group = parser.add_argument_group('Module Selection (default: all)')
    module_group.add_argument(
        '--only-sbom',
        action='store_true',
        help='Run only SBOM generation'
    )
    module_group.add_argument(
        '--only-hardening',
        action='store_true',
        help='Run only hardening checks'
    )
    module_group.add_argument(
        '--only-malware',
        action='store_true',
        help='Run only malware detection'
    )
    module_group.add_argument(
        '--only-risk',
        action='store_true',
        help='Run only risk assessment'
    )
    module_group.add_argument(
        '--skip-sbom',
        action='store_true',
        help='Skip SBOM generation'
    )
    module_group.add_argument(
        '--skip-hardening',
        action='store_true',
        help='Skip hardening checks'
    )
    module_group.add_argument(
        '--skip-malware',
        action='store_true',
        help='Skip malware detection'
    )
    module_group.add_argument(
        '--skip-risk',
        action='store_true',
        help='Skip risk assessment'
    )
    
    # SBOM options
    sbom_group = parser.add_argument_group('SBOM Options')
    sbom_group.add_argument(
        '--sbom-format',
        choices=['spdx-json', 'cyclonedx', 'both'],
        default='spdx-json',
        help='SBOM output format (default: spdx-json)'
    )
    
    # Malware detection options
    malware_group = parser.add_argument_group('Malware Detection Options')
    malware_group.add_argument(
        '-y', '--yara-rules',
        default='./yara',  # ← ADD THIS LINE
        help='Path to YARA rules file or directory (default: ./yara)'  # ← UPDATE THIS
    )
    malware_group.add_argument(
        '--high-entropy',
        type=float,
        default=7.5,
        help='High entropy threshold (default: 7.5)'
    )
    malware_group.add_argument(
        '--low-entropy',
        type=float,
        default=1.0,
        help='Low entropy threshold (default: 1.0)'
    )
    malware_group.add_argument(
        '--no-utf16',
        dest='extract_utf16',
        action='store_false',
        help='Disable UTF-16 string extraction'
    )
    malware_group.add_argument(
        '--fail-on-yara',
        action='store_true',
        help='Exit with error code if YARA matches found'
    )
    
    # AI Report options
    ai_group = parser.add_argument_group('AI Report Generation Options')
    ai_group.add_argument(
        '--ai-report',
        action='store_true',
        help='Generate AI-powered analysis report (requires report_gen.py)'
    )
    ai_group.add_argument(
        '--groq-key',
        help='GROQ API key (or set GROQ_API_KEY env variable)'
    )
    ai_group.add_argument(
        '--report-mode',
        choices=['summary', 'remediation', 'report'],
        default='report',
        help='AI report generation mode (default: report)'
    )
    ai_group.add_argument(
        '--top-k',
        type=int,
        default=5,
        help='Number of top context chunks for AI (default: 5)'
    )
    
    # PDF Export options
    pdf_group = parser.add_argument_group('PDF Export Options')
    pdf_group.add_argument(
        '--export-pdf',
        help='Export AI report to PDF file'
    )
    
    # Email options
    email_group = parser.add_argument_group('Email Notification Options')
    email_group.add_argument(
        '--email-to',
        nargs='+',
        help='Recipient email address(es)'
    )
    email_group.add_argument(
        '--email-from',
        help='Sender email address'
    )
    email_group.add_argument(
        '--email-password',
        help='Email password or app password'
    )
    email_group.add_argument(
        '--email-preset',
        choices=['gmail', 'outlook', 'yahoo'],
        help='Email service preset (gmail/outlook/yahoo)'
    )
    email_group.add_argument(
        '--email-smtp-server',
        help='Custom SMTP server address'
    )
    email_group.add_argument(
        '--email-smtp-port',
        type=int,
        default=587,
        help='SMTP port (default: 587)'
    )
    email_group.add_argument(
        '--email-subject',
        help='Custom email subject'
    )
    email_group.add_argument(
        '--email-cc',
        nargs='+',
        help='CC email address(es)'
    )
    email_group.add_argument(
        '--email-attach-json',
        action='store_true',
        help='Attach JSON report to email'
    )
    email_group.add_argument(
        '--email-attach-pdf',
        action='store_true',
        help='Attach PDF report to email (requires --export-pdf)'
    )
    
    # CI/CD options
    cicd_group = parser.add_argument_group('CI/CD Options')
    cicd_group.add_argument(
        '--fail-on-high',
        action='store_true',
        help='Exit with code 3 if overall risk is High'
    )
    cicd_group.add_argument(
        '--fail-on-medium',
        action='store_true',
        help='Exit with code 2 if overall risk is Medium or above'
    )
    cicd_group.add_argument(
        '--fail-threshold',
        type=float,
        help='Custom risk threshold (0.0-1.0) to fail'
    )
        
    args = parser.parse_args()

    # Validate YARA rules path
    if args.yara_rules:
        yara_path = Path(args.yara_rules)
        if not yara_path.exists():
            LOG.warning(f"YARA rules path not found: {args.yara_rules}")
            LOG.info("Malware detection will run without YARA rules")
            args.yara_rules = None
        else:
            # Count YARA rules
            if yara_path.is_dir():
                yara_count = len(list(yara_path.glob('*.yar')))
                LOG.info(f"Found {yara_count} YARA rules in {args.yara_rules}")
            else:
                LOG.info(f"Using YARA rules file: {args.yara_rules}")

    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine which modules to run
    only_flags = [args.only_sbom, args.only_hardening, args.only_malware, args.only_risk]
    if any(only_flags):
        # If any --only flag is set, only run those
        run_sbom = args.only_sbom
        run_hardening = args.only_hardening
        run_malware = args.only_malware
        run_risk = args.only_risk
    else:
        # Otherwise run all except skipped
        run_sbom = not args.skip_sbom
        run_hardening = not args.skip_hardening
        run_malware = not args.skip_malware
        run_risk = not args.skip_risk
    
    # Build configuration
    config = {
        'run_sbom': run_sbom,
        'run_hardening': run_hardening,
        'run_malware': run_malware,
        'run_risk': run_risk,
        'run_ai_report': args.ai_report,
        'sbom_format': args.sbom_format,
        'yara_rules': args.yara_rules,
        'high_entropy': args.high_entropy,
        'low_entropy': args.low_entropy,
        'extract_utf16': args.extract_utf16,
        'groq_api_key': args.groq_key,
        'report_mode': args.report_mode,
        'top_k': args.top_k,
        'verbose': args.verbose
    }
    
    # Email configuration
    if args.email_to:
        email_config = {
            'to_emails': args.email_to,
            'from_email': args.email_from,
            'password': args.email_password,
            'subject': args.email_subject,
            'cc_emails': args.email_cc,
            'attachments': []
        }
        
        if args.email_preset:
            email_config['preset'] = args.email_preset
        elif args.email_smtp_server:
            email_config['smtp_server'] = args.email_smtp_server
            email_config['smtp_port'] = args.email_smtp_port
        else:
            LOG.error("Must specify either --email-preset or --email-smtp-server")
            return 1
        
        if not args.email_from or not args.email_password:
            LOG.error("--email-from and --email-password are required for email")
            return 1
        
        config['email_config'] = email_config
    
    try:
        # Run analysis
        analyzer = UnifiedBinaryAnalyzer(args.binary, config)
        results = analyzer.run_all()
        
        # Save results
        if args.output:
            analyzer.save_results(args.output)
            # Add to email attachments if requested
            if args.email_to and args.email_attach_json:
                config['email_config']['attachments'].append(args.output)
        
        if args.output_dir:
            analyzer.save_individual_reports(args.output_dir)
        
        # Export PDF if requested
        if args.export_pdf:
            if 'ai_report' not in results or 'html' not in results.get('ai_report', {}):
                LOG.warning("Cannot export PDF: AI report not generated. Use --ai-report")
            else:
                pdf_success = analyzer.export_pdf(args.export_pdf)
                if pdf_success and args.email_to and args.email_attach_pdf:
                    config['email_config']['attachments'].append(args.export_pdf)
        
        # Send email if configured
        if args.email_to:
            analyzer.send_email()
        
        # Print summary to stdout if no output file specified
        if not args.output and not args.output_dir:
            print(json.dumps(results, indent=2))
        
        # Calculate overall risk
        overall_score, overall_interpretation = analyzer.calculate_overall_risk()
        
        # Print summary
        LOG.info("\n" + "="*60)
        LOG.info("ANALYSIS SUMMARY")
        LOG.info("="*60)
        
        if 'malware' in results and 'findings' in results['malware']:
            overall_risk = results['malware']['findings'].get('overall_risk', {})
            LOG.info(f"Malware Risk: {overall_risk.get('interpretation', 'N/A')} ({overall_risk.get('score', 'N/A')})")
        
        if 'risk_assessment' in results and 'overall_risk' in results['risk_assessment']:
            risk = results['risk_assessment']['overall_risk']
            LOG.info(f"RE Risk: {risk.get('interpretation', 'N/A')} ({risk.get('score', 'N/A')})")
        
        if 'hardening' in results:
            hardening = results['hardening']
            checks = [k for k in hardening.keys() if k != '_meta']
            passed = sum(1 for k in checks if hardening[k].get('passed', False))
            LOG.info(f"Hardening: {passed}/{len(checks)} checks passed")
        
        LOG.info("-" * 60)
        LOG.info(f"Overall Weighted Risk: {overall_interpretation} ({overall_score})")
        LOG.info("="*60)
        
        # Determine exit code (3-tier system)
        exit_code = 0
        
        # Check YARA matches first (highest priority)
        if args.fail_on_yara and 'malware' in results:
            yara_matches = results['malware'].get('findings', {}).get('yara', {}).get('matches', [])
            if yara_matches:
                LOG.warning(f"YARA matches found: {len(yara_matches)}")
                LOG.info("Exit Code: 10 (YARA Match)")
                return 10
        
        # Check custom threshold
        if args.fail_threshold is not None:
            if overall_score >= args.fail_threshold:
                LOG.warning(f"Risk score {overall_score} exceeds threshold {args.fail_threshold}")
                exit_code = 3 if overall_score > 0.7 else 2
                LOG.info(f"Exit Code: {exit_code} (Threshold Exceeded)")
                return exit_code
        
        # Check fail-on flags
        if args.fail_on_high and overall_interpretation == 'High':
            LOG.warning("High risk detected with --fail-on-high flag")
            LOG.info("Exit Code: 3 (High Risk)")
            return 3
        
        if args.fail_on_medium and overall_interpretation in ['Medium', 'High']:
            LOG.warning(f"{overall_interpretation} risk detected with --fail-on-medium flag")
            exit_code = 3 if overall_interpretation == 'High' else 2
            LOG.info(f"Exit Code: {exit_code} ({overall_interpretation} Risk)")
            return exit_code
        
        # Standard 3-tier exit codes
        if overall_interpretation == 'High':
            exit_code = 3
        elif overall_interpretation == 'Medium':
            exit_code = 2
        else:
            exit_code = 0
        
        LOG.info(f"Exit Code: {exit_code} ({overall_interpretation} Risk)")
        return exit_code
        
    except Exception as e:
        LOG.error(f"Analysis failed: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())