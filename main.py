import argparse
import asyncio
import sys
import json
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from src.utils.banner import print_banner
from src.core.engine import Engine
from src.modules.dns_enumerator import DNSEnumerator
from src.modules.subdomain_enumerator import SubdomainEnumerator
from src.modules.http_analyzer import HTTPAnalyzer
from src.modules.waf_detector import WAFDetector
from src.utils.logger import Logger
from src.utils.exceptions import ZoroToolkitError

async def analyze_target(domain: str, options: Dict) -> List[Dict]:
    """
    Analyze target domain with all available modules.
    """
    logger = Logger()
    logger.info(f"Starting comprehensive scan for domain: {domain}")
    
    try:
        engine = Engine(
            thread_count=options.get('threads', 10),
            timeout=options.get('timeout', 30)
        )
        
        # Initialize modules
        dns_enum = DNSEnumerator()
        waf_detector = WAFDetector()
        subdomain_enum = SubdomainEnumerator()
        http_analyzer = HTTPAnalyzer()
        
        
        total_tasks = 5  # Update this when adding new tasks
        completed_tasks = 0
        
        # Add high-priority tasks
        logger.info("Starting high-priority scans...")
        
        # DNS Info
        logger.info("Gathering DNS information...")
        dns_result = await engine.execute_async(dns_enum.get_dns_info, domain)
        completed_tasks += 1
        logger.progress(completed_tasks, total_tasks, "Scan Progress")
        
        # WAF Detection
        logger.info("Detecting WAF presence...")
        waf_result = await engine.execute_async(waf_detector.detect_waf, f"https://{domain}")
        completed_tasks += 1
        logger.progress(completed_tasks, total_tasks, "Scan Progress")
        
        # Security Headers
        logger.info("Analyzing security headers...")
        headers_result = await engine.execute_async(http_analyzer.analyze_headers, f"https://{domain}")
        completed_tasks += 1
        logger.progress(completed_tasks, total_tasks, "Scan Progress")
        
        # Subdomain Enumeration
        logger.info("Enumerating subdomains...")
        subdomains_result = await engine.execute_async(subdomain_enum.enumerate, domain)
        completed_tasks += 1
        logger.progress(completed_tasks, total_tasks, "Scan Progress")
        
        # Sensitive Files
        logger.info("Checking for sensitive files...")
        files_result = await engine.execute_async(http_analyzer.check_robots_sitemap, domain)
        completed_tasks += 1
        logger.progress(completed_tasks, total_tasks, "Scan Progress")
        
        # Process results
        results = {
            'dns_info': [dns_result] if dns_result else [],
            'waf_info': [waf_result] if waf_result else [],
            'security_headers': [headers_result] if headers_result else [],
            'subdomains': subdomains_result if subdomains_result else [],
            'sensitive_files': [files_result] if files_result else []
        }
        
        return results
        
    except ZoroToolkitError as e:
        logger.error(f"Scan failed: {str(e)}")
        return {'status': 'error', 'error': str(e)}

def save_report(results: Dict, domain: str, output_dir: Path):
    """Save scan results to a JSON report file"""
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = output_dir / f"zoro_report_{domain}_{timestamp}.json"
    
    report = {
        'scan_info': {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'version': '1.0'
        },
        'results': results
    }
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_file

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Zoro Security Toolkit")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    parser.add_argument("--output-dir", type=str, default="reports", help="Output directory for reports")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Create necessary directories
    Path("logs").mkdir(exist_ok=True)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    options = {
        'threads': args.threads,
        'timeout': args.timeout,
        'verbose': args.verbose
    }
    
    logger = Logger()
    
    try:
        # Run the analysis
        logger.info(f"Starting scan for {args.domain}")
        results = asyncio.run(analyze_target(args.domain, options))
        
        # Save report
        report_file = save_report(results, args.domain, output_dir)
        logger.success(f"Scan report saved to: {report_file}")
        
        # Display results
        logger.success("\n=== Scan Results ===")
        
        if results.get('waf_info'):
            logger.info("\nWAF Detection Results:")
            for waf_info in results['waf_info']:
                if waf_info.get('waf_detected'):
                    logger.success(f"WAF Detected: {', '.join(waf_info['detected_wafs'])}")
                    logger.info("Recommendations:")
                    for rec in waf_info.get('recommendations', []):
                        logger.info(f"- {rec}")
                else:
                    logger.warning("No WAF detected")
        
        if results.get('dns_info'):
            logger.info("\nDNS Information:")
            for info in results['dns_info']:
                records = info.get('records', {})
                if records.get('a'):
                    hostname, aliases, ips = records['a']
                    logger.info(f"Hostname: {hostname}")
                    if aliases:
                        logger.info(f"Aliases: {', '.join(aliases)}")
                    logger.info(f"IP Addresses: {', '.join(ips)}")
                if records.get('mx'):
                    logger.info(f"MX Records: {', '.join(records['mx'])}")
                
        if results.get('security_headers'):
            logger.info("\nSecurity Headers Analysis:")
            for header_info in results['security_headers']:
                headers = header_info.get('headers', {})
                logger.info("Missing Security Headers:")
                for header, value in headers.items():
                    if value == 'Not Set':
                        logger.warning(f"- {header}")
                logger.info("\nRecommendations:")
                for rec in header_info.get('recommendations', []):
                    logger.info(f"- {rec}")
                
        if results.get('subdomains'):
            logger.info("\nDiscovered Subdomains:")
            for subdomain in results['subdomains']:
                if subdomain.get('status') == 'active':
                    logger.success(f"- {subdomain['subdomain']} ({subdomain['ip']})")
                
        if results.get('sensitive_files'):
            logger.info("\nSensitive Files:")
            for file_info in results['sensitive_files']:
                if file_info.get('robots_txt', {}).get('status') == 'found':
                    logger.info("robots.txt found")
                if file_info.get('sitemap_xml', {}).get('status') == 'found':
                    logger.info("sitemap.xml found")
                if file_info.get('sensitive_paths'):
                    logger.warning("Sensitive paths found:")
                    for path in file_info['sensitive_paths']:
                        logger.warning(f"- {path}")
                
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()