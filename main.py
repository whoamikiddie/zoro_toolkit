#!/usr/bin/env python3
# main.py
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
from src.modules.tech_fingerprinter import TechFingerprinter
from src.modules.http_analyzer import HTTPAnalyzer
from src.modules.waf_detector import WAFDetector
from src.utils.logger import Logger
from src.utils.exceptions import ConfigurationError, NetworkError, ZoroToolkitError, RateLimitExceededError, TaskExecutionError

async def analyze_target(domain: str, options: Dict) -> List[Dict]:
    
    # --> Analyze target domain with all available modules.
    logger = Logger()
    logger.info(f"Starting comprehensive scan for domain: {domain}")
    
    try:
        engine = Engine(
            thread_count=options.get('threads', 10),
            timeout=options.get('timeout', 30)
        )
        
        # --> Initialize modules
        dns_enum = DNSEnumerator()
        waf_detector = WAFDetector()
        subdomain_enum = SubdomainEnumerator(domain)
        http_analyzer = HTTPAnalyzer()
        tech_fingerprinter = TechFingerprinter()
        
        # --> DNS Information
        logger.info("Gathering DNS information...")
        dns_result = await engine.execute_async(dns_enum.get_dns_info, domain)
        if isinstance(dns_result, dict) and dns_result.get('records'):
            records = dns_result['records']
            dns_info = []
            if records.get('a'):
                hostname, aliases, ips = records['a']
                dns_info.extend([
                    f"Hostname: {hostname}",
                    f"IP Addresses: {', '.join(ips)}"
                ])
                if aliases:
                    dns_info.append(f"Aliases: {', '.join(aliases)}")
            if records.get('mx'):
                dns_info.append(f"MX Records: {', '.join(records['mx'])}")
            logger.info("DNS Records found:\n" + "\n".join(f"    - {line}" for line in dns_info))
        
        # --> WAF Detection
        logger.info("Detecting WAF presence...")
        waf_result = await engine.execute_async(waf_detector.detect_waf, f"https://{domain}")
        if isinstance(waf_result, dict):
            if waf_result.get('waf_detected', False):
                logger.success(f"Detected WAF: {', '.join(waf_result['detected_wafs'])}")
                if waf_result.get('recommendations'):
                    logger.info("WAF Recommendations:\n" + "\n".join(f"    - {rec}" for rec in waf_result['recommendations']))
            else:
                logger.warning("No WAF detected")
        else:
            logger.error("Invalid response from WAF detector.")

        
        # --> Technology Fingerprinting
        logger.info("Fingerprinting web technologies...")
        tech_result = await tech_fingerprinter.fingerprint(f"https://{domain}")
        if isinstance(tech_result, dict) and tech_result.get('technologies'):
            tech_info = []
            for category, techs in tech_result['technologies'].items():
                if techs:
                    tech_info.append(f"{category.capitalize()}:")
                    tech_info.extend([f"    - {tech}" for tech in techs])
    
            if tech_info:
                logger.info("Detected technologies:\n" + "\n".join(tech_info))
            else:
                logger.info("No technologies detected.")
        else:
            logger.warning(f"No technologies found for domain: {domain}")

        # --> Security Headers
        logger.info("Analyzing security headers...")
        headers_result = await engine.execute_async(http_analyzer.analyze_headers, f"https://{domain}")
        if isinstance(headers_result, dict):
            missing_headers = []
            for header, value in headers_result.get('headers', {}).items():
                if value == 'Not Set':
                    missing_headers.append(header)
            if missing_headers:
                logger.warning("Missing security headers:\n" + "\n".join(f"    - {header}" for header in missing_headers))
            if headers_result.get('recommendations'):
                logger.info("Security header recommendations:\n" + "\n".join(f"    - {rec}" for rec in headers_result['recommendations']))
        
        # --> Subdomain Enumeration
        logger.info("Enumerating subdomains...")
        subdomains_result = await subdomain_enum.enumerate()
        if isinstance(subdomains_result, dict):
            active_subdomains = []
            inactive_subdomains = []
            for sub in subdomains_result.get('subdomains', []):
                if sub.get('status') == 'active':
                    active_subdomains.append(f"    - {sub['subdomain']} (✓ active)")
                else:
                    inactive_subdomains.append(f"    - {sub['subdomain']} (✗ inactive)")
            
            if active_subdomains or inactive_subdomains:
                logger.info("Discovered subdomains:")
                for sub in active_subdomains + inactive_subdomains:
                    logger.info(sub)
        
        # --> Process results
        results = {
            'dns_info': [dns_result] if dns_result else [],
            'waf_info': [waf_result] if waf_result else [],
            'tech_info': [tech_result] if tech_result else [],
            'security_headers': [headers_result] if headers_result else [],
            'subdomains': subdomains_result if subdomains_result else []
        }
        
        return results
        
    except ZoroToolkitError as e:
        logger.error(f"Scan failed: {str(e)}")
        return {'status': 'error', 'error': str(e)}

def save_report(results: Dict, domain: str, output_dir: Path) -> Path:
    # --> save the resutls in the json formats
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
    
# --> create necessary directories
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
        logger.info(f"Starting scan for {args.domain}")
        results = asyncio.run(analyze_target(args.domain, options))
        
        # --> Save report
        report_file = save_report(results, args.domain, output_dir)
        logger.success(f"Scan completed successfully")
        logger.info(f"Report saved to: {report_file}")
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(1)
    except ZoroToolkitError as e:
        logger.critical(f"ZoroToolkitError occurred: {e.message}")
        sys.exit(1)
    except TaskExecutionError as e:
        logger.critical(f"TaskExecutionError occurred: {e.message}")
        sys.exit(1)
    except RateLimitExceededError as e:
        logger.critical(f"RateLimitExceededError occurred: {e.message}")
        sys.exit(1)
    except NetworkError as e:
        logger.critical(f"NetworkError occurred: {e.message}")
        sys.exit(1)
    except ConfigurationError as e:
        logger.critical(f"ConfigurationError occurred: {e.message}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
