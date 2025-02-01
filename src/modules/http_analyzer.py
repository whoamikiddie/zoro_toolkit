import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, Optional, List
from ..utils.logger import Logger

class HTTPAnalyzer:
    """Analyzes HTTP/HTTPS endpoints for security information."""
    
    def __init__(self):
        self.logger = Logger()
        self.timeout = 10
        self.user_agent = "Zoro-Toolkit/1.0"

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create a secure SSL context for HTTPS requests."""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def analyze_headers(self, url: str) -> Dict:
        """Analyze HTTP response headers for security headers."""
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': self.user_agent}
            )
            context = self._create_ssl_context()
            
            with urllib.request.urlopen(req, context=context, timeout=self.timeout) as response:
                headers = dict(response.headers)
                security_headers = {
                    'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                    'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
                    'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
                    'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
                    'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                    'Server': headers.get('Server', 'Not Disclosed')
                }
                
                return {
                    'url': url,
                    'status': 'success',
                    'headers': security_headers,
                    'recommendations': self._analyze_security_headers(security_headers)
                }
                
        except Exception as e:
            self.logger.error(f"Error analyzing headers for {url}: {str(e)}")
            return {
                'url': url,
                'status': 'error',
                'error': str(e)
            }

    def _analyze_security_headers(self, headers: Dict) -> List[str]:
        """Analyze security headers and provide recommendations."""
        recommendations = []
        
        if headers['X-Frame-Options'] == 'Not Set':
            recommendations.append("Add X-Frame-Options header to prevent clickjacking")
            
        if headers['X-XSS-Protection'] == 'Not Set':
            recommendations.append("Add X-XSS-Protection header to enable browser XSS filtering")
            
        if headers['X-Content-Type-Options'] == 'Not Set':
            recommendations.append("Add X-Content-Type-Options header to prevent MIME-type sniffing")
            
        if headers['Strict-Transport-Security'] == 'Not Set':
            recommendations.append("Add HSTS header to enforce HTTPS")
            
        if headers['Content-Security-Policy'] == 'Not Set':
            recommendations.append("Implement Content Security Policy to prevent XSS and other injection attacks")
            
        return recommendations

    def check_robots_sitemap(self, domain: str) -> Dict:
        """Check robots.txt and sitemap.xml for sensitive information."""
        results = {
            'domain': domain,
            'robots_txt': None,
            'sitemap_xml': None,
            'sensitive_paths': []
        }
        
        try:
            # Check robots.txt
            robots_url = f"https://{domain}/robots.txt"
            req = urllib.request.Request(
                robots_url,
                headers={'User-Agent': self.user_agent}
            )
            
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    robots_content = response.read().decode('utf-8')
                    results['robots_txt'] = {
                        'status': 'found',
                        'content': robots_content
                    }
                    
                    # Look for sensitive paths
                    for line in robots_content.split('\n'):
                        if line.startswith('Disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if any(sensitive in path.lower() for sensitive in 
                                ['admin', 'login', 'backup', 'wp-', 'config', 'test']):
                                results['sensitive_paths'].append(path)
                                
            except urllib.error.HTTPError as e:
                results['robots_txt'] = {
                    'status': 'not_found',
                    'error': str(e)
                }
                
            # Check sitemap.xml
            sitemap_url = f"https://{domain}/sitemap.xml"
            req = urllib.request.Request(
                sitemap_url,
                headers={'User-Agent': self.user_agent}
            )
            
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    results['sitemap_xml'] = {
                        'status': 'found',
                        'content_type': response.headers.get('Content-Type', 'unknown')
                    }
            except urllib.error.HTTPError as e:
                results['sitemap_xml'] = {
                    'status': 'not_found',
                    'error': str(e)
                }
                
            return results
            
        except Exception as e:
            self.logger.error(f"Error checking robots/sitemap for {domain}: {str(e)}")
            return {
                'domain': domain,
                'status': 'error',
                'error': str(e)
            }