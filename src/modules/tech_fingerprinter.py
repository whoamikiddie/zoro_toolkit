import re
import json
import asyncio
import aiohttp  # type: ignore
from typing import Dict, List, Optional
from ..utils.logger import Logger
from ..utils.exceptions import ZoroToolkitError

class TechFingerprinter:
    
    def __init__(self):
        self.logger = Logger()
        self._load_signatures()
        
    def _load_signatures(self):
        self.signatures = {
            'frameworks': {
                'Django': [
                    'csrfmiddlewaretoken',
                    'django-debug-toolbar',
                    '__django',
                ],
                'Flask': [
                    'Werkzeug',
                    'flask',
                    'Flask-Session'
                ],
                'Laravel': [
                    'laravel_session',
                    'XSRF-TOKEN',
                    'Laravel'
                ],
                'Express': [
                    'express.sid',
                    'connect.sid',
                    'Express'
                ]
            },
            'cms': {
                'WordPress': [
                    'wp-content',
                    'wp-includes',
                    'wp-json'
                ],
                'Drupal': [
                    'Drupal',
                    'drupal.js',
                    'sites/default'
                ],
                'Joomla': [
                    'joomla',
                    'com_content',
                    'Joomla!'
                ]
            },
            'javascript': {
                'React': [
                    'react.development.js',
                    'react.production.min.js',
                    'react-dom'
                ],
                'Vue.js': [
                    'vue.js',
                    'vue.min.js',
                    'vue-router'
                ],
                'Angular': [
                    'angular.js',
                    'ng-app',
                    'ng-controller'
                ]
            },
            'analytics': {
                'Google Analytics': [
                    'ga.js',
                    'analytics.js',
                    'gtag'
                ],
                'Mixpanel': [
                    'mixpanel',
                    'mixpanel.min.js'
                ]
            },
            'security': {
                'reCAPTCHA': [
                    'recaptcha',
                    'g-recaptcha',
                ],
                'Cloudflare': [
                    'cloudflare',
                    '__cfduid'
                ]
            }
        }

    async def fingerprint(self, url: str) -> Dict:
        try:
            async with aiohttp.ClientSession() as session:
                # Gather all required data concurrently
                results = await asyncio.gather(
                    self._analyze_headers(session, url),
                    self._analyze_source(session, url),
                    self._analyze_scripts(session, url),
                    return_exceptions=True
                )
                
                headers_info, source_info, scripts_info = results
                
                detected_tech = self._combine_findings(
                    headers_info.get('technologies', []) if isinstance(headers_info, dict) else [],
                    source_info.get('technologies', []) if isinstance(source_info, dict) else [],
                    scripts_info.get('technologies', []) if isinstance(scripts_info, dict) else []
                )
                
                security_insights = self._generate_security_insights(detected_tech)
                
                return {
                    'url': url,
                    'status': 'success',
                    'technologies': detected_tech,
                    'security_insights': security_insights,
                    'recommendations': self._generate_recommendations(detected_tech)
                }
                
        except Exception as e:
            self.logger.error(f"Technology fingerprinting failed for {url}: {str(e)}")
            raise ZoroToolkitError(f"Fingerprinting failed: {str(e)}")

    async def _analyze_headers(self, session: aiohttp.ClientSession, url: str) -> Dict:
        try:
            async with session.get(url) as response:
                headers = dict(response.headers)
                technologies = []
                
                if server := headers.get('Server'):
                    technologies.append(('server', server))
                    
                for header in headers:
                    if 'powered-by' in header.lower():
                        technologies.append(('powered-by', headers[header]))
                        
                security_headers = {
                    'X-Frame-Options': headers.get('X-Frame-Options'),
                    'X-XSS-Protection': headers.get('X-XSS-Protection'),
                    'Content-Security-Policy': headers.get('Content-Security-Policy'),
                    'Strict-Transport-Security': headers.get('Strict-Transport-Security')
                }
                
                return {
                    'technologies': technologies,
                    'security_headers': security_headers
                }
                
        except Exception as e:
            self.logger.error(f"Header analysis failed: {str(e)}")
            return {'technologies': [], 'security_headers': {}}

    async def _analyze_source(self, session: aiohttp.ClientSession, url: str) -> Dict:
        try:
            async with session.get(url) as response:
                content = await response.text()
                technologies = []
                
                meta_tags = re.findall(r'<meta[^>]+>', content)
                for meta in meta_tags:
                    if 'generator' in meta.lower():
                        if match := re.search(r'content=["\']([^"\']+)', meta):
                            technologies.append(('generator', match.group(1)))
                
                # Framework detection
                for framework, signatures in self.signatures['frameworks'].items():
                    if any(sig.lower() in content.lower() for sig in signatures):
                        technologies.append(('framework', framework))
                
                # CMS detection
                for cms, signatures in self.signatures['cms'].items():
                    if any(sig.lower() in content.lower() for sig in signatures):
                        technologies.append(('cms', cms))
                
                return {'technologies': technologies}
                
        except Exception as e:
            self.logger.error(f"Source analysis failed: {str(e)}")
            return {'technologies': []}

    async def _analyze_scripts(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """Analyze JavaScript files and dependencies."""
        try:
            async with session.get(url) as response:
                content = await response.text()
                technologies = []
                
                # Extract script sources
                script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)', content)
                
                # Analyze each script source
                for script in script_tags:
                    script_url = script if script.startswith(('http://', 'https://')) else f"{url.rstrip('/')}/{script.lstrip('/')}"
                    
                    for tech_type, signatures in self.signatures['javascript'].items():
                        if any(sig.lower() in script_url.lower() for sig in signatures):
                            technologies.append(('javascript', tech_type))
                
                return {'technologies': technologies}
                
        except Exception as e:
            self.logger.error(f"Script analysis failed: {str(e)}")
            return {'technologies': []}

    def _combine_findings(self, *tech_lists: List) -> Dict:
        """Combine and categorize all detected technologies."""
        combined = {
            'server': set(),
            'frameworks': set(),
            'cms': set(),
            'javascript': set(),
            'security': set(),
            'analytics': set(),
            'other': set()
        }
        
        for tech_list in tech_lists:
            for tech_type, tech_name in tech_list:
                if tech_type in combined:
                    combined[tech_type].add(tech_name)
                else:
                    combined['other'].add(f"{tech_type}:{tech_name}")
        
        # Convert sets to sorted lists
        return {k: sorted(v) for k, v in combined.items() if v}

    def _generate_security_insights(self, detected_tech: Dict) -> Dict:
        """Generate security insights based on detected technologies."""
        insights = {
            'risk_level': 'low',
            'vulnerabilities': [],
            'positive_aspects': []
        }
        
        # Check for security measures
        if 'security' in detected_tech:
            insights['positive_aspects'].extend([
                f"Using {tech} for enhanced security"
                for tech in detected_tech['security']
            ])
        
        # Framework analysis
        if 'frameworks' in detected_tech:
            for framework in detected_tech['frameworks']:
                if framework in ['Django', 'Laravel']:  # Known secure frameworks
                    insights['positive_aspects'].append(
                        f"Using {framework} framework with built-in security features"
                    )
        
        # CMS analysis
        if 'cms' in detected_tech:
            insights['vulnerabilities'].append(
                "CMS detected - ensure regular updates and security patches are applied"
            )
            insights['risk_level'] = 'medium'
        
        return insights

    def _generate_recommendations(self, detected_tech: Dict) -> List[str]:
        """Generate security recommendations based on detected technologies."""
        recommendations = []
        
        # Basic security recommendations
        recommendations.append("Implement HTTPS if not already in use")
        recommendations.append("Enable security headers including CSP and HSTS")
        
        # Framework-specific recommendations
        if 'frameworks' in detected_tech:
            for framework in detected_tech['frameworks']:
                if framework == 'Django':
                    recommendations.extend([
                        "Enable Django's built-in XSS protection",
                        "Configure Django's CSRF protection",
                        "Use Django's secure password hashing"
                    ])
                elif framework == 'Laravel':
                    recommendations.extend([
                        "Enable Laravel's encryption features",
                        "Use Laravel's CSRF protection",
                        "Configure Laravel's authentication guards"
                    ])
        
        # CMS-specific recommendations
        if 'cms' in detected_tech:
            recommendations.extend([
                "Keep CMS and all plugins up to date",
                "Implement strong admin authentication",
                "Use security plugins specific to your CMS",
                "Regular security audits and updates"
            ])
        
        return recommendations