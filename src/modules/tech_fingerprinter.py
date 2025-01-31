import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Set
from datetime import datetime
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class TechnologyFingerprinter:
    def __init__(self, rate_limiter):
        self.rate_limiter = rate_limiter
        self.session = None
        self.technologies: Set[str] = set()
        self._load_signatures()

    def _load_signatures(self):
        """Load technology signatures"""
        self.signatures = {
            "web_servers": {
                "nginx": [
                    {"type": "header", "pattern": r"nginx/?([0-9.]+)?"},
                    {"type": "header", "header": "Server", "pattern": r"nginx"}
                ],
                "apache": [
                    {"type": "header", "pattern": r"apache/?([0-9.]+)?"},
                    {"type": "header", "header": "Server", "pattern": r"apache"}
                ],
                "iis": [
                    {"type": "header", "pattern": r"iis/?([0-9.]+)?"},
                    {"type": "header", "header": "Server", "pattern": r"IIS"}
                ]
            },
            "frameworks": {
                "laravel": [
                    {"type": "cookie", "pattern": r"laravel_session"},
                    {"type": "meta", "pattern": r"csrf-token"}
                ],
                "django": [
                    {"type": "header", "pattern": r"csrftoken"},
                    {"type": "cookie", "pattern": r"django"}
                ],
                "rails": [
                    {"type": "header", "pattern": r"_rails"},
                    {"type": "meta", "pattern": r"csrf-param"}
                ]
            },
            "cms": {
                "wordpress": [
                    {"type": "meta", "pattern": r"generator.*wordpress"},
                    {"type": "path", "pattern": r"/wp-content/"},
                    {"type": "path", "pattern": r"/wp-includes/"}
                ],
                "drupal": [
                    {"type": "meta", "pattern": r"generator.*drupal"},
                    {"type": "path", "pattern": r"/sites/default/files"}
                ],
                "joomla": [
                    {"type": "meta", "pattern": r"generator.*joomla"},
                    {"type": "path", "pattern": r"/media/jui/"}
                ]
            },
            "javascript": {
                "jquery": [
                    {"type": "script", "pattern": r"jquery.*\.js"},
                    {"type": "content", "pattern": r"jQuery"}
                ],
                "react": [
                    {"type": "content", "pattern": r"react.*\.js"},
                    {"type": "meta", "pattern": r"react-root"}
                ],
                "vue": [
                    {"type": "content", "pattern": r"vue.*\.js"},
                    {"type": "meta", "pattern": r"vue"}
                ]
            },
            "analytics": {
                "google_analytics": [
                    {"type": "script", "pattern": r"google-analytics.com"},
                    {"type": "script", "pattern": r"ga\('create'"}
                ],
                "mixpanel": [
                    {"type": "script", "pattern": r"mixpanel"},
                    {"type": "script", "pattern": r"mixpanel.init"}
                ]
            },
            "security": {
                "cloudflare": [
                    {"type": "header", "header": "Server", "pattern": r"cloudflare"},
                    {"type": "cookie", "pattern": r"__cfduid"}
                ],
                "sucuri": [
                    {"type": "header", "pattern": r"sucuri"},
                    {"type": "cookie", "pattern": r"sucuri"}
                ]
            }
        }

    async def analyze(self, target: str) -> Dict[str, Any]:
        """Analyze target for technology fingerprints"""
        self.session = aiohttp.ClientSession()
        try:
            results = await self._scan_target(target)
            return {
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "technologies": self._format_results(results),
                "total_technologies": len(self.technologies)
            }
        finally:
            await self.session.close()

    async def _scan_target(self, target: str) -> Dict[str, List[str]]:
        """Perform comprehensive technology scanning"""
        results = {
            "web_servers": [],
            "frameworks": [],
            "cms": [],
            "javascript": [],
            "analytics": [],
            "security": [],
            "other": []
        }

        try:
            await self.rate_limiter.wait()
            async with self.session.get(f"https://{target}", timeout=10) as response:
                headers = dict(response.headers)
                cookies = response.cookies
                html = await response.text()
                
                # Parse HTML
                soup = BeautifulSoup(html, 'html.parser')
                
                # Analyze different components
                await asyncio.gather(
                    self._analyze_headers(headers, results),
                    self._analyze_cookies(cookies, results),
                    self._analyze_html(soup, results),
                    self._analyze_scripts(soup, results),
                    self._analyze_meta(soup, results)
                )
                
                # Additional JavaScript analysis
                await self._analyze_javascript(target, soup)
                
        except Exception as e:
            results["error"] = str(e)
            
        return results

    async def _analyze_headers(self, headers: Dict, results: Dict):
        """Analyze HTTP headers"""
        for category, techs in self.signatures.items():
            for tech, sigs in techs.items():
                for sig in sigs:
                    if sig["type"] == "header":
                        header_name = sig.get("header", "")
                        if header_name and header_name.lower() in headers:
                            if re.search(sig["pattern"], headers[header_name.lower()], re.I):
                                results[category].append(tech)
                                self.technologies.add(tech)

    async def _analyze_cookies(self, cookies: Dict, results: Dict):
        """Analyze cookies"""
        cookie_string = str(cookies)
        for category, techs in self.signatures.items():
            for tech, sigs in techs.items():
                for sig in sigs:
                    if sig["type"] == "cookie":
                        if re.search(sig["pattern"], cookie_string, re.I):
                            results[category].append(tech)
                            self.technologies.add(tech)

    async def _analyze_html(self, soup: BeautifulSoup, results: Dict):
        """Analyze HTML content"""
        html_content = str(soup)
        for category, techs in self.signatures.items():
            for tech, sigs in techs.items():
                for sig in sigs:
                    if sig["type"] == "content":
                        if re.search(sig["pattern"], html_content, re.I):
                            results[category].append(tech)
                            self.technologies.add(tech)

    async def _analyze_scripts(self, soup: BeautifulSoup, results: Dict):
        """Analyze script tags"""
        scripts = soup.find_all("script", src=True)
        for script in scripts:
            src = script.get("src", "")
            for category, techs in self.signatures.items():
                for tech, sigs in techs.items():
                    for sig in sigs:
                        if sig["type"] == "script":
                            if re.search(sig["pattern"], src, re.I):
                                results[category].append(tech)
                                self.technologies.add(tech)

    async def _analyze_meta(self, soup: BeautifulSoup, results: Dict):
        """Analyze meta tags"""
        meta_tags = soup.find_all("meta")
        for meta in meta_tags:
            content = str(meta)
            for category, techs in self.signatures.items():
                for tech, sigs in techs.items():
                    for sig in sigs:
                        if sig["type"] == "meta":
                            if re.search(sig["pattern"], content, re.I):
                                results[category].append(tech)
                                self.technologies.add(tech)

    async def _analyze_javascript(self, target: str, soup: BeautifulSoup):
        """Analyze JavaScript files for additional insights"""
        scripts = soup.find_all("script", src=True)
        for script in scripts:
            src = script.get("src", "")
            if src.startswith("//"):
                src = f"https:{src}"
            elif src.startswith("/"):
                src = f"https://{target}{src}"
            
            try:
                await self.rate_limiter.wait()
                async with self.session.get(src, timeout=5) as response:
                    if response.status == 200:
                        js_content = await response.text()
                        self._analyze_js_content(js_content)
            except Exception:
                continue

    def _analyze_js_content(self, content: str):
        """Analyze JavaScript content for technology signatures"""
        # Add specific JavaScript analysis logic here
        pass

    def _format_results(self, results: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Format and deduplicate results"""
        formatted = {}
        for category, techs in results.items():
            if techs:
                formatted[category] = list(set(techs))
        return formatted