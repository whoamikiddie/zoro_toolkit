# src/modules/waf_detector.py
import re
import requests
from typing import Dict, List
from ..utils.logger import Logger

class WAFDetector:
    """Web Application Firewall (WAF) detection module."""
    
    def __init__(self):
        self.logger = Logger()
        self.timeout = 10
        self.user_agent = "Zoro-Toolkit/1.0"
        self.waf_signatures = {
            'Cloudflare': [
                'cloudflare',
                '__cfduid',
                'cf-ray',
                'cf-cache-status'
            ],
            'AWS WAF': [
                'x-amzn-RequestId',
                'x-amz-cf-id',
                'x-amz-id'
            ],
            'Akamai': [
                'akamai',
                'ak_bmsc',
                'bm_sz'
            ],
            'Imperva': [
                'incap_ses',
                '_incapsula_version',
                'visid_incap'
            ],
            'F5 BIG-IP': [
                'BigIP',
                'BIGipServer',
                'F5_ST'
            ]
        }

    def detect_waf(self, url: str) -> Dict:
        try:
            headers = {
                'User-Agent': self.user_agent,
                # Add some suspicious headers to trigger WAF
                'X-Forwarded-For': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1'
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=True)
            detected_wafs = []
            
            # Check response headers and cookies for WAF signatures
            all_headers = {k.lower(): v for k, v in response.headers.items()}
            cookies = {k.lower(): v for k, v in response.cookies.items()}
            
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    sig_lower = signature.lower()
                    # Check in headers
                    if any(sig_lower in header for header in all_headers.keys()):
                        detected_wafs.append(waf_name)
                        break
                    # Check in header values
                    if any(sig_lower in str(value).lower() for value in all_headers.values()):
                        detected_wafs.append(waf_name)
                        break
                    # Check in cookies
                    if any(sig_lower in cookie for cookie in cookies.keys()):
                        detected_wafs.append(waf_name)
                        break
            
            # Remove duplicates while preserving order
            detected_wafs = list(dict.fromkeys(detected_wafs))
            
            return {
                'url': url,
                'waf_detected': bool(detected_wafs),
                'detected_wafs': detected_wafs,
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Not disclosed'),
                'recommendations': self._generate_recommendations(detected_wafs)
            }
            
        except Exception as e:
            self.logger.error(f"WAF detection failed for {url}: {str(e)}")
            return {
                'url': url,
                'status': 'error',
                'error': str(e)
            }

    def _generate_recommendations(self, detected_wafs: List[str]) -> List[str]:
        """Generate security recommendations based on WAF detection results."""
        recommendations = []
        
        if not detected_wafs:
            recommendations.append("No WAF detected")
        else:
            pass
            # WAF-specific recommendations
            if 'Cloudflare' in detected_wafs:
                recommendations.append("Enable Cloudflare's advanced security features")
            if 'AWS WAF' in detected_wafs:
                recommendations.append("Review and optimize AWS WAF rules")
            if 'Imperva' in detected_wafs:
                recommendations.append("Configure Imperva security policies")
                
        return recommendations