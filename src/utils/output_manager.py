import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import jinja2
from .logger import Logger

class OutputManager:
    """Advanced output management with multiple format support."""
    
    def __init__(self, output_dir: str = "results"):
        self.logger = Logger()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create templates directory if it doesn't exist
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
        
        # Create HTML template if it doesn't exist
        self._create_default_template()
        
    def _create_default_template(self):
        """Create default HTML template if it doesn't exist."""
        template_path = self.template_dir / "report_template.html"
        if not template_path.exists():
            template_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        :root {
            --primary-color: #2563eb;
            --success-color: #16a34a;
            --warning-color: #ca8a04;
            --error-color: #dc2626;
            --background-color: #f8fafc;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            line-height: 1.5;
            color: #1f2937;
            background-color: var(--background-color);
            margin: 0;
            padding: 2rem;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 2rem;
        }
        
        .header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #e5e7eb;
        }
        
        .section {
            margin-bottom: 2rem;
            padding: 1rem;
            background-color: #f9fafb;
            border-radius: 0.375rem;
        }
        
        .section-title {
            color: var(--primary-color);
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }
        
        .info-card {
            background-color: white;
            padding: 1rem;
            border-radius: 0.375rem;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
        }
        
        .subdomain-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 0.5rem;
        }
        
        .subdomain-item {
            display: flex;
            align-items: center;
            padding: 0.5rem;
            background-color: white;
            border-radius: 0.25rem;
            border: 1px solid #e5e7eb;
        }
        
        .status-icon {
            margin-right: 0.5rem;
            font-size: 1.25rem;
        }
        
        .active { color: var(--success-color); }
        .inactive { color: var(--error-color); }
        
        .recommendations {
            list-style-type: none;
            padding: 0;
        }
        
        .recommendations li {
            margin-bottom: 0.5rem;
            padding: 0.5rem;
            background-color: #f3f4f6;
            border-radius: 0.25rem;
        }
        
        .timestamp {
            color: #6b7280;
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ title }}</h1>
            <p class="timestamp">Generated on {{ timestamp }}</p>
        </div>

        {% if dns_info %}
        <div class="section">
            <h2 class="section-title">DNS Information</h2>
            <div class="info-grid">
                {% for info in dns_info %}
                    <div class="info-card">
                        <p><strong>Hostname:</strong> {{ info.hostname }}</p>
                        <p><strong>IP Addresses:</strong> {{ info.ip_addresses|join(', ') }}</p>
                        {% if info.aliases %}
                        <p><strong>Aliases:</strong> {{ info.aliases|join(', ') }}</p>
                        {% endif %}
                    </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        {% if waf_info %}
        <div class="section">
            <h2 class="section-title">WAF Detection</h2>
            <div class="info-card">
                {% if waf_info.waf_detected %}
                <p><strong>WAF Detected:</strong> {{ waf_info.detected_wafs|join(', ') }}</p>
                {% else %}
                <p>No WAF detected</p>
                {% endif %}
                {% if waf_info.recommendations %}
                <h3>Recommendations:</h3>
                <ul class="recommendations">
                    {% for rec in waf_info.recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if subdomains %}
        <div class="section">
            <h2 class="section-title">Discovered Subdomains</h2>
            <div class="subdomain-list">
                {% for subdomain in subdomains %}
                <div class="subdomain-item">
                    <span class="status-icon {{ 'active' if subdomain.status == 'active' else 'inactive' }}">
                        {{ '✓' if subdomain.status == 'active' else '✗' }}
                    </span>
                    <span>{{ subdomain.subdomain }}</span>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        {% if security_headers %}
        <div class="section">
            <h2 class="section-title">Security Headers</h2>
            <div class="info-card">
                <h3>Missing Headers:</h3>
                <ul class="recommendations">
                    {% for header in security_headers.missing_headers %}
                    <li>{{ header }}</li>
                    {% endfor %}
                </ul>
                {% if security_headers.recommendations %}
                <h3>Recommendations:</h3>
                <ul class="recommendations">
                    {% for rec in security_headers.recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""
            template_path.write_text(template_content)

    def save_results(self, data: Dict[str, Any], target: str, scan_type: str) -> Dict[str, str]:
        """
        Save scan results in multiple formats.
        
        Args:
            data: Scan results to save
            target: Target of the scan
            scan_type: Type of scan performed
            
        Returns:
            Dict with paths to saved reports
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{scan_type}_{target}_{timestamp}"
        
        saved_files = {}
        
        # Save in JSON format
        json_path = self._save_json(data, base_filename)
        saved_files['json'] = str(json_path)
        
        # Save in HTML format
        html_path = self._save_html(data, base_filename, target)
        saved_files['html'] = str(html_path)
        
        # Save in markdown format
        md_path = self._save_markdown(data, base_filename)
        saved_files['markdown'] = str(md_path)
        
        # Save summary
        summary_path = self._save_summary(data, base_filename)
        saved_files['summary'] = str(summary_path)
        
        self.logger.info(f"Results saved to {self.output_dir}")
        return saved_files

    def _save_json(self, data: Dict[str, Any], base_filename: str) -> Path:
        """Save results in JSON format."""
        json_path = self.output_dir / f"{base_filename}.json"
        
        try:
            with open(json_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return json_path
        except Exception as e:
            self.logger.error(f"Failed to save JSON results: {str(e)}")
            raise

    def _save_html(self, data: Dict[str, Any], base_filename: str, target: str) -> Path:
        """Save results in HTML format."""
        html_path = self.output_dir / f"{base_filename}.html"
        
        try:
            template = self.jinja_env.get_template("report_template.html")
            
            # Prepare data for template
            template_data = {
                'title': f"Security Scan Report - {target}",
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'dns_info': self._process_dns_info(data),
                'waf_info': self._process_waf_info(data),
                'subdomains': self._process_subdomains(data),
                'security_headers': self._process_security_headers(data)
            }
            
            html_content = template.render(**template_data)
            html_path.write_text(html_content)
            return html_path
        except Exception as e:
            self.logger.error(f"Failed to save HTML results: {str(e)}")
            raise

    def _process_dns_info(self, data: Dict) -> list:
        """Process DNS information for template."""
        dns_info = []
        for info in data.get('dns_info', []):
            if info and 'records' in info:
                records = info['records']
                if 'a' in records:
                    hostname, aliases, ips = records['a']
                    dns_info.append({
                        'hostname': hostname,
                        'ip_addresses': ips,
                        'aliases': aliases
                    })
        return dns_info

    def _process_waf_info(self, data: Dict) -> Dict:
        """Process WAF information for template."""
        waf_info = {}
        for info in data.get('waf_info', []):
            if info:
                waf_info = {
                    'waf_detected': info.get('waf_detected', False),
                    'detected_wafs': info.get('detected_wafs', []),
                    'recommendations': info.get('recommendations', [])
                }
        return waf_info

    def _process_subdomains(self, data: Dict) -> list:
        """Process subdomains for template."""
        return data.get('subdomains', [])

    def _process_security_headers(self, data: Dict) -> Dict:
        """Process security headers for template."""
        headers_info = {'missing_headers': [], 'recommendations': []}
        for info in data.get('security_headers', []):
            if info and 'headers' in info:
                headers_info['missing_headers'].extend(
                    header for header, value in info['headers'].items()
                    if value == 'Not Set'
                )
                headers_info['recommendations'].extend(
                    info.get('recommendations', [])
                )
        return headers_info

    def _save_markdown(self, data: Dict[str, Any], base_filename: str) -> Path:
        """Save results in markdown format."""
        md_path = self.output_dir / f"{base_filename}.md"
        
        try:
            with open(md_path, 'w') as f:
                f.write(self._generate_markdown(data))
            return md_path
        except Exception as e:
            self.logger.error(f"Failed to save markdown results: {str(e)}")
            raise

    def _save_summary(self, data: Dict[str, Any], base_filename: str) -> Path:
        """Save a brief summary of the results."""
        summary_path = self.output_dir / f"{base_filename}_summary.txt"
        
        try:
            with open(summary_path, 'w') as f:
                f.write(self._generate_summary(data))
            return summary_path
        except Exception as e:
            self.logger.error(f"Failed to save summary: {str(e)}")
            raise

    def _generate_markdown(self, data: Dict[str, Any]) -> str:
        """Generate markdown formatted report."""
        md = []
        
        # Header
        md.append("# Security Scan Report\n")
        md.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Process each section
        if dns_info := self._process_dns_info(data):
            md.append("## DNS Information\n")
            for info in dns_info:
                md.append(f"- Hostname: {info['hostname']}")
                md.append(f"- IP Addresses: {', '.join(info['ip_addresses'])}")
                if info['aliases']:
                    md.append(f"- Aliases: {', '.join(info['aliases'])}")
                md.append("")
        
        if waf_info := self._process_waf_info(data):
            md.append("## WAF Detection\n")
            if waf_info['waf_detected']:
                md.append(f"WAF Detected: {', '.join(waf_info['detected_wafs'])}\n")
                if waf_info['recommendations']:
                    md.append("### Recommendations\n")
                    for rec in waf_info['recommendations']:
                        md.append(f"- {rec}")
            else:
                md.append("No WAF detected\n")
        
        if subdomains := self._process_subdomains(data):
            md.append("## Discovered Subdomains\n")
            for subdomain in subdomains:
                status = "✓" if subdomain['status'] == 'active' else "✗"
                md.append(f"- {subdomain['subdomain']} ({status} {subdomain['status']})")
            md.append("")
        
        return "\n".join(md)

    def _generate_summary(self, data: Dict[str, Any]) -> str:
        """Generate a brief summary of the results."""
        summary = []
        
        summary.append("SECURITY SCAN SUMMARY")
        summary.append("=" * 20)
        summary.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Add key statistics
        if subdomains := self._process_subdomains(data):
            active = sum(1 for s in subdomains if s['status'] == 'active')
            total = len(subdomains)
            summary.append(f"Subdomains: {total} total, {active} active\n")
        
        if waf_info := self._process_waf_info(data):
            if waf_info['waf_detected']:
                summary.append(f"WAF Protection: {', '.join(waf_info['detected_wafs'])}")
            else:
                summary.append("WAF Protection: None detected")
        
        if headers_info := self._process_security_headers(data):
            missing = len(headers_info['missing_headers'])
            summary.append(f"\nMissing Security Headers: {missing}")
            if missing > 0:
                summary.append("Recommendations provided in full report")
        
        return "\n".join(summary)

    def get_latest_results(self, scan_type: Optional[str] = None) -> Optional[Dict]:
        """Retrieve the most recent scan results."""
        try:
            json_files = list(self.output_dir.glob('*.json'))
            if scan_type:
                json_files = [f for f in json_files if scan_type in f.name]
            
            if not json_files:
                return None
            
            latest_file = max(json_files, key=os.path.getctime)
            with open(latest_file) as f:
                return json.load(f)
                
        except Exception as e:
            self.logger.error(f"Failed to retrieve latest results: {str(e)}")
            return None