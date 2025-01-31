import json
import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

class OutputManager:
    def __init__(self, base_dir: str, formats: List[str]):
        self.base_dir = Path(base_dir)
        self.formats = formats
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def save_results(self, module: str, data: Dict[str, Any], target: str):
        """Save module results in specified formats"""
        module_dir = self.base_dir / target / module
        module_dir.mkdir(parents=True, exist_ok=True)

        # Save in all specified formats
        for fmt in self.formats:
            if fmt == "json":
                self._save_json(module_dir / f"{module}_{self.timestamp}.json", data)
            elif fmt == "csv":
                self._save_csv(module_dir / f"{module}_{self.timestamp}.csv", data)
            elif fmt == "markdown":
                self._save_markdown(module_dir / f"{module}_{self.timestamp}.md", data)
            elif fmt == "html":
                self._save_html(module_dir / f"{module}_{self.timestamp}.html", data)

    def _save_json(self, filepath: Path, data: Dict[str, Any]):
        """Save data in JSON format"""
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def _save_csv(self, filepath: Path, data: Dict[str, Any]):
        """Save data in CSV format"""
        if not data:
            return

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write headers
            if isinstance(data, dict):
                writer.writerow(data.keys())
                writer.writerow(data.values())
            elif isinstance(data, list):
                if data and isinstance(data[0], dict):
                    writer.writerow(data[0].keys())
                    for row in data:
                        writer.writerow(row.values())

    def _save_markdown(self, filepath: Path, data: Dict[str, Any]):
        """Save data in Markdown format"""
        with open(filepath, 'w') as f:
            f.write(f"# Scan Results - {self.timestamp}\n\n")
            
            for key, value in data.items():
                f.write(f"## {key}\n")
                if isinstance(value, dict):
                    for k, v in value.items():
                        f.write(f"- **{k}**: {v}\n")
                elif isinstance(value, list):
                    for item in value:
                        f.write(f"- {item}\n")
                else:
                    f.write(f"{value}\n")
                f.write("\n")

    def _save_html(self, filepath: Path, data: Dict[str, Any]):
        """Save data in HTML format"""
        with open(filepath, 'w') as f:
            f.write(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Scan Results - {self.timestamp}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    .section {{ margin: 20px 0; }}
                    .key {{ font-weight: bold; }}
                    .value {{ margin-left: 20px; }}
                </style>
            </head>
            <body>
                <h1>Scan Results - {self.timestamp}</h1>
            """)

            for key, value in data.items():
                f.write(f'<div class="section">')
                f.write(f'<h2>{key}</h2>')
                if isinstance(value, dict):
                    for k, v in value.items():
                        f.write(f'<div><span class="key">{k}:</span>')
                        f.write(f'<span class="value">{v}</span></div>')
                elif isinstance(value, list):
                    f.write('<ul>')
                    for item in value:
                        f.write(f'<li>{item}</li>')
                    f.write('</ul>')
                else:
                    f.write(f'<div class="value">{value}</div>')
                f.write('</div>')

            f.write("""
            </body>
            </html>
            """)