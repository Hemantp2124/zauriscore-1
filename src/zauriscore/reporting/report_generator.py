"""Report Generator for Zauriscore Output Layer.

Generates comprehensive JSON and HTML reports from analysis results.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List

import jinja2

class ReportGenerator:
    def __init__(self, templates_dir: str = 'src/zauriscore/templates'):
        """Initialize the report generator with Jinja2 templates."""
        self.loader = jinja2.FileSystemLoader(templates_dir)
        self.environment = jinja2.Environment(loader=self.loader)
        self.report_template = self.environment.get_template('analysis_report.html')

    def generate_json_report(self, analysis_results: Dict[str, Any], output_path: str = None) -> str:
        """Generate a JSON report from analysis results."""
        # Structure the report
        report = {
            'timestamp': datetime.now().isoformat(),
            'contract_address': analysis_results.get('contract_address', 'Unknown'),
            'overall_score': analysis_results.get('overall_score', 0),
            'slither_score': analysis_results.get('slither_score', 0),
            'ml_score': analysis_results.get('ml_score', 0),
            'mythril_score': analysis_results.get('mythril_score', 0),
            'risk_score': analysis_results.get('risk_score', 0),
            'preprocessing': analysis_results.get('preprocessing', {}),
            'vulnerabilities': analysis_results.get('vulnerabilities', []),
            'gas_optimizations': analysis_results.get('gas_optimizations', []),
            'recommendations': analysis_results.get('recommendations', []),
            'alerts': analysis_results.get('alerts', []),
            'summary': analysis_results.get('summary', '')
        }
        
        json_content = json.dumps(report, indent=2)
        
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(json_content)
        
        return json_content

    def generate_html_report(self, analysis_results: Dict[str, Any], output_path: str = None) -> str:
        """Generate an HTML report from analysis results."""
        # Prepare context for template
        context = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'contract_address': analysis_results.get('contract_address', 'Unknown'),
            'overall_score': analysis_results.get('overall_score', 0),
            'slither_score': analysis_results.get('slither_score', 0),
            'ml_score': analysis_results.get('ml_score', 0),
            'mythril_score': analysis_results.get('mythril_score', 0),
            'risk_score': analysis_results.get('risk_score', 0),
            'vulnerabilities': analysis_results.get('vulnerabilities', []),
            'gas_optimizations': analysis_results.get('gas_optimizations', []),
            'recommendations': analysis_results.get('recommendations', []),
            'alerts': analysis_results.get('alerts', []),
            'summary': analysis_results.get('summary', ''),
            # Add more for viz: scores, charts data
            'scores': {
                'overall': analysis_results.get('overall_score', 0),
                'slither': analysis_results.get('slither_score', 0),
                'ml': analysis_results.get('ml_score', 0),
                'mythril': analysis_results.get('mythril_score', 0),
                'risk': analysis_results.get('risk_score', 0)
            }
        }
        
        html_content = self.report_template.render(context)
        
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(html_content)
        
        return html_content

    def integrate_with_analyzer(self, analyzer_results: Dict[str, Any]) -> Dict[str, str]:
        """Integrate report generation into analyzer workflow."""
        json_report = self.generate_json_report(analyzer_results)
        html_report = self.generate_html_report(analyzer_results)
        
        return {
            'json_report': json_report,
            'html_report': html_report,
            'json_path': f"reports/{analyzer_results.get('contract_address', 'report')}.json",
            'html_path': f"reports/{analyzer_results.get('contract_address', 'report')}.html"
        }

# Example usage and template placeholder
if __name__ == '__main__':
    # Sample results
    sample_results = {
        'contract_address': '0x123...',
        'overall_score': 85,
        'slither_score': 90,
        'ml_score': 80,
        'mythril_score': 75,
        'risk_score': 70,
        'vulnerabilities': ['Reentrancy possible'],
        'gas_optimizations': ['Optimize loops'],
        'recommendations': ['Add checks'],
        'alerts': [],
        'summary': 'Contract is moderately secure.'
    }
    
    generator = ReportGenerator()
    json_out = generator.generate_json_report(sample_results, 'output.json')
    html_out = generator.generate_html_report(sample_results, 'output.html')
    
print('Reports generated!')

# Note: Create templates/analysis_report.html with appropriate HTML structure, CSS for dashboard viz (e.g., charts with Chart.js),
# sections for scores, vulnerabilities, recommendations, etc.