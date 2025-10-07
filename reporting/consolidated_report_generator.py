"""
Consolidated Report Generator
Combines functionality from multiple report generator implementations
"""

import os
import json
import logging
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Union
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConsolidatedReportGenerator:
    """
    Consolidated report generator that combines features from multiple implementations
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the report generator
        
        Args:
            output_dir: Directory to save reports. If None, uses current directory
        """
        self.output_dir = output_dir or os.getcwd()
        self.reports_generated = 0
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        logger.info(f"Report generator initialized. Output directory: {self.output_dir}")
    
    def generate_report(self, data: Union[Dict, List, pd.DataFrame], 
                       report_type: str = "json", 
                       filename: Optional[str] = None) -> str:
        """
        Generate a report from the provided data
        
        Args:
            data: Data to generate report from
            report_type: Type of report to generate (json, csv, excel, txt)
            filename: Optional filename for the report
            
        Returns:
            Path to the generated report file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.{report_type}"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            if report_type == "json":
                self._generate_json_report(data, filepath)
            elif report_type == "csv":
                self._generate_csv_report(data, filepath)
            elif report_type == "excel":
                self._generate_excel_report(data, filepath)
            elif report_type == "txt":
                self._generate_text_report(data, filepath)
            else:
                raise ValueError(f"Unsupported report type: {report_type}")
            
            self.reports_generated += 1
            logger.info(f"Generated {report_type} report: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to generate {report_type} report: {e}")
            raise
    
    def _generate_json_report(self, data: Union[Dict, List], filepath: str):
        """Generate JSON report"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _generate_csv_report(self, data: Union[pd.DataFrame, List], filepath: str):
        """Generate CSV report"""
        if isinstance(data, pd.DataFrame):
            data.to_csv(filepath, index=False)
        else:
            df = pd.DataFrame(data)
            df.to_csv(filepath, index=False)
    
    def _generate_excel_report(self, data: Union[pd.DataFrame, List], filepath: str):
        """Generate Excel report"""
        if isinstance(data, pd.DataFrame):
            data.to_excel(filepath, index=False)
        else:
            df = pd.DataFrame(data)
            df.to_excel(filepath, index=False)
    
    def _generate_text_report(self, data: Union[Dict, List, str], filepath: str):
        """Generate text report"""
        if isinstance(data, str):
            content = data
        elif isinstance(data, dict):
            content = "\n".join([f"{k}: {v}" for k, v in data.items()])
        elif isinstance(data, list):
            content = "\n".join([str(item) for item in data])
        else:
            content = str(data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def generate_summary_report(self, reports_data: List[Dict]) -> str:
        """
        Generate a summary report from multiple report data
        
        Args:
            reports_data: List of report data dictionaries
            
        Returns:
            Path to the summary report
        """
        summary = {
            "total_reports": len(reports_data),
            "generation_timestamp": datetime.now().isoformat(),
            "reports": reports_data
        }
        
        return self.generate_report(summary, "json", "summary_report.json")
    
    def batch_generate_reports(self, data_list: List[Union[Dict, List]], 
                              report_types: List[str] = None) -> List[str]:
        """
        Generate multiple reports in batch
        
        Args:
            data_list: List of data to generate reports from
            report_types: List of report types for each data item
            
        Returns:
            List of paths to generated reports
        """
        if report_types is None:
            report_types = ["json"] * len(data_list)
        
        if len(data_list) != len(report_types):
            raise ValueError("data_list and report_types must have the same length")
        
        generated_files = []
        for i, (data, report_type) in enumerate(zip(data_list, report_types)):
            filename = f"batch_report_{i+1}_{datetime.now().strftime('%H%M%S')}.{report_type}"
            filepath = self.generate_report(data, report_type, filename)
            generated_files.append(filepath)
        
        return generated_files
    
    def get_stats(self) -> Dict:
        """
        Get statistics about reports generated
        
        Returns:
            Dictionary with statistics
        """
        return {
            "reports_generated": self.reports_generated,
            "output_directory": self.output_dir,
            "last_updated": datetime.now().isoformat()
        }


# Factory function for backward compatibility
def create_report_generator(output_dir: Optional[str] = None) -> ConsolidatedReportGenerator:
    """
    Factory function to create report generator instance
    
    Args:
        output_dir: Output directory for reports
        
    Returns:
        ConsolidatedReportGenerator instance
    """
    return ConsolidatedReportGenerator(output_dir)


# Contract-specific report generation
def generate_contract_report(contract_address: str, api_key: str, output_directory: str, chainid: int = 1):
    """
    Convenience function to generate a full contract report
    
    Args:
        contract_address (str): Ethereum contract address
        api_key (str): Etherscan API key
        chainid (int): EVM chain ID (default 1)
    """
    # Import required modules
    import subprocess
    from datetime import datetime
    
    # Fetch contract source code from Etherscan
    from zauriscore.utils.report_generator import fetch_source_code_from_etherscan, secure_filename
    
    fetch_started = datetime.now()
    src_data, src_prov = fetch_source_code_from_etherscan(contract_address, api_key, chainid)
    
    # Proxy resolution logic
    proxy_info = {
        "is_proxy": str(src_data.get('Proxy', '0')) == '1',
        "proxy_address": contract_address,
        "implementation_address": src_data.get('Implementation') or None,
        "analysis_target": "proxy",
        "notes": None
    }
    
    analysis_target_address = contract_address
    analysis_source_data = src_data
    
    if proxy_info["is_proxy"] and proxy_info["implementation_address"]:
        try:
            impl_data, impl_prov = fetch_source_code_from_etherscan(proxy_info["implementation_address"], api_key, chainid)
            analysis_source_data = impl_data
            analysis_target_address = proxy_info["implementation_address"]
            proxy_info["analysis_target"] = "implementation"
            proxy_info["notes"] = "Implementation resolved via Etherscan metadata field 'Implementation'"
            src_prov = impl_prov
        except Exception as e:
            logger.warning("Failed to resolve implementation source: %s", e)

    # Generate comprehensive report
    from zauriscore.utils.report_generator import ZauriScoreReportGenerator
    report_generator = ZauriScoreReportGenerator()
    report = report_generator.generate_comprehensive_report(
        analysis_target_address, 
        analysis_source_data
    )
    fetch_finished = datetime.now()
    duration = (fetch_finished - fetch_started).total_seconds()

    # Export reports
    json_report = report_generator.export_report(report, 'json')
    markdown_report = report_generator.export_report(report, 'markdown')
    
    # Ensure output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Create secure filenames
    safe_contract_address = secure_filename(contract_address)
    json_filename = f"{safe_contract_address}_report.json"
    md_filename = f"{safe_contract_address}_report.md"
    
    report_path_json = os.path.join(output_directory, json_filename)
    report_path_md = os.path.join(output_directory, md_filename)
    
    # Save reports
    with open(report_path_json, 'w', encoding='utf-8') as f:
        f.write(json_report)
    with open(report_path_md, 'w', encoding='utf-8') as f:
        f.write(markdown_report)

    # Enrich saved JSON with provenance, proxy resolution, and decision summary
    try:
        with open(report_path_json, 'r', encoding='utf-8') as f:
            saved = json.load(f)

        # Add provenance information
        saved.setdefault('provenance', {})
        saved['provenance'].update({
            'chain': {'chainid': chainid, 'network': 'Ethereum Mainnet' if chainid == 1 else f'Chain {chainid}'},
            'compiler': {
                'requested_version': analysis_source_data.get('CompilerVersion'),
                'used_version': _get_solc_version()
            },
            'tools': {
                'slither_version': _get_slither_version(),
                'mythril_version': None,
                'detectors': []
            },
            'sources': {
                'etherscan_endpoint': src_prov.get('etherscan_endpoint'),
                'response_hash': src_prov.get('response_hash'),
                'verification_status': src_prov.get('verification_status'),
                'source_type': 'multi_file' if (analysis_source_data.get('SourceCode','').strip().startswith('{') and 'sources' in analysis_source_data.get('SourceCode','')) else 'single_file'
            },
            'runtime': {
                'started_at': fetch_started.isoformat(),
                'finished_at': fetch_finished.isoformat(),
                'duration_seconds': duration
            }
        })

        # Add proxy resolution info
        saved['proxy_resolution'] = proxy_info

        # Add decision summary
        ai = saved.get('ai_vulnerability_assessment', {})
        risk_score = ai.get('risk_score') if isinstance(ai.get('risk_score'), (int, float)) else -1
        risk_category = ai.get('risk_category', 'Unknown')

        detectors = saved.get('security_features', {}).get('static_analysis', {}).get('slither_detectors', []) or []
        has_high = any((d.get('impact','').lower() in ('high','critical')) for d in detectors)
        has_medium = any((d.get('impact','').lower() == 'medium') for d in detectors)

        if has_high:
            status = 'No-Go'
            reasons = ['High/Critical severity static findings present']
        elif risk_score is not None and risk_score >= 0 and risk_score > 60:
            status = 'Needs-Review'
            reasons = ['AI risk score above acceptable threshold']
        elif has_medium:
            status = 'Needs-Review'
            reasons = ['Medium severity findings present']
        else:
            status = 'Go'
            reasons = ['No high/medium issues detected; only informational/optimizations']

        saved['decision_summary'] = {
            'status': status,
            'reasons': reasons[:3],
            'risk_score': risk_score if (risk_score is not None and risk_score >= 0) else None,
            'risk_category': risk_category,
            'highlights': [
                'Proxy resolved to implementation' if proxy_info['is_proxy'] and proxy_info['analysis_target']=='implementation' else 'Direct contract analysis',
                f"Compiler requested: {analysis_source_data.get('CompilerVersion')}",
                'Static analysis completed'
            ]
        }

        with open(report_path_json, 'w', encoding='utf-8') as f:
            json.dump(saved, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.warning('Failed to enrich report with provenance/summary: %s', e)

    logger.info("Reports generated for contract %s in %s", contract_address, output_directory)
    return report_path_json, report_path_md


def _get_slither_version() -> str:
    """Get Slither version"""
    try:
        import slither
        return getattr(slither, "__version__", "unknown")
    except Exception:
        return "unknown"


def _get_solc_version() -> str:
    """Get solc version"""
    try:
        proc = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=10)
        out = (proc.stdout or proc.stderr or "").strip()
        # Extract version like 0.7.6
        for token in out.split():
            if token[0].isdigit() and token.count('.') >= 1:
                return token
        return out[:64]
    except Exception:
        return "unknown"


# Utility functions for common operations
def load_data_from_file(filepath: str) -> Union[Dict, List]:
    """
    Load data from JSON file
    
    Args:
        filepath: Path to JSON file
        
    Returns:
        Loaded data
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_data_to_file(data: Union[Dict, List], filepath: str):
    """
    Save data to JSON file
    
    Args:
        data: Data to save
        filepath: Path to save file
    """
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# Main execution for testing
if __name__ == "__main__":
    # Example usage
    generator = ConsolidatedReportGenerator()
    
    # Sample data
    sample_data = {
        "project": "Zauriscore",
        "version": "1.0",
        "status": "active",
        "modules": ["reporting", "utils", "analysis"]
    }
    
    # Generate different report types
    json_report = generator.generate_report(sample_data, "json")
    csv_report = generator.generate_report([sample_data], "csv")
    txt_report = generator.generate_report(sample_data, "txt")
    
    print(f"Generated reports:")
    print(f"- JSON: {json_report}")
    print(f"- CSV: {csv_report}")
    print(f"- Text: {txt_report}")
    print(f"Total reports generated: {generator.get_stats()['reports_generated']}")