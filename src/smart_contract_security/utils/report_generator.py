import json
import os
import copy
import logging
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple, Union, Optional

import numpy as np
import requests
from jinja2 import Environment, FileSystemLoader
from werkzeug.utils import secure_filename

# Configure Jinja2 environment
TEMPLATES_DIR = Path(__file__).parent / 'templates'
env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

# Module logger
logger = logging.getLogger(__name__)

# Module logger
logger = logging.getLogger(__name__)

def json_numpy_serializer(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    raise TypeError(f'Object of type {type(obj)} is not JSON serializable')

class ReportExporter:
    """Base class for report exporters."""
    
    def export(self, data: Dict[str, Any], output_path: Optional[str] = None) -> Union[Dict, str, bytes]:
        """Export report data to the target format.
        
        Args:
            data: Report data to export
            output_path: Optional path to save the report
            
        Returns:
            Exported report in the target format
        """
        raise NotImplementedError("Subclasses must implement export()")


class JSONExporter(ReportExporter):
    """Exports reports in JSON format."""
    
    def export(self, data: Dict[str, Any], output_path: Optional[str] = None) -> Union[Dict, str, bytes]:
        """Export report as JSON.
        
        Args:
            data: Report data to export
            output_path: Optional path to save the JSON file
            
        Returns:
            JSON string if output_path is None, otherwise writes to file and returns file path
        """
        json_str = json.dumps(data, indent=2, default=json_numpy_serializer)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            return output_path
        return json_str


class MarkdownExporter(ReportExporter):
    """Exports reports in Markdown format."""
    
    def __init__(self):
        self.template = env.get_template('report.md.j2')
    
    def export(self, data: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Export report as Markdown.
        
        Args:
            data: Report data to export
            output_path: Optional path to save the Markdown file
            
        Returns:
            Markdown string if output_path is None, otherwise writes to file and returns file path
        """
        # Transform data to match template expectations
        report_data = self._transform_data(data)
        markdown = self.template.render(**report_data)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown)
            return output_path
        return markdown
    
    def _transform_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform report data to match template expectations."""
        return {
            'metadata': {
                'contract_name': data.get('contract_details', {}).get('ContractName', 'Unknown'),
                'contract_address': data.get('metadata', {}).get('contract_address', 'N/A'),
                'analysis_date': data.get('metadata', {}).get('analysis_date', datetime.utcnow().isoformat()),
                'tool_version': data.get('metadata', {}).get('tool_version', '1.0.0')
            },
            'risk_summary': {
                'risk_score': data.get('decision_summary', {}).get('risk_score', 0),
                'risk_category': data.get('decision_summary', {}).get('risk_category', 'Unknown'),
                'confidence': 95  # Default confidence, should be calculated
            },
            'findings': self._extract_findings(data),
            'provenance': data.get('provenance', {})
        }
    
    def _extract_findings(self, data: Dict[str, Any]) -> list:
        """Extract and format findings from analysis data."""
        findings = []
        # Extract from various sources (static analysis, heuristics, etc.)
        if 'security_issues' in data:
            findings.extend(data['security_issues'])
        # Add more sources as needed
        return findings


class PDFExporter(ReportExporter):
    """Exports reports in PDF format using LaTeX."""
    
    def export(self, data: Dict[str, Any], output_path: Optional[str] = None) -> bytes:
        """Export report as PDF.
        
        Args:
            data: Report data to export
            output_path: Path to save the PDF file
            
        Returns:
            PDF bytes if output_path is None, otherwise writes to file and returns file path
            
        Note:
            Requires pdflatex to be installed on the system.
        """
        # First generate markdown
        markdown_exporter = MarkdownExporter()
        markdown = markdown_exporter.export(data)
        
        # Convert markdown to PDF using pandoc
        try:
            if output_path:
                cmd = f'echo "{markdown}" | pandoc -f markdown -o "{output_path}" --pdf-engine=xelatex'
                subprocess.run(cmd, shell=True, check=True)
                return output_path
            else:
                cmd = 'pandoc -f markdown -t pdf --pdf-engine=xelatex'
                result = subprocess.run(
                    cmd, 
                    input=markdown.encode('utf-8'), 
                    shell=True, 
                    check=True, 
                    capture_output=True
                )
                return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate PDF: {e}")
            raise RuntimeError("Failed to generate PDF. Is pandoc and xelatex installed?") from e


class ZauriScoreReportGenerator:
    """Main report generator class supporting multiple export formats."""
    
    def __init__(self):
        self.report_template = {
            "metadata": {
                "tool_version": "1.2.0",
                "analysis_date": datetime.utcnow().isoformat(),
                "contract_address": None
            },
            "decision_summary": {
                "status": "Unknown",  # Go | No-Go | Needs-Review
                "reasons": [],
                "risk_score": None,
                "risk_category": "Unknown",
                "highlights": []
            },
            "contract_details": {
                "ContractName": None,
                "CompilerVersion": None,
                "LicenseType": None,
                "OptimizationUsed": None
            },
            "provenance": {
                "chain": {"chainid": 1, "network": "Ethereum Mainnet"},
                "compiler": {"requested_version": None, "used_version": None},
                "tools": {"slither_version": None, "mythril_version": None, "detectors": []},
                "sources": {
                    "etherscan_endpoint": None,
                    "response_hash": None,
                    "verification_status": None,
                    "source_type": None
                },
                "runtime": {"started_at": None, "finished_at": None, "duration_seconds": None}
            },
            "proxy_resolution": {
                "is_proxy": False,
                "proxy_address": None,
                "implementation_address": None,
                "analysis_target": "proxy",
                "notes": None
            },
            "code_metrics": {
                "total_lines": None,
                "complexity_score": None
            },
            "ai_vulnerability_assessment": {
                "risk_score": None,
                "risk_category": None,
                "confidence_level": None
            },
            "security_features": {
                "static_analysis": {
                    "slither_detectors": [],
                    "mythril_analysis": {},
                    "vulnerability_flags": []
                },
                "ml_detection": {
                    "codebert_insights": {},
                    "risk_dimensions": {}
                }
            },
            "detailed_risk_breakdown": {
                "centralization_risks": 0,
                "transfer_mechanism_risks": 0,
                "ownership_risks": 0
            },
            "recommendations": {
                "immediate_actions": [
                    "Implement robust access control mechanisms",
                    "Add reentrancy guards",
                    "Enhance ownership management",
                    "Add comprehensive NatSpec comments"
                ],
                "long_term_improvements": [
                    "Conduct professional security audit",
                    "Implement multi-signature ownership",
                    "Add time-locks for critical functions"
                ]
            }
        }

    def generate_json_report(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a JSON report from the analysis data
        
        Args:
            analysis_data (Dict[str, Any]): Analysis results from the contract analyzer
            
        Returns:
            Dict[str, Any]: Formatted report
        """
        # Use deep copy so nested dicts don't leak across requests
        report = copy.deepcopy(self.report_template)
        
        # Update metadata
        report['metadata']['analysis_date'] = datetime.now().isoformat()
        report['metadata']['contract_address'] = analysis_data.get('contract_address', 'N/A')
        
        # Update contract details
        if 'contract_details' in analysis_data:
            report['contract_details'].update(analysis_data['contract_details'])
            
        # Update code metrics
        if 'source_code' in analysis_data:
            report['code_metrics'].update({
                'total_lines': len(analysis_data['source_code'].split('\n')),
                'complexity_score': self._calculate_complexity(analysis_data['source_code'])
            })
            
        # Update vulnerability assessment
        if 'vulnerability_assessment' in analysis_data:
            report['ai_vulnerability_assessment'].update(analysis_data['vulnerability_assessment'])
            
        # Update security features
        if 'security_features' in analysis_data:
            report['security_features'].update(analysis_data['security_features'])
            
        # Update risk breakdown
        if 'risk_breakdown' in analysis_data:
            report['detailed_risk_breakdown'].update(analysis_data['risk_breakdown'])
            
        return report
        
    def _calculate_complexity(self, source_code: str) -> int:
        """
        Calculate a basic complexity score for the contract
        
        Args:
            source_code (str): Contract source code
        
        Returns:
            int: Complexity score
        """
        import re
        
        # Count complexity indicators
        complexity = 0
        
        # Count function definitions
        function_matches = re.findall(r'function\s+\w+', source_code)
        complexity += len(function_matches) * 2
        
        # Count modifier definitions
        modifier_matches = re.findall(r'modifier\s+\w+', source_code)
        complexity += len(modifier_matches) * 3
        
        # Count control flow statements
        flow_statements = re.findall(r'(if|else|for|while|require|revert)', source_code)
        complexity += len(flow_statements)
        
        # Normalize complexity to 0-100 range
        return min(max(complexity, 0), 100)

    def generate_comprehensive_report(self, contract_address: str, source_code: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive AI-powered security report
        
        Args:
            contract_address (str): Ethereum contract address
            source_code (str): Contract source code
        
        Returns:
            Dict containing detailed security analysis
        """
        # Use package-relative imports
        from ..analyzers.multi_tool_analyzer import MultiToolAnalyzer
        from ..analyzers.heuristic_analyzer import calculate_heuristic_score
        from ..core.ml_pipeline import ZauriScoreMLPipeline  # Use the actual ML pipeline

        # Check if source_code is a dictionary and contains 'SourceCode'
        if not isinstance(source_code, dict) or 'SourceCode' not in source_code or not source_code['SourceCode']:
            raise ValueError(
                "Failed to retrieve valid contract source code. "
                "This might be due to an invalid/missing Etherscan API key, "
                "network issues, or the contract not being verified on Etherscan."
            )

        # Populate metadata
        self.report_template['metadata']['analysis_date'] = datetime.now().isoformat()
        self.report_template['metadata']['contract_address'] = contract_address
        
        # Populate contract details
        self.report_template['contract_details'] = {
            'ContractName': source_code.get('ContractName', 'N/A'),
            'CompilerVersion': source_code.get('CompilerVersion', 'N/A'),
            'LicenseType': source_code.get('LicenseType', 'N/A'),
            'OptimizationUsed': source_code.get('OptimizationUsed', 'N/A')
        }
        
        # Calculate code metrics
        source_code_text = source_code.get('SourceCode', '')
        self.report_template['code_metrics'] = {
            'total_lines': len(source_code_text.splitlines()),
            'complexity_score': self._calculate_complexity(source_code_text)
        }

        # Perform heuristic analysis
        heuristic_result = calculate_heuristic_score(source_code.get('SourceCode', ''))
                # --- Start of Inserted Block ---
        # Process Slither Static Analysis Findings from heuristic_result
        static_analysis_findings = {
            "slither_detectors": [],
            "message": None # Initialize message
        }
        # Access slither results nested within heuristic_result
        slither_detectors_raw = heuristic_result.get('slither_detectors', []) # Raw list from heuristic_result
        slither_error = heuristic_result.get('slither_error', None) # Get error if present

        # Determine success based on presence of error and detectors list type
        slither_success = slither_error is None and isinstance(slither_detectors_raw, list)

        if slither_success:
            if slither_detectors_raw: # Check if the list is not empty
                for detector in slither_detectors_raw:
                    if isinstance(detector, dict):
                        finding = {
                            "check": detector.get('check', 'N/A'),
                            "impact": detector.get('impact', 'N/A'),
                            "confidence": detector.get('confidence', 'N/A'),
                            "description": detector.get('markdown', detector.get('description', 'No description provided'))
                        }
                        static_analysis_findings["slither_detectors"].append(finding)
                if not static_analysis_findings["slither_detectors"]:
                     # This case might occur if detectors were filtered out or invalid format
                     static_analysis_findings["message"] = "Slither analysis ran successfully, but no valid detectors were processed."
            else:
                 # Slither ran, returned success (no error), but found nothing
                 static_analysis_findings["message"] = "Slither analysis successful, no specific detectors triggered."
        elif slither_error:
            # Slither reported an error
            static_analysis_findings["message"] = f"Slither analysis failed. Error: {slither_error}"
        else:
            # Slither results were missing or not in the expected list format
            static_analysis_findings["message"] = "Slither analysis results were not available or in an unexpected format."
        # --- End of Inserted Block ---
        # Generate AI risk score using the ML pipeline
        ml_pipeline = ZauriScoreMLPipeline()  # Instantiate the pipeline
        # Ensure source_code_text is not empty before prediction
        if source_code_text:
            # predict_risk returns a tensor, get the float value
            # Handle potential errors during prediction gracefully
            try:
                ai_risk_score_tensor = ml_pipeline.predict_risk(source_code_text)
                # Assuming the tensor contains a single score value
                ai_risk_score = float(ai_risk_score_tensor) # Directly use the float result 
                # Ensure score is within 0-100 range if necessary (model might output outside)
                ai_risk_score = max(0.0, min(100.0, ai_risk_score))
            except Exception as e:
                logger.error("Error during ML prediction: %s", e)
                ai_risk_score = -1.0 # Indicate prediction failure
        else:
             ai_risk_score = -1.0 # Indicate missing source code for prediction

        # Categorize the score (handle prediction failure case)
        if ai_risk_score >= 0:
            risk_category = ml_pipeline.categorize(ai_risk_score)
        else:
            risk_category = "Prediction Failed"

        # Populate AI vulnerability assessment using heuristic flags for now
        # TODO: Replace vulnerability_flags with actual AI pattern detection results when available
        self.report_template['ai_vulnerability_assessment'] = {
            "risk_score": ai_risk_score,
            "risk_category": risk_category,
            # Confidence level might relate more to the score prediction's confidence, TBD
            "confidence_level": "High" if ai_risk_score > 70 else "Medium" if ai_risk_score > 40 else "Low", 
            "detailed_ai_findings": heuristic_result.get('vulnerability_flags', []) # Using heuristic flags as placeholder
        }

        # Populate security features (don't overwrite entire block)
        self.report_template['security_features']['static_analysis'].update({
            "slither_detectors": static_analysis_findings["slither_detectors"],
            "vulnerability_flags": heuristic_result.get('vulnerability_flags', [])
        })

        # Populate recommendations
        self.report_template['recommendations'] = {
            "immediate_actions": [
                "Implement robust access control mechanisms",
                "Add reentrancy guards",
                "Enhance ownership management",
                "Add comprehensive NatSpec comments"
            ],
            "long_term_improvements": [
                "Conduct professional security audit",
                "Implement multi-signature ownership",
                "Add time-locks for critical functions"
            ]
        }

        return self.report_template

    def export_report(self, report: Dict[str, Any], output_format: str = 'json') -> str:
        """
        Export the report in specified format
        
        Args:
            report (Dict): Comprehensive security report
            output_format (str): Output format (json/markdown)
        
        Returns:
            str: Formatted report
        """
        if output_format == 'json':
            return json.dumps(report, indent=2, default=json_numpy_serializer)
        
        elif output_format == 'markdown':
            return self._generate_markdown_report(report).encode('utf-8', errors='ignore').decode('utf-8')

    def _generate_markdown_report(self, report: Dict[str, Any]) -> str:
        """
        Convert report to markdown format
        
        Args:
            report (Dict): Comprehensive security report
        
        Returns:
            str: Markdown formatted report
        """
        markdown_report = f"""# 🛡️ ZauriScore™ Comprehensive Security Report

## 📊 Contract Summary
### Basic Contract Information
- **Contract Name**: {report.get('contract_details', {}).get('ContractName', 'N/A')}
- **Contract Address**: `{report['metadata']['contract_address']}`
- **Blockchain Network**: Ethereum
- **Date of Analysis**: `{report['metadata']['analysis_date']}`
- **Source Code Origin**: Etherscan

### Initial Metadata
- **Lines of Code**: {report.get('code_metrics', {}).get('total_lines', 'N/A')}
- **Complexity Score**: {report.get('code_metrics', {}).get('complexity_score', 'N/A')}
- **Compiler Version**: {report.get('contract_details', {}).get('CompilerVersion', 'N/A')}

## 🚨 Risk Score (0-100)
- **AI-Predicted Vulnerability Level**: {report['ai_vulnerability_assessment']['risk_score']}/100
- **Risk Category**: {report['ai_vulnerability_assessment']['risk_category']}
- **Confidence Level**: {report['ai_vulnerability_assessment']['confidence_level']}

## 🔍 Detailed Analysis
### Static Analysis Findings
{chr(10).join(
    f"- {f.get('check','N/A')} | Impact: {f.get('impact','N/A')} | Confidence: {f.get('confidence','N/A')} | {f.get('description','')}"
    for f in report['security_features']['static_analysis'].get('slither_detectors', [])
)}

### AI-Detected Vulnerability Patterns
{chr(10).join(f"- {pattern}" for pattern in report['security_features']['static_analysis'].get('vulnerability_flags', []))}

### Confidence Levels
- **Static Analysis Confidence**: {report['ai_vulnerability_assessment']['confidence_level']}

## 📊 Heuristic Breakdown
### Point-Based Risk Assessment
{chr(10).join(f"- {risk_type}: {score}" for risk_type, score in report.get('detailed_risk_breakdown', {}).items())}

## 🛡️ Remediation Suggestions
### Immediate Actions
{chr(10).join(f"- {action}" for action in report['recommendations']['immediate_actions'])}

### Long-Term Improvements
{chr(10).join(f"- {improvement}" for improvement in report['recommendations']['long_term_improvements'])}
"""
        return markdown_report

def _sha256_bytes(b: bytes) -> str:
    return 'sha256:' + hashlib.sha256(b).hexdigest()


def fetch_source_code_from_etherscan_v1(contract_address: str, api_key: str, chainid: int = 1) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Fallback to Etherscan V1 API if V2 response is unexpected."""
    url = (
        f"https://api.etherscan.io/api?module=contract&action=getsourcecode"
        f"&address={contract_address}&apikey={api_key}"
    )
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if str(data.get('status')) == '1' and str(data.get('message')).upper() == 'OK':
        result = data.get('result')
        if isinstance(result, list) and result and isinstance(result[0], dict):
            prov = {
                "etherscan_endpoint": url,
                "response_hash": _sha256_bytes(resp.content),
                "verification_status": 'Verified' if result[0].get('SourceCode') else 'Unverified',
            }
            return result[0], prov
    raise ValueError(f"Etherscan V1 error: {data}")


def fetch_source_code_from_etherscan(contract_address: str, api_key: str, chainid: int = 1) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Fetch the contract source code from Etherscan V2 API.
    Returns a single result dict containing SourceCode, ContractName, CompilerVersion, etc.
    """
    url = (
        f"https://api.etherscan.io/v2/api?module=contract&action=getsourcecode"
        f"&address={contract_address}&chainid={chainid}&apikey={api_key}"
    )
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()

    if str(data.get('status')) == '1' and str(data.get('message')).upper() == 'OK':
        result = data.get('result')
        # V2 commonly returns a dict; some responses may still return a single-item list
        if isinstance(result, dict):
            prov = {
                "etherscan_endpoint": url,
                "response_hash": _sha256_bytes(response.content),
                "verification_status": 'Verified' if result.get('SourceCode') else 'Unverified',
            }
            return result, prov
        if isinstance(result, list) and result and isinstance(result[0], dict):
            first = result[0]
            prov = {
                "etherscan_endpoint": url,
                "response_hash": _sha256_bytes(response.content),
                "verification_status": 'Verified' if first.get('SourceCode') else 'Unverified',
            }
            return first, prov
        raise ValueError(
            f"Unexpected Etherscan result payload shape: {type(result).__name__}"
        )
    else:
        # Try V1 fallback
        try:
            return fetch_source_code_from_etherscan_v1(contract_address, api_key, chainid)
        except Exception:
            raise ValueError(
                f"Error fetching source code for contract {contract_address}: {data.get('result', 'Unknown error')}"
            )

def _get_slither_version() -> str:
    try:
        import slither
        return getattr(slither, "__version__", "unknown")
    except Exception:
        return "unknown"


def _get_solc_version() -> str:
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


def generate_contract_report(contract_address: str, api_key: str, output_directory: str, chainid: int = 1):
    """
    Convenience function to generate a full contract report
    
    Args:
        contract_address (str): Ethereum contract address
        api_key (str): Etherscan API key
        chainid (int): EVM chain ID (default 1)
    """
    # Fetch contract source code from Etherscan (provenance-aware)
    fetch_started = datetime.now()
    src_data, src_prov = fetch_source_code_from_etherscan(contract_address, api_key, chainid)
    # Proxy resolution: analyze implementation if present
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
            # Merge/override source provenance with implementation fetch
            src_prov = impl_prov
        except Exception as e:
            logger.warning("Failed to resolve implementation source: %s", e)

    # Debug print to check the received source code data
    # print(f"[DEBUG] Received source code data: {source_code_data}")
    
    report_generator = ZauriScoreReportGenerator()
    report = report_generator.generate_comprehensive_report(
        analysis_target_address, 
        analysis_source_data
    )
    fetch_finished = datetime.now()
    duration = (fetch_finished - fetch_started).total_seconds()

    # Export JSON report
    json_report = report_generator.export_report(report, 'json')
    
    # Export Markdown report
    markdown_report = report_generator.export_report(report, 'markdown')
    
    # Ensure output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Create secure filenames
    safe_contract_address = secure_filename(contract_address)
    json_filename = f"{safe_contract_address}_report.json"
    md_filename = f"{safe_contract_address}_report.md"
    
    report_path_json = os.path.join(output_directory, json_filename)
    report_path_md = os.path.join(output_directory, md_filename)
    
    # Save reports to the specified directory
    with open(report_path_json, 'w', encoding='utf-8') as f:
        f.write(json_report)  # json_report is already a string here
    with open(report_path_md, 'w', encoding='utf-8') as f:
        f.write(markdown_report)  # markdown_report is also a string
    
    # Enrich saved JSON with provenance, proxy resolution, and decision summary and rewrite JSON file
    try:
        with open(report_path_json, 'r', encoding='utf-8') as f:
            saved = json.load(f)

        # provenance
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

        # proxy_resolution
        saved['proxy_resolution'] = proxy_info

        # decision_summary (simple heuristic)
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
            json.dump(saved, f, indent=2, default=json_numpy_serializer)
    except Exception as e:
        logger.warning('Failed to enrich report with provenance/summary: %s', e)

    logger.info("Reports generated for contract %s in %s", contract_address, output_directory)
    return report_path_json, report_path_md

def generate_report(
    data: Dict[str, Any], 
    output_path: Optional[str] = None, 
    format: str = 'json'
) -> Union[Dict, str, bytes]:
    """Generate a report from the given data in the specified format.
    
    Args:
        data: Data to include in the report
        output_path: Path to save the report (optional)
        format: Output format ('json', 'markdown', or 'pdf')
        
    Returns:
        The generated report in the requested format. If output_path is provided,
        returns the path to the saved file. Otherwise, returns the report content.
    """
    # Create appropriate exporter
    if format.lower() == 'json':
        exporter = JSONExporter()
    elif format.lower() == 'markdown':
        exporter = MarkdownExporter()
    elif format.lower() == 'pdf':
        exporter = PDFExporter()
    else:
        raise ValueError(f"Unsupported format: {format}")
    
    # Ensure output file has correct extension if path is provided
    if output_path:
        base_path = os.path.splitext(output_path)[0]
        if format == 'pdf':
            output_path = f"{base_path}.pdf"
        elif format == 'markdown':
            output_path = f"{base_path}.md"
        elif format == 'json':
            output_path = f"{base_path}.json"
    
    # Generate and return the report
    return exporter.export(data, output_path)

if __name__ == "__main__":
    # Example contract address (you can replace this with any valid Ethereum contract address)
    contract_address = "0x6b175474e89094c44da98b954eedeac495271d0f"  # Example: DAI contract
    
    # Get the Etherscan API key from the environment variables
    api_key = os.getenv("ETHERSCAN_API_KEY")
    
    if not api_key:
        print("Error: Etherscan API key not found in the .env file.")
    else:
        # Call the generate_contract_report function with the contract address, api_key, and an example output directory
        # Construct 'reports' directory relative to this script's location for the example
        script_dir = os.path.dirname(os.path.abspath(__file__))
        example_reports_dir = os.path.join(script_dir, '..', 'reports') # Assumes reports dir is one level up
        generate_contract_report(contract_address, api_key, example_reports_dir)