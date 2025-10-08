# Lazy imports for performance
_torch = None
_transformers = None
_requests = None
_numpy = None

def _get_torch():
    global _torch
    if _torch is None:
        import torch
        _torch = torch
    return _torch

def _get_transformers():
    global _transformers
    if _transformers is None:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        _transformers = (AutoTokenizer, AutoModelForSequenceClassification)
    return _transformers

def _get_requests():
    global _requests
    if _requests is None:
        import requests
        _requests = requests
    return _requests

def _get_numpy():
    global _numpy
    if _numpy is None:
        import numpy as np
        _numpy = np
    return _numpy

# Core lightweight imports (keep these)
import sys
import json
import logging
import os
import tempfile
from typing import Dict, Any, Optional, List, Tuple, Union, cast
from pathlib import Path
from .slither_utils import SlitherUtils
from dotenv import load_dotenv
import re
from datetime import datetime

# Import our analyzers
from .code_similarity import CodeSimilarityAnalyzer
from .gas_optimization_analyzer import GasOptimizationAnalyzer
from .mythril_analyzer import MythrilAnalyzer

# Load environment variables once at module level
load_dotenv()

# Configure logging
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'zauriscore.log')
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler()
    ]
)

class ComprehensiveContractAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._codebert_tokenizer = None
        self._codebert_model = None
        self.temp_dir = None
        self.temp_file = None
        # Load environment variables
        self.etherscan_api_key = os.getenv('ETHERSCAN_API_KEY')

        # Load environment variables from .env file
        try:
            self.etherscan_api_key = os.getenv('ETHERSCAN_API_KEY')
            if self.etherscan_api_key and self.etherscan_api_key.strip():
                # Basic validation - just check if it's not empty after stripping
                self.etherscan_api_key = self.etherscan_api_key.strip()
                self.logger.info("Etherscan API key loaded successfully")
            else:
                self.etherscan_api_key = None
                self.logger.warning("ETHERSCAN_API_KEY not set - API key dependent features will be unavailable")
        except Exception as e:
            self.etherscan_api_key = None
            self.logger.warning(f"Warning loading API key: {e}")
            self.logger.info("Continuing without API key - some features may be limited")

        # Initialize our analyzers
        self.gas_optimizer = GasOptimizationAnalyzer()
        self.mythril_analyzer = MythrilAnalyzer()

        self.chain_ids = {
            'ethereum': 1,
            'polygon': 137,
            'arbitrum': 42161,
            'optimism': 10
        }
        self.api_bases = {
            'ethereum': 'https://api.etherscan.io',
            'polygon': 'https://api.polygonscan.com',
            'arbitrum': 'https://api.arbiscan.io',
            'optimism': 'https://api-optimistic.etherscan.io'
        }
        self.api_keys = {
            'ethereum': self.etherscan_api_key,
            'polygon': os.getenv('POLYGONSCAN_API_KEY'),
            'arbitrum': os.getenv('ARBISCAN_API_KEY'),
            'optimism': os.getenv('OPTIMISM_ETHERSCAN_API_KEY')
        }
        self._load_codebert()
        self.slither_utils = SlitherUtils()
        self.slither = None  # Will be initialized when needed

    def _load_codebert(self):
        """Load CodeBERT model with proper device handling."""
        try:
            if self._codebert_tokenizer is None or self._codebert_model is None:
                # Use lazy imports
                torch = _get_torch()
                AutoTokenizer, AutoModelForSequenceClassification = _get_transformers()

                # Suppress warnings about uninitialized weights
                import warnings
                import logging as python_logging

                # Suppress transformers warnings
                python_logging.getLogger("transformers.modeling_utils").setLevel(python_logging.WARNING)

                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", message=".*Some weights of.*were not initialized.*")

                    # Load tokenizer and model
                    self._codebert_tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')

                    # Use AutoModel and add classification head for proper binary classification
                    from transformers import AutoModel
                    base_model = AutoModel.from_pretrained('microsoft/codebert-base')

                    # Add classification head
                    class CodeBERTClassifier(torch.nn.Module):
                        def __init__(self, base_model):
                            super().__init__()
                            self.base_model = base_model
                            self.classifier = torch.nn.Linear(base_model.config.hidden_size, 2)  # Binary classification

                        def forward(self, input_ids, attention_mask=None):
                            outputs = self.base_model(input_ids=input_ids, attention_mask=attention_mask)
                            pooled_output = outputs.pooler_output
                            return self.classifier(pooled_output)

                    self._codebert_model = CodeBERTClassifier(base_model)

                    # Move to appropriate device
                    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                    self._codebert_model.to(device)
                    self._device = device

                self.logger.info(f"CodeBERT model and tokenizer loaded successfully on device: {self._device}")
        except Exception as e:
            self.logger.error(f"Failed to load CodeBERT model/tokenizer: {e}")
            self._codebert_tokenizer = None
            self._codebert_model = None
            self._device = None

    def _run_codebert_analysis(self, source_code: str) -> Dict[str, Any]:
        """Run CodeBERT analysis on the source code."""
        if not self._codebert_model or not self._codebert_tokenizer:
            self._load_codebert()

        try:
            # Use lazy imports
            torch = _get_torch()

            # Preprocess the code
            source_code = source_code.strip()
            if not source_code:
                return {'error': 'Empty source code'}

            # Truncate based on tokenizer max length instead of character count
            if not self._codebert_tokenizer:
                raise RuntimeError("CodeBERT tokenizer not available")

            # Tokenize to check length
            tokens = self._codebert_tokenizer.tokenize(source_code)
            if len(tokens) > 512:
                self.logger.warning(f"Input sequence truncated from {len(tokens)} to 512 tokens")
                # Truncate tokens instead of characters for better accuracy
                source_code = self._codebert_tokenizer.convert_tokens_to_string(tokens[:512])

            # Tokenize and encode
            inputs = self._codebert_tokenizer(
                source_code,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt"
            )

            # Move to device if available
            if self._device:
                inputs = {k: v.to(self._device) for k, v in inputs.items()}

            # Get model predictions
            if not self._codebert_model:
                raise RuntimeError("CodeBERT model not available")

            with torch.no_grad():
                outputs = self._codebert_model(**inputs)
                logits = outputs

            # Get predicted class and confidence scores
            predicted_class = torch.argmax(logits, dim=1).item()
            confidence_scores = torch.softmax(logits, dim=1).tolist()[0]

            # Return analysis results
            return {
                'predicted_class': predicted_class,
                'confidence_scores': confidence_scores,
                'analysis_timestamp': datetime.now().isoformat(),
                'source_code_length': len(source_code),
                'token_count': len(self._codebert_tokenizer.tokenize(source_code)) if self._codebert_tokenizer else 0
            }

        except Exception as e:
            self.logger.error(f"Error in CodeBERT analysis: {e}")
            return {'error': str(e)}

    def _generate_summary(self, results: Dict[str, Any]) -> None:
        """Generate a summary of the analysis results with enhanced NLG explanations."""
        # Calculate total issues
        results['summary']['total_issues'] = sum(
            results['static_analysis']['summary'].values()
        )

        # Determine security risk level
        high_issues = results['static_analysis']['summary']['high']
        medium_issues = results['static_analysis']['summary']['medium']
        
        if high_issues > 0:
            results['summary']['security_risk'] = 'High'
        elif medium_issues > 0:
            results['summary']['security_risk'] = 'Medium'
        else:
            results['summary']['security_risk'] = 'Low'

        # Determine gas efficiency
        if results['gas_optimization']['estimated_savings'] > 100000:
            results['summary']['gas_efficiency'] = 'Poor'
        elif results['gas_optimization']['estimated_savings'] > 50000:
            results['summary']['gas_efficiency'] = 'Fair'
        else:
            results['summary']['gas_efficiency'] = 'Good'

        # Vulnerability explanations mapping
        vuln_explanations = {
            'reentrancy': 'Reentrancy attacks occur when external calls are made before state changes, allowing attackers to drain funds multiple times. Fix by following checks-effects-interactions pattern.',
            'integer_overflow': 'Integer overflow/underflow can manipulate values beyond expected ranges, leading to incorrect calculations. Use SafeMath library or Solidity 0.8+.',
            'unchecked_low_level': 'Unchecked low-level calls (e.g., call(), send()) can fail silently, ignoring return values and potentially leading to loss of funds. Always check return values.',
            'timestamp_dependency': 'Using block.timestamp for randomness or time-sensitive logic can be manipulated by miners. Use stronger randomness sources like Chainlink VRF.',
            'short_address_attack': 'Short address attacks exploit poor address validation in abi.decode. Ensure fixed-size decoding or validation checks.',
            'access_control': 'Missing access control allows unauthorized users to call sensitive functions. Use modifiers like onlyOwner.',
            'arbitrary_jump': 'Arbitrary jump vulnerabilities allow control flow hijacking via unchecked assembly or jumps. Avoid unchecked assembly.',
            'tx_origin_phishing': 'Using tx.origin for authentication is insecure as it can be manipulated by phishing contracts. Use msg.sender instead.'
        }

        # Generate plain-language vulnerability explanations
        explanations = []
        detectors = results['static_analysis'].get('detectors', [])
        for detector in detectors:
            vuln_type = detector.get('check', 'unknown').lower()
            explanation = vuln_explanations.get(vuln_type, f'Vulnerability detected: {vuln_type}. Review the code for security issues.')
            explanations.append({
                'type': vuln_type,
                'impact': detector.get('impact', 'Unknown'),
                'explanation': explanation,
                'confidence': detector.get('confidence', 'Medium'),
                'line': detector.get('impact_contracts', [{}])[0].get('source_line', 'N/A')
            })
        results['summary']['vulnerability_explanations'] = explanations

        # Risk score interpretation
        if 'trust_risk_scoring' in results:
            risk_score = results['trust_risk_scoring']['risk_score']
            reputation_index = results['trust_risk_scoring']['reputation_index']
            if risk_score > 80:
                risk_interp = 'Very High Risk: This contract has significant security, optimization, and/or historical concerns. Immediate remediation required before deployment.'
            elif risk_score > 50:
                risk_interp = 'Moderate Risk: Potential issues identified; thorough audit recommended.'
            else:
                risk_interp = 'Low Risk: Generally secure, but continued monitoring advised.'
            results['summary']['risk_interpretation'] = {
                'risk_score': risk_score,
                'reputation_index': reputation_index,
                'interpretation': risk_interp,
                'advice': 'Consider professional audit for production use.'
            }

        # Detailed optimization suggestions
        gas_opps = results['gas_optimization'].get('opportunities', [])
        opt_suggestions = []
        for opp in gas_opps:
            opt_suggestions.append({
                'description': opp.get('description', 'Optimization opportunity'),
                'estimated_gas_savings': opp.get('estimated_savings', 0),
                'code_location': opp.get('line', 'N/A'),
                'suggestion': opp.get('suggestion', 'Review and refactor code as per Slither guidance.')
            })
        if 'gas_optimization' in results:
            results['summary']['optimization_suggestions'] = {
                'total_opportunities': len(opt_suggestions),
                'estimated_total_savings': results['gas_optimization'].get('estimated_savings', 0),
                'suggestions': opt_suggestions
            }

        # Threshold-based alerts
        alerts = []
        if high_issues > 0:
            alerts.append('ALERT: High-severity vulnerabilities detected!')
        if results.get('ml_score', 0) > 5:
            alerts.append('ALERT: ML model flags potential vulnerabilities.')
        if results.get('overall_score', 0) > 6:
            alerts.append('ALERT: Overall score indicates risks.')
        if 'trust_risk_scoring' in results and results['trust_risk_scoring']['risk_score'] > 70:
            alerts.append('CRITICAL ALERT: High risk score - deployment not recommended.')
        results['summary']['alerts'] = alerts

        # Consolidated plain-language report
        plain_report = [
            f"## Smart Contract Analysis Report",
            f"### Contract Overview",
            f"- Name: {results.get('contract_name', 'Unknown')}",
            f"- Address: {results.get('contract_address', 'N/A')}",
            f"- Security Risk Level: {results['summary']['security_risk']}",
            f"- Total Issues: {results['summary']['total_issues']}",
            f"- Gas Efficiency: {results['summary'].get('gas_efficiency', 'Unknown')}",
            f"### Risk Assessment",
            f"- Overall Score: {results.get('overall_score', 0):.2f}/10 (higher = riskier)",
            f"- ML Score: {results.get('ml_score', 0):.2f}/10",
            f"- Slither Score: {results.get('slither_score', 0):.2f}/10",
            f"- Mythril Score: {results.get('mythril_score', 0):.2f}/10",
        ]
        if 'trust_risk_scoring' in results:
            plain_report.extend([
                f"- Risk Score: {results['trust_risk_scoring']['risk_score']}/100",
                f"- Reputation Index: {results['trust_risk_scoring']['reputation_index']}/100",
                f"{results['summary']['risk_interpretation']['interpretation']}",
            ])
        plain_report.extend([
            f"### Key Findings",
            f"- High Severity: {high_issues}",
            f"- Medium Severity: {medium_issues}",
            f"- Gas Savings Potential: ~{results['gas_optimization'].get('estimated_savings', 0)} gas",
        ])
        if explanations:
            plain_report.append("### Vulnerability Explanations")
            for exp in explanations[:5]:  # Limit to top 5
                plain_report.append(f"- {exp['type'].title()}: {exp['explanation'][:100]}... (Line: {exp['line']})")
        if opt_suggestions:
            plain_report.append("### Optimization Suggestions")
            for sug in opt_suggestions[:3]:
                plain_report.append(f"- {sug['description']}: Savings ~{sug['estimated_gas_savings']} gas (Line: {sug['code_location']})")
        if alerts:
            plain_report.append("### Alerts")
            plain_report.extend([f"- {alert}" for alert in alerts])
        plain_report.append("### Recommendations")
        recommendations = results['summary'].get('recommendations', ["No specific recommendations at this time."])
        if isinstance(recommendations, list):
            plain_report.extend(recommendations if recommendations else ["No specific recommendations at this time."])
        else:
            plain_report.append(str(recommendations))
        results['summary']['plain_language_report'] = '\n'.join(str(item) for item in plain_report if item)

        # Generate recommendations (enhanced legacy for backward compatibility)
        # Merge with existing recommendations instead of overwriting
        existing_recommendations = results['summary'].get('recommendations', [])
        if isinstance(existing_recommendations, list):
            recommendations = existing_recommendations.copy()
        else:
            recommendations = []

        # Add security recommendations
        if high_issues > 0:
            recommendations.append("Critical security issues detected. Immediate review required.")
        if medium_issues > 0:
            recommendations.append("Medium severity issues found. Review and fix recommended.")

        # Add gas optimization recommendations
        if results['gas_optimization']['estimated_savings'] > 0:
            recommendations.append(f"Gas optimization opportunities found. Estimated savings: ~{results['gas_optimization']['estimated_savings']} gas")

        # Add ML analysis recommendations
        if results['ml_analysis'].get('predicted_class') == 1:
            confidence = results['ml_analysis'].get('confidence_scores', [0, 0])[1]
            if confidence > 0.7:
                recommendations.append("ML model detected potential vulnerabilities. Review ML analysis results.")

        # Add risk-based recommendations
        if 'trust_risk_scoring' in results:
            risk_score = results['trust_risk_scoring']['risk_score']
            if risk_score > 80:
                recommendations.append("CRITICAL: High risk score. Do not deploy without fixes.")
            elif risk_score > 50:
                recommendations.append("WARNING: Moderate risk. Review thoroughly.")
            else:
                recommendations.append("SAFE: Low risk score. Suitable for deployment.")

        results['summary']['recommendations'] = recommendations

    def _extract_features(self, contract):
        """Extract detailed features from the contract AST using Slither."""
        return self.slither_utils.extract_features(contract)

    def analyze_contract(self, contract_address: Optional[str] = None, source_code: Optional[str] = None, chain: str = 'ethereum') -> Dict[str, Any]:
        results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'contract_address': contract_address,
            'chain': chain,
            'contract_name': 'Unknown',
            'compiler_version': 'Unknown',
            'optimization_used': 'Unknown',
            'runs': 0,
            'static_analysis': {
                'detectors': [],
                'summary': {
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'informational': 0
                }
            },
            'pattern_analysis': {
                'patterns': [],
                'matches': 0
            },
            'ml_analysis': {
                'predicted_class': None,
                'confidence_scores': [],
                'source_code_length': 0,
                'token_count': 0
            },
            'gas_optimization': {
                'opportunities': [],
                'estimated_savings': 0
            },
            'summary': {
                'total_issues': 0,
                'security_risk': 'Unknown',
                'gas_efficiency': 'Unknown',
                'recommendations': []
            }
        }

        # Prepare source code and filesystem layout
        try:
            if source_code is None and contract_address:
                # Get source code from chain explorer
                try:
                    contract_data = self.get_contract_source(contract_address, chain)
                    if contract_data.get('status') == '1':
                        item = contract_data['result'][0]
                        source_code = item.get('SourceCode', '')
                        # Add contract metadata to results
                        results.update({
                            'contract_name': item.get('ContractName', 'Unknown'),
                            'compiler_version': item.get('CompilerVersion', 'Unknown'),
                            'optimization_used': item.get('OptimizationUsed', 'Unknown'),
                            'runs': item.get('Runs', 0)
                        })
                except Exception as e:
                    self.logger.error(f"Failed to fetch contract source code: {e}")
                    return {'error': f'Failed to fetch contract source code: {str(e)}'}

                # Fetch historical data if address provided
                try:
                    tx_count = self.get_transaction_count(contract_address, chain)
                    results['historical_data'] = {'transaction_count': tx_count, 'chain': chain}
                except Exception as e:
                    self.logger.warning(f"Failed to fetch transaction count: {e}")
                    results['historical_data'] = {'transaction_count': 0, 'chain': chain}

            elif source_code:
                # For direct source code analysis
                results.update({
                    'contract_name': 'TestContract',
                    'compiler_version': 'Unknown',
                    'optimization_used': 'Unknown',
                    'runs': 0
                })
                if contract_address:
                    try:
                        tx_count = self.get_transaction_count(contract_address, chain)
                        results['historical_data'] = {'transaction_count': tx_count, 'chain': chain}
                    except Exception as e:
                        self.logger.warning(f"Failed to fetch transaction count: {e}")
                        results['historical_data'] = {'transaction_count': 0, 'chain': chain}
                else:
                    results['historical_data'] = {'transaction_count': 0, 'chain': chain}

            # Store the original source code in results for display
            results['source_code'] = source_code

            # Directory to place temporary contract files
            try:
                # Use system temp directory for better portability
                import tempfile
                base_temp_dir = os.path.join(tempfile.gettempdir(), 'zauriscore_contracts')
                os.makedirs(base_temp_dir, exist_ok=True)
                temp_dir = base_temp_dir

                # Default main file path
                import time
                main_file = os.path.join(temp_dir, f'Contract_{int(time.time())}.sol')

                # Normalize Etherscan quirks: double-braced JSON and escaped newlines
                sc = (source_code or '').strip()
                # If JSON wrapped in extra braces {{ ... }}, strip one layer
                if (sc.startswith("{{") and sc.endswith("}}")) or (sc.startswith("{\n{") and sc.rstrip().endswith("}\n}")):
                    sc = sc[1:-1]

                # Attempt to parse as JSON (multi-file format)
                parsed = None
                try:
                    parsed = json.loads(sc)
                except json.JSONDecodeError:
                    # Try to recover: extract inner JSON object if Etherscan wrapped it
                    try:
                        # Look for a common key indicating the JSON contract wrapper
                        key_idx = sc.find('"language"')
                        if key_idx != -1:
                            # find the opening brace before the key and the last closing brace
                            start_idx = sc.rfind('{', 0, key_idx)
                            end_idx = sc.rfind('}')
                            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                                candidate = sc[start_idx:end_idx+1]
                                parsed = json.loads(candidate)
                        # Fallback: try decoding escaped sequences and parse again
                        if parsed is None:
                            try:
                                alt = bytes(sc, 'utf-8').decode('unicode_escape')
                                parsed = json.loads(alt)
                            except Exception:
                                parsed = None
                    except Exception:
                        parsed = None

                if isinstance(parsed, dict) and 'sources' in parsed:
                    # Write each source file for completeness
                    concatenated = []
                    for rel_path, file_data in parsed['sources'].items():
                        try:
                            norm_path = os.path.normpath(rel_path)
                            full_path = os.path.join(temp_dir, norm_path)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            content = file_data.get('content', '')
                            with open(full_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                            # Collect content to create a flattened main file for Slither
                            # Remove SPDX license lines to avoid multiple SPDX identifiers in a single concatenated file
                            cleaned_lines = []
                            for line in content.splitlines():
                                if line.strip().startswith('// SPDX-License-Identifier:') or line.strip().startswith('/* SPDX-License-Identifier:'):
                                    # Skip SPDX lines in concatenation; keep file-level license handling flexible
                                    continue
                                cleaned_lines.append(line)
                            concatenated.append(f"// File: {rel_path}\n" + '\n'.join(cleaned_lines))
                        except Exception as e:
                            self.logger.warning(f"Error processing source file {rel_path}: {e}")
                            continue

                    # Create a flattened main file that concatenates all sources. Slither expects a file
                    try:
                        with open(main_file, 'w', encoding='utf-8') as mf:
                            mf.write('\n\n'.join(concatenated))
                        source_path = main_file
                    except Exception as e:
                        self.logger.error(f"Error creating concatenated file: {e}")
                        # Fallback to directory if flattening failed
                        source_path = temp_dir
                elif isinstance(parsed, dict) and parsed.get('content'):
                    # Single-file JSON with 'content'
                    try:
                        with open(main_file, 'w', encoding='utf-8') as f:
                            f.write(parsed.get('content', source_code))
                        source_path = main_file
                    except Exception as e:
                        self.logger.error(f"Error writing single-file contract: {e}")
                        return {'error': f'Error writing contract file: {str(e)}'}
                else:
                    # Not JSON; treat as raw solidity source but unescape if needed
                    try:
                        # If the string includes escaped newlines like \r\n or \n, unescape them
                        if "\\n" in sc or "\\r\\n" in sc:
                            sc = bytes(sc, 'utf-8').decode('unicode_escape')
                    except Exception as e:
                        self.logger.warning(f"Error unescaping source code: {e}")

                    try:
                        with open(main_file, 'w', encoding='utf-8') as f:
                            f.write(sc)
                        source_path = main_file
                    except Exception as e:
                        self.logger.error(f"Error writing raw contract file: {e}")
                        return {'error': f'Error writing contract file: {str(e)}'}

            except Exception as e:
                self.logger.error(f"Error setting up temporary files: {e}")
                return {'error': f'Error setting up temporary files: {str(e)}'}

        except Exception as e:
            self.logger.error(f"Error preparing source code: {e}")
            return {'error': f'Error preparing source code: {str(e)}'}
            
        # Initialize Slither with the source code
        slither = None
        try:
            slither = self.slither_utils.init_slither(source_path)

            # Update contract metadata
            if slither and getattr(slither, 'contracts', None):
                contract = slither.contracts[0]
                results['contract_name'] = contract.name
                try:
                    # Try to get compiler information
                    cu = getattr(contract, 'compilation_unit', None)
                    if cu is not None:
                        results['compiler_version'] = getattr(cu, 'compiler_version', 'Unknown')
                        results['optimization_used'] = getattr(cu, 'compiler_optimization', getattr(cu, 'compiler_optimization_used', 'Unknown'))
                        results['runs'] = getattr(cu, 'compiler_runs', getattr(cu, 'runs', 0))
                    else:
                        results['compiler_version'] = 'Unknown'
                        results['optimization_used'] = 'Unknown'
                        results['runs'] = 0
                except AttributeError:
                    # Fallback if newer Slither API
                    results['compiler_version'] = 'Unknown'
                    results['optimization_used'] = 'Unknown'
                    results['runs'] = 0

                # Detect proxy patterns and upgradeability
                try:
                    results['upgradeable_analysis'] = {
                        'is_proxy': False,
                        'proxy_type': 'None',
                        'upgrade_safety_score': 10.0,  # Default safe
                        'storage_collision_risk': False,
                        'issues': []
                    }

                    if getattr(contract, 'is_proxy', False):
                        results['upgradeable_analysis']['is_proxy'] = True
                        results['upgradeable_analysis']['proxy_type'] = 'UUPS or Transparent'  # Initial general detection
                        results['upgradeable_analysis']['upgrade_safety_score'] -= 3.0  # Base penalty for proxies

                        # Check for Transparent Proxy specific issues
                        transparent_detector = None
                        if hasattr(slither, 'register_detector'):
                            try:
                                slither_any = cast(Any, slither)
                                transparent_detector = slither_any.register_detector('TransparentProxyAdminNoControl')
                            except Exception:
                                transparent_detector = None
                        if transparent_detector:
                            try:
                                transparent_issues = transparent_detector.detect()
                            except Exception:
                                transparent_issues = []
                            if transparent_issues:
                                results['upgradeable_analysis']['proxy_type'] = 'Transparent'
                                results['upgradeable_analysis']['issues'].extend([{
                                    'title': issue.title,
                                    'description': issue.description,
                                    'severity': 'High',
                                    'lines': issue.lines
                                } for issue in transparent_issues])
                                results['upgradeable_analysis']['upgrade_safety_score'] -= 3.0 * len(transparent_issues)

                        # Check for UUPS Proxy specific issues
                        uups_detector = None
                        if hasattr(slither, 'register_detector'):
                            try:
                                slither_any = cast(Any, slither)
                                uups_detector = slither_any.register_detector('UUPSChildAdminRights')
                            except Exception:
                                uups_detector = None
                        if uups_detector:
                            try:
                                uups_issues = uups_detector.detect()
                            except Exception:
                                uups_issues = []
                            if uups_issues:
                                results['upgradeable_analysis']['proxy_type'] = 'UUPS'
                                results['upgradeable_analysis']['issues'].extend([{
                                    'title': issue.title,
                                    'description': issue.description,
                                    'severity': 'High',
                                    'lines': issue.lines
                                } for issue in uups_issues])
                                results['upgradeable_analysis']['upgrade_safety_score'] -= 3.0 * len(uups_issues)

                        # Additional check for storage layout issues (simplified)
                        if len(contract.state_variables) > 10:  # Heuristic for complexity
                            results['upgradeable_analysis']['storage_collision_risk'] = True
                            results['upgradeable_analysis']['issues'].append({
                                'title': 'Potential Storage Collision Risk',
                                'description': 'Proxy contracts with many state variables may risk slot collisions during upgrades.',
                                'severity': 'Medium',
                                'lines': []
                            })
                            results['upgradeable_analysis']['upgrade_safety_score'] -= 2.0

                    # Clamp score
                    results['upgradeable_analysis']['upgrade_safety_score'] = max(0.0, min(10.0, results['upgradeable_analysis']['upgrade_safety_score']))

                    # Extract features for preprocessing
                    preprocessing_features = self._extract_features(contract)
                    results['preprocessing'] = preprocessing_features

                    # Expand tokenization with feature metadata in ML analysis
                    if 'ml_analysis' in results and not results['ml_analysis'].get('error'):
                        results['ml_analysis']['features_extracted'] = {
                            'num_functions': len(preprocessing_features['functions']),
                            'num_state_vars': len(preprocessing_features['state_variables']),
                            'num_modifiers': len(preprocessing_features['modifiers']),
                            'num_loops': preprocessing_features['loops']
                        }

                except Exception as e:
                    self.logger.error(f"Error in contract analysis: {e}")
                    results['upgradeable_analysis'] = {
                        'is_proxy': False,
                        'proxy_type': 'None',
                        'upgrade_safety_score': 10.0,
                        'storage_collision_risk': False,
                        'issues': []
                    }

                # Analyze gas optimization
                try:
                    gas_results = self.gas_optimizer.analyze(contract)
                    results['gas_optimization']['opportunities'] = gas_results
                    # Calculate actual gas savings from optimization opportunities
                    total_savings = 0
                    for opp in gas_results:
                        saving_str = opp.get('saving', '0')
                        # Extract numeric value from saving string (e.g., "~20000 gas per slot saved" -> 20000)
                        import re
                        gas_match = re.search(r'~?(\d+)', saving_str)
                        if gas_match:
                            total_savings += int(gas_match.group(1))

                    results['gas_optimization']['estimated_savings'] = total_savings
                except Exception as e:
                    self.logger.error(f"Error in gas optimization analysis: {e}")
                    results['gas_optimization']['opportunities'] = []
                    results['gas_optimization']['estimated_savings'] = 0

                # Run Slither detectors
                try:
                    static_issues = self.slither_utils.run_slither_detectors(self.slither)
                    for issue_dict in static_issues:
                        try:
                            impact_str = issue_dict.get('impact', 'LOW')
                            severity_lower = impact_str.lower()
                            if severity_lower in results['static_analysis']['summary']:
                                results['static_analysis']['summary'][severity_lower] += 1
                            results['static_analysis']['detectors'].append({
                                'title': issue_dict.get('title', 'Unknown'),
                                'description': issue_dict.get('description', ''),
                                'severity': impact_str.title(),
                                'impact': impact_str,
                                'confidence': issue_dict.get('confidence', 'MEDIUM'),
                                'lines': issue_dict.get('lines', [])
                            })
                        except Exception as e:
                            self.logger.error(f"Error processing detector issue: {e}")
                            continue
                except Exception as e:
                    self.logger.error(f"Error running Slither detectors: {e}")
                    results['static_analysis']['detectors'] = []
                    results['static_analysis']['summary'] = {'high': 0, 'medium': 0, 'low': 0, 'informational': 0}

        except Exception as e:
            # Don't abort the entire analysis if Slither/solc is not available.
            # Log the error and continue with other analyses (ML, Mythril).
            self.logger.error(f"Error initializing Slither or analyzing contract: {e}")
            slither = None
            # Ensure static analysis fields remain present but empty
            results['static_analysis']['detectors'] = []
            results['static_analysis']['summary'] = {'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
            results['gas_optimization']['opportunities'] = []
            results['gas_optimization']['estimated_savings'] = 0
            results['upgradeable_analysis'] = {
                'is_proxy': False,
                'proxy_type': 'None',
                'upgrade_safety_score': 10.0,
                'storage_collision_risk': False,
                'issues': []
            }
            # Continue execution (do not return)

                # Run CodeBERT analysis
        try:
            ml_results = self._run_codebert_analysis(source_code or "")
            results['ml_analysis'] = ml_results

            # Compute ml_score (0-10, higher more vulnerable)
            if ml_results.get('predicted_class') == 1:
                ml_confidence = ml_results.get('confidence_scores', [0, 0])[1]
                ml_score = ml_confidence * 10
            else:
                ml_score = 0.0
            results['ml_score'] = round(ml_score, 2)
        except Exception as e:
            self.logger.error(f"Error in ML analysis: {e}")
            results['ml_analysis'] = {'error': str(e)}
            results['ml_score'] = 0.0

        # Run Mythril analysis
        try:
            mythril_results = self.mythril_analyzer.analyze(source_path)
            results['mythril_analysis'] = mythril_results
            mythril_score = mythril_results.get('score', 0.0)
            results['mythril_score'] = round(mythril_score, 2)
        except Exception as e:
            self.logger.error(f"Error in Mythril analysis: {e}")
            results['mythril_analysis'] = {'error': str(e)}
            results['mythril_score'] = 0.0

        # Compute slither_score based on severity counts (after Slither analysis)
        slither_summary = results['static_analysis']['summary']
        slither_score = (
            slither_summary.get('high', 0) * 4.0 +
            slither_summary.get('medium', 0) * 2.0 +
            slither_summary.get('low', 0) * 0.5 +
            slither_summary.get('informational', 0) * 0.1
        )
        results['slither_score'] = round(slither_score, 2)

        # Compute weighted overall_score (0-10 scale)
        weights = {'slither': 0.4, 'ml': 0.3, 'mythril': 0.3}
        overall_score = (
            weights['slither'] * results['slither_score'] +
            weights['ml'] * results['ml_score'] +
            weights['mythril'] * results['mythril_score']
        )
        results['overall_score'] = round(overall_score, 2)

        # Combine vulnerabilities from Slither and Mythril
        slither_vulns = results['static_analysis'].get('detectors', [])
        mythril_vulns = results['mythril_analysis'].get('vulnerabilities', [])
        results['vulnerabilities'] = slither_vulns + mythril_vulns

        # Add mythril severities to summary
        if 'mythril_analysis' in results and 'severity_counts' in results['mythril_analysis']:
            myth_sev = results['mythril_analysis']['severity_counts']
            if isinstance(myth_sev, dict):
                for sev_key, count in myth_sev.items():
                    if isinstance(sev_key, str) and sev_key in results['static_analysis']['summary']:
                        results['static_analysis']['summary'][sev_key] = results['static_analysis']['summary'].get(sev_key, 0) + int(count)

        # Generate summary
        self._generate_summary(results)
        self._compute_trust_risk_score(results)
        return results

    def get_contract_source(self, address: str, chain: str) -> dict:
        """Fetch contract source code using Etherscan V2 API with rate limiting."""
        if chain not in self.api_bases:
            raise ValueError(f"Unsupported chain: {chain}. Supported: {list(self.api_bases.keys())}")

        base_url = self.api_bases[chain]
        api_key = self.api_keys.get(chain)

        if not api_key:
            raise ValueError(f"API key not configured for {chain}. Set ETHERSCAN_API_KEY environment variable.")

        if not address.startswith('0x') or len(address) != 42:
            raise ValueError("Invalid EVM address format")

        # Use lazy imports
        requests = _get_requests()

        max_retries = 3
        base_delay = 1  # seconds

        for attempt in range(max_retries):
            try:
                # Etherscan V2 API with chainid - correct format for 2025
                chain_id = self.chain_ids[chain]
                self.logger.info(f"Making Etherscan API request for {chain} (chain_id: {chain_id})")

                url = f"{base_url}/v2/api?chainid={chain_id}&module=contract&action=getsourcecode&address={address}&apikey={api_key}"
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                data = response.json()

                if str(data.get('status')) == '1' and str(data.get('message')).upper() == 'OK':
                    return data

                if str(data.get('message')).upper() == 'NOTOK':
                    error_msg = data.get('result', 'Unknown error')
                    if 'deprecated V1 endpoint' in error_msg:
                        raise Exception(f"Etherscan API key not compatible with V2. Please get a new V2 API key from https://etherscan.io/myapikey")
                    else:
                        raise Exception(f"Etherscan API error: {error_msg}")

                raise Exception(f"Unexpected Etherscan response: {data}")

            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:  # Last attempt
                    self.logger.error(f"Network error fetching contract source after {max_retries} attempts: {e}")
                    raise Exception(f"Network error: {str(e)}")
                else:
                    # Exponential backoff for rate limiting
                    delay = base_delay * (2 ** attempt)
                    self.logger.warning(f"API request failed (attempt {attempt + 1}/{max_retries}), retrying in {delay}s: {e}")
                    import time
                    time.sleep(delay)

        # Should never reach here, but just in case
        raise Exception("Unexpected error in API retry logic")

    def get_transaction_count(self, address: str, chain: str) -> int:
        """Fetch transaction count using Etherscan V2 API with rate limiting."""
        if chain not in self.api_bases:
            self.logger.warning(f"Unsupported chain {chain}; cannot fetch transaction count.")
            return 0

        base_url = self.api_bases[chain]
        api_key = self.api_keys.get(chain)

        if not api_key:
            self.logger.warning(f"No API key for {chain}; cannot fetch transaction count.")
            return 0

        if not address.startswith('0x') or len(address) != 42:
            self.logger.warning("Invalid address format")
            return 0

        # Use lazy imports
        requests = _get_requests()

        max_retries = 2  # Fewer retries for transaction count (less critical)
        base_delay = 1  # seconds

        for attempt in range(max_retries):
            try:
                # Etherscan V2 API format for transaction count
                chain_id = self.chain_ids.get(chain, 1)  # Default to 1 if chain not found
                url = f"{base_url}/v2/api?chainid={chain_id}&module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=10000&sort=asc&apikey={api_key}"
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                data = response.json()

                if data.get('status') == '1':
                    transactions = data.get('result', [])
                    return len(transactions)
                else:
                    self.logger.warning(f"Failed to fetch tx count for {chain}: {data.get('message', 'Unknown')}")
                    # Fallback: return 0 for now, could implement alternative methods
                    return 0

            except Exception as e:
                if attempt == max_retries - 1:  # Last attempt
                    self.logger.error(f"Error fetching transaction count for {chain} after {max_retries} attempts: {e}")
                    return 0
                else:
                    # Exponential backoff for rate limiting
                    delay = base_delay * (2 ** attempt)
                    self.logger.warning(f"Transaction count request failed (attempt {attempt + 1}/{max_retries}), retrying in {delay}s: {e}")
                    import time
                    time.sleep(delay)

        return 0

    def _compute_trust_risk_score(self, results: Dict[str, Any]) -> None:
        """Compute ensemble risk score and reputation index."""
        if 'historical_data' not in results:
            results['historical_data'] = {'transaction_count': 0}

        # Security risk from overall score (0-100, higher = riskier)
        security_risk = results.get('overall_score', 0) * 10

        # Gas risk: higher savings indicate poorer optimization (arbitrary scaling)
        gas_savings = results.get('gas_optimization', {}).get('estimated_savings', 0)
        gas_risk = min(30, gas_savings / 5000)

        # Historical risk: lower tx count indicates less tested (higher risk)
        tx_count = results['historical_data']['transaction_count']
        historical_risk = 25 if tx_count == 0 else 15 if tx_count < 100 else 5 if tx_count < 1000 else 0

        # Weighted ensemble risk score
        risk_score = 0.7 * security_risk + 0.15 * gas_risk + 0.15 * historical_risk
        risk_score = min(100, max(0, risk_score))

        # Reputation index (higher = better)
        reputation_index = max(0, 100 - risk_score)

        results['trust_risk_scoring'] = {
            'risk_score': round(risk_score, 2),
            'reputation_index': round(reputation_index, 2),
            'explanation': (
                f"Risk score combines security ({round(security_risk, 2)}), "
                f"gas optimization ({round(gas_risk, 2)}), "
                f"and historical activity ({historical_risk})."
            ),
            'components': {
                'security_risk': round(security_risk, 2),
                'gas_risk': round(gas_risk, 2),
                'historical_risk': historical_risk,
                'transaction_count': tx_count
            }
        }
