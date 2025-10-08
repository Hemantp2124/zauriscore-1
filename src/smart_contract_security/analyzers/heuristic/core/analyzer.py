"""
Heuristic Analyzer

This module provides the main HeuristicAnalyzer class for analyzing smart contracts
using a combination of static analysis, heuristics, and machine learning.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import requests

from ..ml.vulnerability_analyzer import MLVulnerabilityWeightCalculator
from ..utils.slither_utils import run_slither, SlitherAnalysisError, SlitherTimeoutError
from ..utils.scoring import normalize_score
from ..types import HeuristicWeights, EconomicRisk, AnalysisResult

logger = logging.getLogger(__name__)

# Constants
DEFAULT_TIMEOUT = 30  # seconds
TEMP_CONTRACTS_DIR = Path(os.getenv('TEMP_CONTRACTS_DIR', Path.cwd() / "temp_contracts"))

class HeuristicAnalyzer:
    """Analyzes smart contracts using heuristic and ML-based approaches."""
    
    def __init__(
        self,
        weights: Optional[HeuristicWeights] = None,
        ml_model_path: str = 'microsoft/codebert-base',
        use_ml: bool = True
    ) -> None:
        """Initialize the HeuristicAnalyzer.
        
        Args:
            weights: Dictionary of weights for different heuristics
            ml_model_path: Path to the ML model for vulnerability detection
            use_ml: Whether to enable ML-based analysis
        """
        self.weights = weights or {
            'reentrancy_guard_present': 5,
            'reentrancy_guard_absent': -15,
            'unguarded_call': -20,
            'owner_selfdestruct': -20,
            'access_control_present': 5,
            'access_control_absent': -10,
            'natspec_present': 10,
            'etherscan_verified': 10,
            'no_external_calls': 10,
            'economic_risk_low': 10,
            'economic_risk_medium': -5,
            'economic_risk_high': -15,
            'compiler_vulnerability': -25
        }
        
        self.ml_analyzer = None
        if use_ml:
            try:
                self.ml_analyzer = MLVulnerabilityWeightCalculator(model_path=ml_model_path)
            except ImportError as e:
                logger.warning("ML analysis disabled: %s", str(e))
            except Exception as e:
                logger.error("Failed to initialize ML analyzer: %s", str(e), exc_info=True)
    
    def analyze_contract(
        self,
        contract_code: Union[str, Dict[str, str]],
        contract_address: Optional[str] = None,
        main_source_unit_name: str = "MainContract.sol",
        etherscan_verified: bool = False,
        verbose: bool = False
    ) -> AnalysisResult:
        """Analyze a smart contract using heuristics and ML.
        
        Args:
            contract_code: Solidity source code as a string or dictionary of files
            contract_address: Optional contract address for additional context
            main_source_unit_name: Name of the main contract file
            etherscan_verified: Whether the contract is verified on Etherscan
            verbose: Whether to enable verbose logging
            
        Returns:
            AnalysisResult: Dictionary containing analysis results
        """
        result: AnalysisResult = {
            'success': False,
            'score': 0.0,
            'findings': {},
            'warnings': [],
            'error': None,
            'metadata': {}
        }
        
        try:
            # Run Slither analysis
            slither_results = run_slither(
                contract_code=contract_code,
                main_source_unit_name=main_source_unit_name,
                verbose=verbose
            )
            
            if not slither_results.get('success', False):
                result['error'] = f"Slither analysis failed: {slither_results.get('error', 'Unknown error')}"
                return result
            
            # Extract findings from Slither
            findings = self._extract_findings_from_slither(slither_results)
            
            # Run ML analysis if available
            if self.ml_analyzer and isinstance(contract_code, str):
                ml_findings = self._run_ml_analysis(contract_code)
                findings.update(ml_findings)
            
            # Apply heuristics
            score = self._calculate_heuristic_score(findings, etherscan_verified)
            
            # Prepare result
            result.update({
                'success': True,
                'score': score,
                'findings': findings,
                'metadata': {
                    'slither_results': slither_results,
                    'heuristics_used': list(self.weights.keys())
                }
            })
            
            return result
            
        except SlitherTimeoutError as e:
            result['error'] = f"Analysis timed out: {str(e)}"
            return result
        except SlitherAnalysisError as e:
            result['error'] = f"Analysis error: {str(e)}"
            return result
        except Exception as e:
            logger.exception("Unexpected error during analysis")
            result['error'] = f"Unexpected error: {str(e)}"
            return result
    
    def _extract_findings_from_slither(self, slither_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant findings from Slither analysis results.
        
        Args:
            slither_results: Raw results from Slither analysis
            
        Returns:
            Dict containing processed findings
        """
        findings = {}
        
        # Process detector results
        for detector in slither_results.get('results', {}).get('detectors', []):
            finding = {
                'check': detector.get('check', 'unknown'),
                'impact': detector.get('impact', 'Informational'),
                'confidence': detector.get('confidence', 'Medium'),
                'description': detector.get('description', ''),
                'elements': detector.get('elements', [])
            }
            
            # Categorize findings by check type
            check_name = finding['check'].lower()
            if check_name not in findings:
                findings[check_name] = []
            findings[check_name].append(finding)
        
        return findings
    
    def _run_ml_analysis(self, contract_code: str) -> Dict[str, Any]:
        """Run ML-based vulnerability analysis on the contract code.
        
        Args:
            contract_code: Source code of the contract
            
        Returns:
            Dict containing ML analysis results
        """
        if not self.ml_analyzer:
            return {}
            
        try:
            # Calculate vulnerability similarities
            similarities = self.ml_analyzer.calculate_code_vulnerability_similarity(contract_code)
            
            # Assess economic risk
            economic_risk = self.ml_analyzer.assess_economic_risk(contract_code)
            
            return {
                'ml_vulnerability_similarities': similarities,
                'economic_risk': economic_risk
            }
        except Exception as e:
            logger.warning("ML analysis failed: %s", str(e))
            return {}
    
    def _calculate_heuristic_score(
        self, 
        findings: Dict[str, Any],
        etherscan_verified: bool = False
    ) -> float:
        """Calculate a heuristic score based on the analysis findings.
        
        Args:
            findings: Dictionary of analysis findings
            etherscan_verified: Whether the contract is verified on Etherscan
            
        Returns:
            float: Normalized score between 0 and 100
        """
        score = 0.0
        
        # Apply heuristics based on findings
        if 'reentrancy' in findings:
            if any('reentrancy' in f['description'].lower() for f in findings['reentrancy']):
                score += self.weights.get('reentrancy_guard_absent', 0)
            else:
                score += self.weights.get('reentrancy_guard_present', 0)
        
        if 'unprotected-upgrade' in findings:
            score += self.weights.get('access_control_absent', 0)
        
        if 'natspec' in findings:
            score += self.weights.get('natspec_present', 0)
        
        if etherscan_verified:
            score += self.weights.get('etherscan_verified', 0)
        
        # Apply ML-based heuristics if available
        if 'ml_vulnerability_similarities' in findings:
            similarities = findings['ml_vulnerability_similarities']
            if similarities.get('reentrancy', 0) > 0.7:
                score += self.weights.get('reentrancy_guard_absent', 0)
            
            if similarities.get('access_control', 0) > 0.7:
                score += self.weights.get('access_control_absent', 0)
        
        if 'economic_risk' in findings:
            risk_level = findings['economic_risk']
            score += self.weights.get(risk_level, 0)
        
        # Normalize the score to 0-100 range
        return normalize_score(score)
