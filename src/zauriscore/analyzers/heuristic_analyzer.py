"""Heuristic Analyzer for Smart Contract Security Assessment.

This module provides heuristic-based analysis of Solidity smart contracts to identify
potential security vulnerabilities and code quality issues. It integrates with Slither
and provides ML-based vulnerability detection.
"""

# Standard library imports
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Union, Literal

# Third-party imports
import requests

# Configure logging
logger = logging.getLogger(__name__)

# Constants
SLITHER_TIMEOUT = 120  # seconds
SLITHER_INFORMATIONAL_EXIT_CODE = 4294967295  # 0xFFFFFFFF

# Use pathlib for cross-platform path handling
TEMP_CONTRACTS_DIR = Path(os.getenv('TEMP_CONTRACTS_DIR', Path.cwd() / "temp_contracts"))
ZAURISCORE_BASE_DIR = Path(__file__).parent.parent.parent

# Heuristic scoring weights with type hints
class HeuristicWeights(TypedDict):
    """Type definition for heuristic scoring weights."""
    reentrancy_guard_present: int
    reentrancy_guard_absent: int
    unguarded_call: int
    owner_selfdestruct: int
    access_control_present: int
    access_control_absent: int
    natspec_present: int
    etherscan_verified: int
    no_external_calls: int
    economic_risk_low: int
    economic_risk_medium: int
    economic_risk_high: int
    compiler_vulnerability: int

HEURISTIC_POINTS: HeuristicWeights = {
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

# Type aliases
EconomicRisk = Literal['economic_risk_low', 'economic_risk_medium', 'economic_risk_high']

# ML Dependencies
try:
    import torch
    import numpy as np
    from transformers import AutoTokenizer, AutoModel
    from sklearn.preprocessing import MinMaxScaler
    ML_DEPENDENCIES_AVAILABLE = True
except ImportError as e:
    logger.warning('Machine learning dependencies not fully available. Some features will be disabled: %s', str(e))
    ML_DEPENDENCIES_AVAILABLE = False


class MLVulnerabilityWeightCalculator:
    """Analyzes contract code for ML-based vulnerability patterns using BERT embeddings."""

    def __init__(self, model_path: str = 'microsoft/codebert-base') -> None:
        """Initialize the MLVulnerabilityWeightCalculator.
        
        Args:
            model_path: Path to the pre-trained model or model identifier from huggingface.co/models
            
        Raises:
            ImportError: If required ML dependencies are not available
        """
        if not ML_DEPENDENCIES_AVAILABLE:
            error_msg = 'Machine learning dependencies not available'
            logger.error(error_msg)
            raise ImportError(error_msg)
        
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModel.from_pretrained(model_path)
            
            self.vulnerability_embeddings = {
                'reentrancy': self._embed_vulnerability_type('reentrancy attack external call state change'),
                'access_control': self._embed_vulnerability_type('unauthorized access control ownership'),
                'selfdestruct': self._embed_vulnerability_type('contract self destruction owner control'),
                'external_call': self._embed_vulnerability_type('unguarded external call low-level call'),
                'economic_manipulation': self._embed_vulnerability_type('price oracle liquidity manipulation')
            }
            logger.info("ML model and tokenizer initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize ML model: %s", str(e))
            raise

    def _embed_vulnerability_type(self, description: str) -> torch.Tensor:
        """Generate embedding for a vulnerability type description.
        
        Args:
            description: Text description of the vulnerability type
            
        Returns:
            torch.Tensor: Embedding vector
        """
        try:
            inputs = self.tokenizer(description, return_tensors='pt', truncation=True, max_length=512)
            with torch.no_grad():
                outputs = self.model(**inputs)
            return outputs.last_hidden_state.mean(dim=1).flatten()
        except Exception as e:
            logger.error("Error generating embedding: %s", str(e))
            raise

    def calculate_code_vulnerability_similarity(self, contract_code: str) -> Dict[str, float]:
        """Calculate similarity scores between contract code and known vulnerability types.
        
        Args:
            contract_code: Source code of the contract to analyze
            
        Returns:
            Dict[str, float]: Dictionary mapping vulnerability types to similarity scores
        """
        try:
            contract_embedding = self._embed_vulnerability_type(contract_code)
            similarities = {}
            
            for vuln_type, vuln_embedding in self.vulnerability_embeddings.items():
                similarity = torch.nn.functional.cosine_similarity(
                    contract_embedding.unsqueeze(0), 
                    vuln_embedding.unsqueeze(0)
                ).item()
                similarities[vuln_type] = similarity
                
            return similarities
        except Exception as e:
            logger.error("Error calculating code vulnerability similarity: %s", str(e))
            return {}

    def assess_economic_risk(self, contract_code: str) -> str:
        """Assess the economic risk level of a contract.
        
        Args:
            contract_code: Source code of the contract to analyze
            
        Returns:
            str: Risk level ('economic_risk_low', 'economic_risk_medium', 'economic_risk_high')
        """
        try:
            similarities = self.calculate_code_vulnerability_similarity(contract_code)
            economic_risk_score = similarities.get('economic_manipulation', 0)
            
            if economic_risk_score < 0.2:
                return 'economic_risk_low'
            elif economic_risk_score < 0.5:
                return 'economic_risk_medium'
            return 'economic_risk_high'
        except Exception as e:
            logger.error("Error assessing economic risk: %s", str(e))
            return 'economic_risk_medium'  # Default to medium on error


class SlitherAnalysisError(Exception):
    """Base exception for Slither analysis errors."""
    pass

class SlitherTimeoutError(SlitherAnalysisError):
    """Raised when Slither analysis times out."""
    pass

def run_slither(
    contract_code: Union[str, Dict[str, Any]], 
    main_source_unit_name: str = "MainContract.sol", 
    verbose: bool = False
) -> Dict[str, Any]:
    """Run Slither static analysis on a smart contract.
    
    Args:
        contract_code: Either a string of Solidity code or a dictionary of source files
        main_source_unit_name: Name of the main contract file
        verbose: Whether to enable verbose logging
        
    Returns:
        Dict containing Slither analysis results
    """
    slither_path = shutil.which("slither")
    if not slither_path:
        error_msg = "Slither executable not found in PATH. Please install Slither: pip install slither-analyzer"
        logger.error(error_msg)
        return {
            "success": False, 
            "error": error_msg, 
            "results": {"detectors": []}, 
            "inheritance_graph_dot": None, 
            "raw_detector_json_output": None, 
            "raw_inheritance_json_output": None
        }

    temp_run_dir = None
    try:
        # Set up temporary directory
        temp_run_dir = setup_temp_directory()
        slither_results = initialize_slither_results()

        # Process contract code and get path to the main contract file
        slither_target_for_cmd = process_contract_code(
            contract_code, main_source_unit_name, temp_run_dir
        )

        # Run Slither detectors with timeout
        try:
            detector_results = run_slither_detectors(
                slither_path="slither",
                target=slither_target_for_cmd
            )
            slither_results.update(detector_results)
        except subprocess.TimeoutExpired as te:
            error_msg = f"Slither detector analysis timed out after {te.timeout} seconds"
            logger.error(error_msg)
            slither_results.update({
                "success": False,
                "error": error_msg,
                "type": "timeout"
            })
        except subprocess.CalledProcessError as cpe:
            error_msg = f"Slither detector execution failed with code {cpe.returncode}: {cpe.stderr}"
            logger.error(error_msg)
            slither_results.update({
                "success": False,
                "error": error_msg,
                "type": "detector_error"
            })

        # Run Slither inheritance analysis if detectors succeeded
        if slither_results.get("success", True):
            try:
                inheritance_results = run_slither_inheritance(
                    slither_path="slither",
                    target=slither_target_for_cmd
                )
                slither_results.update(inheritance_results)
            except subprocess.TimeoutExpired as te:
                error_msg = f"Slither inheritance analysis timed out after {te.timeout} seconds"
                logger.error(error_msg)
                slither_results.update({
                    "success": False,
                    "error": error_msg,
                    "type": "timeout"
                })
            except subprocess.CalledProcessError as cpe:
                error_msg = f"Slither inheritance analysis failed with code {cpe.returncode}: {cpe.stderr}"
                logger.error(error_msg)
                slither_results.update({
                    "success": False,
                    "error": error_msg,
                    "type": "inheritance_error"
                })

        return slither_results

    except Exception as e:
        error_msg = f"Unexpected error during Slither analysis: {str(e)}"
        logger.exception(error_msg)
        return {
            "success": False,
            "error": error_msg,
            "type": "unexpected_error"
        }

    finally:
        # Clean up temporary directory
        if temp_run_dir is not None and temp_run_dir.exists():
            try:
                cleanup_temp_directory(temp_run_dir)
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up temporary directory: {cleanup_error}")
    return slither_results


def setup_temp_directory() -> Path:
    """Create a temporary directory for Slither analysis.
    
    Returns:
        Path: Path to the created temporary directory
    """
    temp_dir = Path(TEMP_CONTRACTS_DIR) / str(uuid.uuid4())
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def initialize_slither_results() -> Dict[str, Any]:
    """Initialize a dictionary to store Slither analysis results.
    
    Returns:
        Dict containing initialized result structure
    """
    return {
        "success": True,
        "error": None,
        "results": {"detectors": []},
        "inheritance_graph_dot": None,
        "raw_detector_json_output": None,
        "raw_inheritance_json_output": None
    }


def process_contract_code(
    contract_code: Union[str, Dict[str, Any]],
    main_source_unit_name: str,
    temp_dir: Path
) -> str:
    """Process contract code and save to a temporary file.
    
    Args:
        contract_code: Contract code as string or dictionary of files
        main_source_unit_name: Name of the main contract file
        temp_dir: Directory to save the contract files
        
    Returns:
        str: Path to the main contract file
    """
    if isinstance(contract_code, dict):
        # Handle multiple source files
        for filename, content in contract_code.items():
            file_path = temp_dir / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding='utf-8')
        return str(temp_dir / main_source_unit_name)
    else:
        # Handle single file
        file_path = temp_dir / main_source_unit_name
        file_path.write_text(contract_code, encoding='utf-8')
        return str(file_path)


def run_slither_detectors(slither_path: str, target: str) -> Dict[str, Any]:
    """Run Slither vulnerability detectors on the target.
    
    Args:
        slither_path: Path to the Slither executable
        target: Path to the target contract file or directory
        
    Returns:
        Dict containing detector results
    """
    try:
        # Run Slither detectors
        result = subprocess.run(
            [slither_path, target, "--json", "-"],
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT
        )
        
        # Check for errors
        if result.returncode != 0 and result.returncode != SLITHER_INFORMATIONAL_EXIT_CODE:
            return {
                "success": False,
                "error": f"Slither failed with exit code {result.returncode}: {result.stderr}"
            }
            
        # Parse and return results
        return {
            "success": True,
            "raw_detector_json_output": json.loads(result.stdout) if result.stdout else {}
        }
        
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Slither detector analysis timed out"}
    except json.JSONDecodeError:
        return {"success": False, "error": "Failed to parse Slither output as JSON"}


def run_slither_inheritance(slither_path: str, target: str) -> Dict[str, Any]:
    """Run Slither inheritance analysis on the target.
    
    Args:
        slither_path: Path to the Slither executable
        target: Path to the target contract file or directory
        
    Returns:
        Dict containing inheritance analysis results
    """
    try:
        # Run Slither inheritance analysis
        result = subprocess.run(
            [slither_path, target, "--print-inheritance-dot"],
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT
        )
        
        # Check for errors
        if result.returncode != 0 and result.returncode != SLITHER_INFORMATIONAL_EXIT_CODE:
            return {"success": False, "error": f"Slither inheritance analysis failed: {result.stderr}"}
            
        return {
            "success": True,
            "inheritance_graph_dot": result.stdout
        }
        
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Slither inheritance analysis timed out"}


def cleanup_temp_directory(temp_dir: Path) -> None:
    """Clean up temporary directory after analysis is complete.
    
    Args:
        temp_dir: Path to the temporary directory to clean up
    """
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    except Exception as e:
        logger.warning(f"Failed to clean up temporary directory {temp_dir}: {str(e)}")


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for file logging
    """
    log_level = getattr(logging, log_level.upper(), logging.INFO)
    handlers = [logging.StreamHandler()]
    
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


def normalize_score(score: float, min_score: float = -100.0, max_score: float = 50.0) -> float:
    """Normalize a score to a 0-100 scale.
    
    Args:
        score: Raw score to normalize
        min_score: Minimum possible score
        max_score: Maximum possible score
        
    Returns:
        float: Normalized score between 0 and 100
    """
    if max_score <= min_score:
        logger.warning("max_score must be greater than min_score")
        return 50.0  # Default to middle value
    
    # Ensure score is within bounds
    score = max(min(score, max_score), min_score)
    
    # Normalize to 0-100 range
    return ((score - min_score) / (max_score - min_score)) * 100# Clamp between 0 and 100


class HeuristicAnalyzer:
    """Main class for heuristic-based smart contract analysis."""

    def __init__(self, model_path: str = 'microsoft/codebert-base') -> None:
        """
        Initialize the HeuristicAnalyzer.
        
        Args:
            model_path: Path to the pre-trained ML model.
        """
        self.weights = HEURISTIC_POINTS
        if ML_DEPENDENCIES_AVAILABLE:
            self.ml = MLVulnerabilityWeightCalculator(model_path)
        else:
            self.ml = None
        self.logger = logger

    def analyze(self, contract_code: str, main_source_unit_name: str = "MainContract.sol") -> Dict[str, Any]:
        """
        Analyze the smart contract using heuristics, Slither, and ML.
        
        Args:
            contract_code: The Solidity source code.
            main_source_unit_name: Name of the main source file.
            
        Returns:
            Dict containing analysis results, score, and findings.
        """
        findings = []
        score = 0.0
        economic_risk = 'unknown'
        
        # Run Slither analysis
        slither_results = run_slither(contract_code, main_source_unit_name)
        if slither_results.get('success'):
            detectors = slither_results.get('results', {}).get('detectors', [])
            for detector in detectors:
                check_type = detector.get('check', '')
                impact = detector.get('impact', 'Medium')
                findings.append({
                    'type': 'slither',
                    'check': check_type,
                    'impact': impact,
                    'description': detector.get('description', ''),
                    'confidence': detector.get('confidence', 'Medium')
                })
                # Adjust score based on detector type (simplified)
                if 'reentrancy' in check_type:
                    score += self.weights['reentrancy_guard_absent']
                elif 'selfdestruct' in check_type:
                    score += self.weights['owner_selfdestruct']
                elif 'access' in check_type:
                    score += self.weights['access_control_absent']
                else:
                    score -= 5  # Generic penalty
        else:
            findings.append({
                'type': 'slither',
                'error': slither_results.get('error', 'Slither analysis failed')
            })
        
        # ML-based vulnerability assessment
        if self.ml:
            similarities = self.ml.calculate_code_vulnerability_similarity(contract_code)
            for vuln_type, similarity in similarities.items():
                if similarity > 0.5:
                    findings.append({
                        'type': 'ml',
                        'vulnerability': vuln_type,
                        'similarity': similarity,
                        'description': f'High similarity to {vuln_type} patterns'
                    })
                    score -= 10 * similarity
            economic_risk = self.ml.assess_economic_risk(contract_code)
            score += self.weights.get(economic_risk, 0)
        
        # Basic heuristic checks on code
        if re.search(r'\bReentrancyGuard\b', contract_code):
            score += self.weights['reentrancy_guard_present']
            findings.append({
                'type': 'heuristic',
                'check': 'reentrancy_guard_present',
                'description': 'ReentrancyGuard detected'
            })
        if re.search(r'\bowner\s*\.\s*selfdestruct', contract_code, re.IGNORECASE):
            score += self.weights['owner_selfdestruct']
            findings.append({
                'type': 'heuristic',
                'check': 'owner_selfdestruct',
                'description': 'Owner-controlled selfdestruct detected (negative)'
            })
        if re.search(r'\s*\*\s*', contract_code):
            score += self.weights['natspec_present']
            findings.append({
                'type': 'heuristic',
                'check': 'natspec_present',
                'description': 'NatSpec documentation detected'
            })
        if not re.search(r'\bcall\b|\bdelegatecall\b|\bstaticcall\b', contract_code):
            score += self.weights['no_external_calls']
            findings.append({
                'type': 'heuristic',
                'check': 'no_external_calls',
                'description': 'No low-level external calls detected'
            })
        
        # Normalize score
        normalized_score = normalize_score(score)
        
        return {
            'score': normalized_score,
            'raw_score': score,
            'findings': findings,
            'slither_results': slither_results,
            'economic_risk': economic_risk,
            'success': slither_results.get('success', False)
        }

    def analyze_with_mythril(self, contract_path: str) -> dict:
        """Run Mythril analysis using Docker."""
        try:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{Path(contract_path).parent.absolute()}:/tmp",
                "mythril/myth",
                "analyze", f"/tmp/{Path(contract_path).name}",
                "--output", "json"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr, "success": False}
                
        except Exception as e:
            return {"error": str(e), "success": False}


def test_heuristic_analyzer() -> None:
    """Run basic tests for the heuristic analyzer."""
    import doctest
    import pytest
    
    # Run doctests
    doctest.testmod()
    
    # Run pytest tests
    test_dir = os.path.join(os.path.dirname(__file__), "tests")
    if os.path.exists(test_dir):
        pytest.main([test_dir])
    else:
        logger.warning("Test directory not found: %s", test_dir)


if __name__ == "__main__":
    # Configure logging when run directly
    setup_logging()
    logger.info("Starting Heuristic Analyzer")
    
    # Run tests if --test flag is provided
    if "--test" in sys.argv:
        test_heuristic_analyzer()
    else:
        logger.info("Use --test to run tests")