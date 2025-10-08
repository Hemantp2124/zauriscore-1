"""
Slither Analysis Utilities

This module provides utilities for running Slither static analysis on Solidity contracts.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Union

logger = logging.getLogger(__name__)

# Constants
SLITHER_TIMEOUT = 120  # seconds
SLITHER_INFORMATIONAL_EXIT_CODE = 4294967295  # 0xFFFFFFFF

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
        temp_run_dir = _setup_temp_directory()
        slither_results = _initialize_slither_results()

        # Process contract code and get path to the main contract file
        slither_target_for_cmd = _process_contract_code(
            contract_code, main_source_unit_name, temp_run_dir
        )

        # Run Slither detectors with timeout
        try:
            detector_results = _run_slither_detectors(
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
                inheritance_results = _run_slither_inheritance(
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
                _cleanup_temp_directory(temp_run_dir)
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up temporary directory: {cleanup_error}")

def _setup_temp_directory() -> Path:
    """Create a temporary directory for Slither analysis.
    
    Returns:
        Path: Path to the created temporary directory
    """
    temp_dir = Path(tempfile.mkdtemp(prefix="zauriscore_slither_"))
    logger.debug(f"Created temporary directory: {temp_dir}")
    return temp_dir

def _initialize_slither_results() -> Dict[str, Any]:
    """Initialize a dictionary to store Slither analysis results.
    
    Returns:
        Dict containing initialized result structure
    """
    return {
        "success": True,
        "error": None,
        "type": None,
        "results": {
            "detectors": []
        },
        "inheritance_graph_dot": None,
        "raw_detector_json_output": None,
        "raw_inheritance_json_output": None
    }

def _process_contract_code(
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
        # Save multiple files
        for filename, content in contract_code.items():
            file_path = temp_dir / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        return str(temp_dir / main_source_unit_name)
    else:
        # Save single file
        main_file = temp_dir / main_source_unit_name
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write(contract_code)
        return str(main_file)

def _run_slither_detectors(slither_path: str, target: str) -> Dict[str, Any]:
    """Run Slither vulnerability detectors on the target.
    
    Args:
        slither_path: Path to the Slither executable
        target: Path to the target contract file or directory
        
    Returns:
        Dict containing detector results
    """
    cmd = [
        slither_path,
        target,
        "--detect-all",
        "--json",
        "-",
        "--disable-color",
        "--exclude-optimization",
        "--exclude-informational"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT,
            check=True
        )
        
        # Parse JSON output
        detector_results = json.loads(result.stdout)
        
        return {
            "success": True,
            "results": {
                "detectors": detector_results.get("results", {}).get("detectors", [])
            },
            "raw_detector_json_output": detector_results
        }
    except subprocess.TimeoutExpired:
        raise
    except subprocess.CalledProcessError as e:
        # Check if this is just an informational exit code
        if e.returncode == SLITHER_INFORMATIONAL_EXIT_CODE:
            return {
                "success": True,
                "results": {
                    "detectors": []
                },
                "raw_detector_json_output": {}
            }
        raise

def _run_slither_inheritance(slither_path: str, target: str) -> Dict[str, Any]:
    """Run Slither inheritance analysis on the target.
    
    Args:
        slither_path: Path to the Slither executable
        target: Path to the target contract file or directory
        
    Returns:
        Dict containing inheritance analysis results
    """
    cmd = [
        slither_path,
        target,
        "--print",
        "inheritance-graph",
        "--disable-color"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT,
            check=True
        )
        
        return {
            "inheritance_graph_dot": result.stdout,
            "raw_inheritance_json_output": result.stdout
        }
    except subprocess.TimeoutExpired:
        raise
    except subprocess.CalledProcessError as e:
        # Check if this is just an informational exit code
        if e.returncode == SLITHER_INFORMATIONAL_EXIT_CODE:
            return {
                "inheritance_graph_dot": "",
                "raw_inheritance_json_output": {}
            }
        raise

def _cleanup_temp_directory(temp_dir: Path) -> None:
    """Clean up temporary directory after analysis is complete.
    
    Args:
        temp_dir: Path to the temporary directory to clean up
    """
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
            logger.debug(f"Removed temporary directory: {temp_dir}")
    except Exception as e:
        logger.warning(f"Failed to clean up temporary directory {temp_dir}: {e}")
        # Don't raise - we don't want cleanup failures to mask analysis errors
