"""
ZauriScore CLI - Command Line Interface for Smart Contract Analysis
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

from zauriscore.core.ml_pipeline import ZauriScoreMLPipeline
from zauriscore.analyzers.comprehensive_contract_analysis import ComprehensiveContractAnalyzer
from zauriscore.reporting.consolidated_report_generator import create_report_generator

logger = logging.getLogger(__name__)

def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the CLI.
    
    Args:
        verbose: Enable verbose logging if True
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def analyze_contract(contract_path: str, output_path: Optional[str] = None, 
                   format: str = 'json') -> None:
    """Analyze a smart contract and generate a report.
    
    Args:
        contract_path: Path to the smart contract file
        output_path: Path to save the report (optional)
        format: Output format (json, markdown, or pdf)
    """
    try:
        logger.info(f"Analyzing contract: {contract_path}")
        analyzer = ComprehensiveContractAnalyzer()
        result = analyzer.analyze_contract(contract_path)
        
        if output_path:
            generator = create_report_generator(output_path)
            output = generator.generate_report(result, format)
            logger.info(f"Report generated: {output}")
        else:
            # Print to stdout if no output file specified
            if format == 'json':
                import json
                print(json.dumps(result, indent=2))
            else:
                generator = create_report_generator()
                print(generator.generate_report(result, format))
                
    except Exception as e:
        logger.error(f"Error analyzing contract: {e}")
        sys.exit(1)

def train_model(dataset_path: str, model_output: str) -> None:
    """Train the ML model on the specified dataset.
    
    Args:
        dataset_path: Path to the training dataset
        model_output: Path to save the trained model
    """
    try:
        logger.info(f"Training model on dataset: {dataset_path}")
        pipeline = ZauriScoreMLPipeline()
        pipeline.train(dataset_path, model_output)
        logger.info(f"Model saved to: {model_output}")
    except Exception as e:
        logger.error(f"Error training model: {e}")
        sys.exit(1)

def main() -> None:
    """Main entry point for the ZauriScore CLI."""
    parser = argparse.ArgumentParser(
        description='ZauriScore - Smart Contract Security Analysis Tool',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-v', '--verbose', 
        action='store_true', 
        help='Enable verbose logging (debug level)'
    )

    subparsers = parser.add_subparsers(
        dest='command', 
        title='available commands',
        help='Command to execute',
        required=True
    )

    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze', 
        help='Analyze a smart contract',
        description='Perform security analysis on a smart contract'
    )
    analyze_parser.add_argument(
        'contract_path', 
        type=str, 
        help='Path to the smart contract file'
    )
    analyze_parser.add_argument(
        '-o', '--output', 
        type=str, 
        help='Output file path for the report (default: print to stdout)'
    )
    analyze_parser.add_argument(
        '--format', 
        type=str, 
        choices=['json', 'markdown', 'pdf'],
        default='json',
        help='Output format of the report'
    )

    # Train command
    train_parser = subparsers.add_parser(
        'train', 
        help='Train the ML model',
        description='Train the machine learning model on a dataset'
    )
    train_parser.add_argument(
        'dataset_path', 
        type=str, 
        help='Path to the training dataset directory'
    )
    train_parser.add_argument(
        'model_output', 
        type=str, 
        help='Path to save the trained model'
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    try:
        if args.command == 'analyze':
            analyze_contract(args.contract_path, args.output, args.format)
        elif args.command == 'train':
            train_model(args.dataset_path, args.model_output)
        else:
            parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            logger.exception("Detailed error:")
        sys.exit(1)

if __name__ == '__main__':
    main()
