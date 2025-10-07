#!/usr/bin/env python3
"""
ZauriScore Contract Analysis Runner

This script runs comprehensive security analysis on smart contracts using the
ZauriScore framework. It demonstrates the multi-layered analysis capabilities
including static analysis, gas optimization, and ML-based vulnerability detection.
"""

import sys
import json
import logging
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from zauriscore.analyzers.comprehensive_contract_analysis import ComprehensiveContractAnalyzer
from zauriscore.utils.logger import setup_logger
from zauriscore.config import settings

def analyze_contract_sample():
    """Run analysis on the sample contract."""
    
    # Setup logging
    logger = setup_logger('contract_analysis', log_level='INFO')
    logger.info("🛡️ Starting ZauriScore Contract Analysis")
    
    # Initialize analyzer
    analyzer = ComprehensiveContractAnalyzer()
    
    # Read sample contract
    contract_path = Path('src/zauriscore/data/contracts/samples/sample_contract.sol')
    
    if not contract_path.exists():
        logger.error(f"Sample contract not found at {contract_path}")
        return None
    
    with open(contract_path, 'r') as f:
        source_code = f.read()
    
    logger.info(f"Loaded contract from {contract_path}")
    logger.info(f"Contract size: {len(source_code)} characters")
    
    # Run comprehensive analysis
    try:
        logger.info("Running comprehensive analysis...")
        
        # Perform analysis
        results = analyzer.analyze_contract(
            contract_address="0xSampleContract123456789",
            source_code=source_code,
            chain="ethereum"
        )
        
        logger.info("✅ Analysis completed successfully!")
        
        # Display summary
        if results and 'summary' in results:
            summary = results['summary']
            
            print("\n" + "="*60)
            print("🛡️ ZauriScore Security Analysis Report")
            print("="*60)
            
            print(f"📊 Security Risk: {summary.get('security_risk', 'Unknown')}")
            print(f"⛽ Gas Efficiency: {summary.get('gas_efficiency', 'Unknown')}")
            print(f"🔍 Total Issues: {summary.get('total_issues', 0)}")
            
            # Static analysis results
            if 'static_analysis' in results and 'summary' in results['static_analysis']:
                static_summary = results['static_analysis']['summary']
                print(f"\n📋 Static Analysis Summary:")
                print(f"  High Risk: {static_summary.get('high', 0)}")
                print(f"  Medium Risk: {static_summary.get('medium', 0)}")
                print(f"  Low Risk: {static_summary.get('low', 0)}")
                print(f"  Informational: {static_summary.get('informational', 0)}")
            
            # Gas optimization results
            if 'gas_optimization' in results:
                gas_opt = results['gas_optimization']
                print(f"\n⛽ Gas Optimization:")
                print(f"  Estimated Savings: {gas_opt.get('estimated_savings', 0)} gas units")
                print(f"  Recommendations: {len(gas_opt.get('recommendations', []))}")
            
            # CodeBERT analysis
            if 'codebert_analysis' in results:
                codebert = results['codebert_analysis']
                if 'error' not in codebert:
                    print(f"\n🤖 AI Analysis:")
                    print(f"  Predicted Class: {codebert.get('predicted_class', 'N/A')}")
                    print(f"  Confidence: {max(codebert.get('confidence_scores', [0])):.2%}")
            
            print("\n" + "="*60)
        
        # Save detailed results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"analysis_results_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"📄 Detailed results saved to {output_file}")
        
        return results
        
    except Exception as e:
        logger.error(f"❌ Analysis failed: {str(e)}")
        logger.exception("Full error traceback:")
        return None

def main():
    """Main function."""
    print("🚀 ZauriScore Contract Analysis Tool")
    print("=====================================\n")
    
    # Run analysis
    results = analyze_contract_sample()
    
    if results:
        print("\n✅ Analysis completed! Check the log file for detailed results.")
        return 0
    else:
        print("\n❌ Analysis failed. Check logs for error details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())