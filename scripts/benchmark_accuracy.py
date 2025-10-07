"""Benchmark script for ML (CodeBERT) and ensemble scoring accuracy in ZauriScore."""

import os
import json
import time
import logging
import numpy as np
from pathlib import Path
from datetime import datetime
from sklearn.metrics import (
    mean_squared_error, f1_score, accuracy_score,
    precision_score, recall_score, roc_auc_score, confusion_matrix
)
from typing import Dict, List, Tuple, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('benchmark.log')
    ]
)
logger = logging.getLogger(__name__)

# Import analyzer with error handling
try:
    from zauriscore.analyzers.comprehensive_contract_analysis import ComprehensiveContractAnalyzer
except ImportError as e:
    logger.error(f"Failed to import ComprehensiveContractAnalyzer: {e}")
    raise ImportError(f"Failed to import ComprehensiveContractAnalyzer: {e}") from e

# Sample contracts: simple safe and vulnerable examples
# Ground truth: risk scores (0-1, lower better) for regression; labels (0 safe, 1 vulnerable) for classification
samples = [
    {
        'name': 'Simple Safe Contract',
        'code': '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Safe {\n    function transfer() public {}\n}',
        'ground_truth_risk': 0.2,  # Low risk
        'ground_truth_label': 0    # Safe
    },
    {
        'name': 'Reentrancy Vulnerable',
        'code': '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Vulnerable {\n    mapping(address => uint) public balances;\n    \n    function withdraw() public {\n        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");\n        require(success, "Transfer failed");\n        balances[msg.sender] = 0;\n    }\n    \n    function deposit() public payable {\n        balances[msg.sender] += msg.value;\n    }\n}',
        'ground_truth_risk': 0.9,  # High risk
        'ground_truth_label': 1    # Vulnerable
    },
    {
        'name': 'Another Safe',
        'code': '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Secure {\n    uint public balance;\n    \n    function deposit() public payable {\n        balance += msg.value;\n    }\n}',
        'ground_truth_risk': 0.1,
        'ground_truth_label': 0
    },
    {
        'name': 'Unchecked Send Vulnerable',
        'code': '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Bad {\n    function send() public payable {\n        // Fixed: Use payable address for .send()\n        payable(address(0)).transfer(msg.value);\n    }\n}',
        'ground_truth_risk': 0.8,
        'ground_truth_label': 1
    }
]

# For temporary files (analyzer writes to temp)
def run_analysis(code, temp_dir='temp_benchmark'):
    try:
        # Create temp directory if it doesn't exist
        os.makedirs(temp_dir, exist_ok=True)
        
        # Write contract to file
        contract_path = os.path.join(temp_dir, 'contract.sol')
        with open(contract_path, 'w') as f:
            f.write(code)
            
        # Initialize analyzer and run analysis
        analyzer = ComprehensiveContractAnalyzer()
        result = analyzer.analyze_contract(source_code=code)
        
        return {
            'ml_score': float(result.get('ml_score', 0.5)),
            'overall_score': float(result.get('overall_score', 0.5)),
            'predicted_label': 1 if float(result.get('ml_score', 0.5)) > 0.5 else 0
        }
        
    except Exception as e:
        print(f"Error analyzing contract: {str(e)}")
        return {
            'ml_score': 0.5,  # Default to neutral score on error
            'overall_score': 0.5,
            'predicted_label': 0,
            'error': str(e)
        }

def calculate_metrics(true_risks: List[float], predictions: List[float], 
                     true_labels: List[int], pred_labels: List[int]) -> Dict[str, float]:
    """Calculate and return comprehensive evaluation metrics."""
    metrics = {
        'mse': float(mean_squared_error(true_risks, predictions)),
        'accuracy': float(accuracy_score(true_labels, pred_labels)),
        'f1': float(f1_score(true_labels, pred_labels, average='weighted')),
        'precision': float(precision_score(true_labels, pred_labels, average='weighted', zero_division=0)),
        'recall': float(recall_score(true_labels, pred_labels, average='weighted', zero_division=0))
    }
    
    try:
        metrics['roc_auc'] = float(roc_auc_score(true_labels, predictions))
    except ValueError:
        metrics['roc_auc'] = float('nan')
        
    return metrics

def run_benchmark(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run the benchmark on the provided samples."""
    logger.info("Starting benchmark with %d samples", len(samples))
    
    # Initialize result trackers
    results = {
        'ml': {'scores': [], 'predictions': []},
        'ensemble': {'scores': [], 'predictions': []},
        'true_risks': [],
        'true_labels': [],
        'sample_details': [],
        'start_time': datetime.utcnow().isoformat(),
        'duration_seconds': 0.0
    }
    
    start_time = time.time()
    
    # Process each sample
    for i, sample in enumerate(samples, 1):
        try:
            logger.info("Analyzing sample %d/%d: %s", i, len(samples), sample['name'])
            
            # Run analysis
            preds = run_analysis(sample['code'])
            
            # Store results
            results['ml']['scores'].append(preds['ml_score'])
            results['ml']['predictions'].append(preds['predicted_label'])
            results['ensemble']['scores'].append(preds['overall_score'])
            results['ensemble']['predictions'].append(1 if preds['overall_score'] > 0.5 else 0)
            results['true_risks'].append(sample['ground_truth_risk'])
            results['true_labels'].append(sample['ground_truth_label'])
            
            # Log progress
            logger.info(
                "Sample %d results - ML: %.2f (pred: %d), Ensemble: %.2f (pred: %d), True: %.2f (%d)",
                i, preds['ml_score'], preds['predicted_label'],
                preds['overall_score'], 1 if preds['overall_score'] > 0.5 else 0,
                sample['ground_truth_risk'], sample['ground_truth_label']
            )
            
        except Exception as e:
            logger.error("Error processing sample %d (%s): %s", i, sample.get('name', 'unnamed'), str(e))
            # Add placeholders for failed samples
            results['ml']['scores'].append(0.5)
            results['ml']['predictions'].append(0)
            results['ensemble']['scores'].append(0.5)
            results['ensemble']['predictions'].append(0)
            results['true_risks'].append(sample['ground_truth_risk'])
            results['true_labels'].append(sample['ground_truth_label'])
    
    # Calculate duration
    duration = time.time() - start_time
    results['duration_seconds'] = duration
    results['end_time'] = datetime.utcnow().isoformat()
    results['samples_per_second'] = len(samples) / duration if duration > 0 else 0
    
    # Calculate metrics
    results['metrics'] = {
        'ml': calculate_metrics(
            results['true_risks'],
            results['ml']['scores'],
            results['true_labels'],
            results['ml']['predictions']
        ),
        'ensemble': calculate_metrics(
            results['true_risks'],
            results['ensemble']['scores'],
            results['true_labels'],
            results['ensemble']['predictions']
        )
    }
    
    # Add confusion matrix
    results['confusion_matrix'] = {
        'ml': confusion_matrix(results['true_labels'], results['ml']['predictions']).tolist(),
        'ensemble': confusion_matrix(results['true_labels'], results['ensemble']['predictions']).tolist()
    }
    
    logger.info("Benchmark completed in %.2f seconds (%.2f samples/sec)", 
               duration, results['samples_per_second'])
    
    return results

# Run the benchmark
benchmark_results = run_benchmark(samples)

# Print summary
print("\n" + "="*80)
print("BENCHMARK RESULTS")
print("="*80)
print(f"\nTotal samples: {len(samples)}")
print(f"Duration: {benchmark_results['duration_seconds']:.2f} seconds")
print(f"Throughput: {benchmark_results['samples_per_second']:.2f} samples/second")

print("\nML Model Performance:")
for metric, value in benchmark_results['metrics']['ml'].items():
    print(f"  {metric.upper()}: {value:.4f}")

print("\nEnsemble Model Performance:")
for metric, value in benchmark_results['metrics']['ensemble'].items():
    print(f"  {metric.upper()}: {value:.4f}")

# Save detailed results
output_file = f"benchmark_results_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
with open(output_file, 'w') as f:
    json.dump(benchmark_results, f, indent=2)

print(f"\nDetailed results saved to: {output_file}")

# Print final results
print("\nBenchmark Results:")
print("=" * 80)
print(f"Total samples processed: {len(samples)}")
print(f"Duration: {benchmark_results['duration_seconds']:.2f} seconds")
print(f"Throughput: {benchmark_results['samples_per_second']:.2f} samples/second")

# Print ML metrics
print("\nML Model Performance:")
for metric, value in benchmark_results['metrics']['ml'].items():
    print(f"  {metric.upper()}: {value:.4f}")

# Print Ensemble metrics
print("\nEnsemble Model Performance:")
for metric, value in benchmark_results['metrics']['ensemble'].items():
    print(f"  {metric.upper()}: {value:.4f}")

print("\n" + "=" * 80)
print(json.dumps(results, indent=2))

# Save to file
with open('benchmark_results.json', 'w') as f:
    json.dump(results, f, indent=2)
print("Results saved to benchmark_results.json")