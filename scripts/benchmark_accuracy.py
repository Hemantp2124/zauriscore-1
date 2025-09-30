"""Benchmark script for ML (CodeBERT) and ensemble scoring accuracy in ZauriScore."""

import os
import json
from sklearn.metrics import mean_squared_error, f1_score, accuracy_score
import numpy as np
from zauriscore.analyzers.comprehensive_contract_analysis import ComprehensiveContractAnalyzer

# Sample contracts: simple safe and vulnerable examples
# Ground truth: risk scores (0-1, lower better) for regression; labels (0 safe, 1 vulnerable) for classification
samples = [
    {
        'name': 'Simple Safe Contract',
        'code': 'pragma solidity ^0.8.0; contract Safe { function transfer() public {} }',
        'ground_truth_risk': 0.2,  # Low risk
        'ground_truth_label': 0    # Safe
    },
    {
        'name': 'Reentrancy Vulnerable',
        'code': 'pragma solidity ^0.8.0; contract Vulnerable { mapping(address=>uint) balances; function withdraw() public { msg.sender.call.value(balances[msg.sender])(); } }',
        'ground_truth_risk': 0.9,  # High risk
        'ground_truth_label': 1    # Vulnerable
    },
    {
        'name': 'Another Safe',
        'code': 'pragma solidity ^0.8.0; contract Secure { uint public balance; function deposit() public payable { balance += msg.value; } }',
        'ground_truth_risk': 0.1,
        'ground_truth_label': 0
    },
    {
        'name': 'Unchecked Send Vulnerable',
        'code': 'pragma solidity ^0.8.0; contract Bad { function send() public { address(0x0).send(msg.value); } }',
        'ground_truth_risk': 0.8,
        'ground_truth_label': 1
    }
]

# For temporary files (analyzer writes to temp)
def run_analysis(code, temp_dir='temp_benchmark'):
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    with open(os.path.join(temp_dir, 'contract.sol'), 'w') as f:
        f.write(code)
    analyzer = ComprehensiveContractAnalyzer()
    # Note: For real contracts, pass address; here simulate with source
    # Assuming analyzer can handle source; adjust if needed
    result = analyzer.analyze_contract(source_code=code)  # Modify analyzer if needed to accept source_code
    return {
        'ml_score': result.get('ml_score', 0.5),
        'overall_score': result.get('overall_score', 0.5),
        'predicted_label': 1 if result.get('ml_score', 0.5) > 0.5 else 0  # Threshold 0.5
    }

# Run benchmarks
ml_predictions = []
ml_true_risks = []
labels_true = []
labels_pred = []
ensemble_predictions = []
ensemble_true_risks = []

for sample in samples:
    print(f"Analyzing: {sample['name']}")
    preds = run_analysis(sample['code'])
    print(f"ML Score: {preds['ml_score']}, Overall: {preds['overall_score']}, Label: {preds['predicted_label']}")
    
    ml_predictions.append(preds['ml_score'])
    ml_true_risks.append(sample['ground_truth_risk'])
    labels_true.append(sample['ground_truth_label'])
    labels_pred.append(preds['predicted_label'])
    
    ensemble_predictions.append(preds['overall_score'])
    ensemble_true_risks.append(sample['ground_truth_risk'])

# Compute metrics
ml_mse = mean_squared_error(ml_true_risks, ml_predictions)
ensemble_mse = mean_squared_error(ensemble_true_risks, ensemble_predictions)
class_f1 = f1_score(labels_true, labels_pred, average='weighted')
class_acc = accuracy_score(labels_true, labels_pred)

results = {
    'ml_mse': float(ml_mse),
    'ensemble_mse': float(ensemble_mse),
    'classification_f1': float(class_f1),
    'classification_accuracy': float(class_acc),
    'samples': len(samples)
}

print("\nBenchmark Results:")
print(json.dumps(results, indent=2))

# Save to file
with open('benchmark_results.json', 'w') as f:
    json.dump(results, f, indent=2)
print("Results saved to benchmark_results.json")