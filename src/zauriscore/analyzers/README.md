# Heuristic Analyzer Module

This module provides heuristic-based analysis of Solidity smart contracts to identify potential security vulnerabilities and code quality issues.

## Features

- ML-based vulnerability detection using BERT embeddings
- Integration with Slither for static analysis
- CFG and taint-flow extraction for enhanced exploit analysis, including graph metrics and taint propagation tracking
- Numeric feature aggregation from CFG/taint for ML pipeline integration (e.g., taint_ratio, num_nodes, longest_path)
- Heuristic scoring system for smart contract security assessment
- Support for both single-file and multi-file contracts
- Comprehensive test coverage

## Requirements

- Python 3.8+
- Dependencies listed in `requirements-dev.txt`

## Installation

1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

## Running Tests

Run the full test suite:
```bash
pytest tests/ -v
```

Run tests with coverage report:
```bash
pytest tests/ --cov=zauriscore.analyzers --cov-report=term-missing
```

## Code Quality Checks

Run all quality checks:
```bash
python scripts/check_quality.py
```

Individual checks:
- `pylint zauriscore/analyzers/heuristic_analyzer.py`
- `flake8 zauriscore/analyzers/heuristic_analyzer.py`
- `mypy zauriscore/analyzers/heuristic_analyzer.py`

## Usage Example

```python
from zauriscore.analyzers.heuristic_analyzer import MLVulnerabilityWeightCalculator
from zauriscore.analyzers.cfg_taint_analyzer import CFGTAintAnalyzer

# Initialize the heuristic analyzer
heuristic_analyzer = MLVulnerabilityWeightCalculator()

# Initialize CFG/Taint analyzer
cfg_analyzer = CFGTAintAnalyzer()

# Analyze a contract for vulnerabilities
contract_code = """
pragma solidity ^0.8.0;

contract SampleContract {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function riskyTransfer(address to, uint amount) external {
        // Potential reentrancy
        to.call{value: amount}();
    }
}
"""

# Get vulnerability similarities
similarities = heuristic_analyzer.calculate_code_vulnerability_similarity(contract_code)
print("Vulnerability similarities:", similarities)

# Get CFG/Taint features
features = cfg_analyzer.extract_features(contract_code)
print("CFG/Taint features:", features)

# Assess economic risk
risk_level = heuristic_analyzer.assess_economic_risk(contract_code)
print(f"Economic risk level: {risk_level}")
```

## Code Structure

- `heuristic_analyzer.py`: Main module with the `MLVulnerabilityWeightCalculator` class and helper functions
- `cfg_taint_analyzer.py`: Control flow graph extraction and taint-flow analysis using Slither, generating features for vulnerability detection
- `comprehensive_contract_analysis.py`: Integrated analyzer combining Slither, CodeBERT, and CFG/taint features for enhanced risk scoring
- Integration with ML pipeline: Features feed into `scripts/feature_extraction.py` and `scripts/train_exploit_fine_tune.py` for CodeBERT fine-tuning with numeric inputs
- `tests/test_heuristic_analyzer.py`: Unit tests for the module (extend for CFG/taint testing)
- Configuration files:
  - `.pylintrc`: Pylint configuration
  - `.flake8`: Flake8 configuration
  - `mypy.ini`: Mypy type checking configuration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and quality checks
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
