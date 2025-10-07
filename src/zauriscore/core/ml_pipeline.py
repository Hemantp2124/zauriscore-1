import os
import json
import logging
import concurrent.futures
from datetime import datetime
import numpy as np
import torch
from typing import Dict, Any, List

# Ensure logging is configured
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Third-party imports
import pandas as pd
from torch.utils.data import Dataset, DataLoader
from transformers import RobertaTokenizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score

# Local imports
from ..data.contract_source_retriever import ContractSourceRetriever
from ..analyzers.heuristic_analyzer import HeuristicAnalyzer
from ..models.codebert import CodeBERTRegressor
from ..reporting.consolidated_report_generator import create_report_generator

# Configuration
HIGH_RISK_THRESHOLD = 60
LEARNING_THRESHOLD = 10
MAX_PARALLEL_CONTRACTS = 10

class ZauriScoreMLPipeline:
    """Comprehensive Machine Learning Pipeline for ZauriScore™ Smart Contract Security Analysis"""
    def __init__(self, 
                 model_path='../models/zauriscore_regression_model.pth',
                 data_dir='../datasets',
                 log_dir='../logs'):
        """
        Initialize ZauriScore ML Pipeline
        
        Args:
            model_path (str, optional): Path to pre-trained model
            data_dir (str, optional): Directory for dataset storage
            log_dir (str, optional): Directory for log files
        """
        # Logging setup
        self.logger = self._setup_logging(log_dir)
        
        # Directories and Paths
        self.model_path = model_path
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        
        # Model and tokenizer initialization
        self.tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')
        
        # Load or initialize model
        self.model = CodeBERTRegressor()
        
        if model_path and os.path.exists(model_path):
            try:
                # Try loading state dict
                state_dict = torch.load(model_path)
                self.model.load_state_dict(state_dict)
                self.logger.info('Existing model state loaded successfully.')
            except Exception as e:
                self.logger.error(f'Failed to load model state: {e}')
        
        # Ensure model is in evaluation mode
        self.model.eval()
        
        # Auxiliary Systems
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.etherscan_retriever = ContractSourceRetriever()
        
        # Learning Management
        self.learning_queue = []
        self.BATCH_SIZE = 16
        self.MAX_QUEUE_SIZE = 100
        
        # Community Feedback Mechanism
        self.community_feedback = {}
    
    def _setup_logging(self, log_dir):
        """
        Configure logging for the ML pipeline.
        
        Args:
            log_dir (str): Directory for log files
        
        Returns:
            logging.Logger: Configured logger
        """
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ZauriScore™ ML Pipeline - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'ml_pipeline.log')),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def intelligent_detection(self, contract_codes):
        """
        Perform intelligent risk detection using CodeBERT
        
        Args:
            contract_codes (list or str): Contract source code(s)
        
        Returns:
            list or dict: Risk analysis for contract(s)
        """
        # Ensure input is a list
        single_input = isinstance(contract_codes, str)
        if single_input:
            contract_codes = [contract_codes]
        
        # Tokenize and preprocess contracts
        tokenized_contracts = self.tokenizer(
            contract_codes, 
            padding=True, 
            truncation=True, 
            max_length=512, 
            return_tensors='pt'
        )
        
        # Predict risk scores
        with torch.no_grad():
            outputs = self.model.codebert(
                input_ids=tokenized_contracts['input_ids'], 
                attention_mask=tokenized_contracts['attention_mask']
            )
            pooled_output = outputs.last_hidden_state[:, 0, :]
            
            # Handle single sample case
            if pooled_output.size(0) == 1:
                # Add a dummy batch dimension for batch normalization
                pooled_output = torch.cat([pooled_output, pooled_output], dim=0)
                predictions = self.model.regressor(pooled_output)[0]
            else:
                predictions = self.model.regressor(pooled_output).squeeze()
        
        # Combine with heuristic analysis
        risk_analyses = []
        for i, contract_code in enumerate(contract_codes):
            # Extract AI risk score
            if len(contract_codes) > 1:
                ai_risk_score = predictions[i].item()
            else:
                ai_risk_score = predictions.item()
            
            # Perform heuristic analysis
            heuristic_result = self.heuristic_analyzer.analyze(contract_code)
            
            # Combine AI and heuristic scores
            final_risk_score = (ai_risk_score + heuristic_result['score']) / 2
            
            risk_analysis = {
                'ai_risk_score': ai_risk_score,
                'heuristic_score': heuristic_result['score'],
                'final_risk_score': final_risk_score,
                'risk_category': heuristic_result['risk_category'],
                'detected_vulnerabilities': heuristic_result['vulnerabilities'],
                'confidence': min(max(final_risk_score, 0), 100)
            }
            
            risk_analyses.append(risk_analysis)
        
        # Return single result for single input
        return risk_analyses[0] if single_input else risk_analyses
    
    def collect_contract_data(self, contract_code, actual_score=None):
        """
        Collect contract data for continuous learning
        
        Args:
            contract_code (str): Smart contract source code
            actual_score (float, optional): Actual risk score
        
        Returns:
            dict: Collected contract data
        """
        # Complexity metrics
        complexity = self._calculate_complexity(contract_code)
        
        # Predict risk
        predicted_score = self.predict_risk(contract_code)
        
        # Collect data
        contract_data = {
            'code': contract_code,
            'predicted_score': predicted_score,
            'actual_score': actual_score,
            'complexity': complexity,
            'timestamp': datetime.now()
        }
        
        return contract_data
    
    def _calculate_complexity(self, contract_code):
        """
        Calculate contract complexity metrics
        
        Args:
            contract_code (str): Smart contract source code
        
        Returns:
            dict: Complexity metrics
        """
        return {
            'line_count': len(contract_code.splitlines()),
            'function_count': contract_code.count('function '),
            'complexity_score': len(contract_code) / 100  # Simple complexity metric
        }
    
    def continuous_learning(self, contract_code, actual_risk_score=None):
        """
        Implement continuous learning mechanism
        
        Args:
            contract_code (str): Smart contract source code
            actual_risk_score (float, optional): Actual risk score from community
        
        Returns:
            dict: Learning update details
        """
        # Predict initial risk
        predicted_score = self.predict_risk(contract_code)
        
        # Learning entry
        learning_entry = {
            'contract_code': contract_code,
            'predicted_score': predicted_score,
            'actual_score': actual_risk_score,
            'timestamp': datetime.now()
        }
        
        # Add to learning queue
        self.learning_queue.append(learning_entry)
        
        # Check for retraining
        if len(self.learning_queue) >= self.MAX_QUEUE_SIZE:
            self.batch_retrain()
        
        return {
            'predicted_score': predicted_score,
            'learning_queue_size': len(self.learning_queue)
        }
    
    def predict_risk(self, contract_code):
        """
        Predict risk score for a given contract code
        
        Args:
            contract_code (str): Smart contract source code
        
        Returns:
            float: Predicted risk score
        """
        # Tokenize contract code
        inputs = self.tokenizer(
            contract_code, 
            padding=True, 
            truncation=True, 
            max_length=512, 
            return_tensors='pt'
        )
        
        # Predict score
        with torch.no_grad():
            outputs = self.model.codebert(
                input_ids=inputs['input_ids'], 
                attention_mask=inputs['attention_mask']
            )
            pooled_output = outputs.last_hidden_state[:, 0, :]
            
            # Handle single sample case
            if pooled_output.size(0) == 1:
                # Add a dummy batch dimension for batch normalization
                pooled_output = torch.cat([pooled_output, pooled_output], dim=0)
                score = self.model.regressor(pooled_output)[0]
            else:
                score = self.model.regressor(pooled_output).squeeze()
        
        return float(score.numpy())

    def categorize(self, score: float) -> str:
        """Categorize a risk score into buckets.

        Centralizes thresholding so other modules (e.g., report generation)
        do not hardcode their own thresholds.
        """
        try:
            s = float(score)
        except Exception:
            return "Unknown"
        if s > 75:
            return "High"
        if s > 40:
            return "Medium"
        return "Low"
    
    def batch_retrain(self):
        """
        Perform batch retraining when learning queue is full.
        Uses only entries with actual scores for training.
        """
        # Filter entries with actual scores
        trainable_entries = [
            entry for entry in self.learning_queue 
            if entry['actual_score'] is not None
        ]
        
        if not trainable_entries:
            self.logger.info("No entries with actual scores for retraining.")
            return
        
        # Prepare training data
        contracts = [entry['contract_code'] for entry in trainable_entries]
        actual_scores = [entry['actual_score'] for entry in trainable_entries]
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            contracts, actual_scores, test_size=0.2, random_state=42
        )
        
        # Training logic (simplified)
        train_dataset = ContractRegressionDataset(
            X_train, y_train, self.tokenizer
        )
        train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True)
        
        # Optimizer and Loss
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=2e-5)
        criterion = torch.nn.MSELoss()
        
        # Training loop
        self.model.train()
        for epoch in range(3):  # Short incremental training
            total_loss = 0
            for batch in train_loader:
                optimizer.zero_grad()
                
                predictions = self.model(
                    batch['input_ids'], 
                    batch['attention_mask']
                )
                loss = criterion(predictions, batch['score'])
                
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
            
            self.logger.info(f"Retraining Epoch {epoch+1}, Loss: {total_loss}")
        
        # Evaluate
        self.model.eval()
        with torch.no_grad():
            test_predictions = [
                self.predict_risk(code) for code in X_test
            ]
            mse = mean_squared_error(y_test, test_predictions)
            r2 = r2_score(y_test, test_predictions)
        
        self.logger.info(f"Retraining Metrics - MSE: {mse}, R2: {r2}")
        
        # Save updated model
        torch.save(self.model.state_dict(), self.model_path)
        
        # Clear learning queue
        self.learning_queue.clear()
    
    def generate_report(self):
        """Generate a report of learning progress.
        
        Returns:
            dict: Learning statistics
        """
        # Check if there's any learning data
        if not self.learning_queue:
            return {'status': 'No learning data available'}
        
        # Compute basic statistics
        learning_stats = {
            'total_samples': len(self.learning_queue),
            'unique_contracts': len(set(entry['code'] for entry in self.learning_queue)),
            'avg_complexity': sum(entry.get('complexity', {}).get('complexity_score', 0) for entry in self.learning_queue) / len(self.learning_queue),
            'status': 'Learning in progress'
        }
        
        return learning_stats
    
    def analyze_contract(self, contract_code, heuristic_analyzer=None):
        """Comprehensive contract analysis method.
        
        Args:
            contract_code (str): Source code of the smart contract
            heuristic_analyzer (HeuristicAnalyzer, optional): Pre-initialized heuristic analyzer
        
        Returns:
            dict: Comprehensive contract analysis results
        """
        # Use default heuristic analyzer if not provided
        if heuristic_analyzer is None:
            heuristic_analyzer = HeuristicAnalyzer()
        
        # Predict initial risk score
        ai_score = self.predict_risk(contract_code)
        
        # Calculate contract complexity
        complexity = self._calculate_complexity(contract_code)
        
        # Perform heuristic analysis
        heuristic_result = heuristic_analyzer.analyze(contract_code)
        
        # Combine AI and heuristic scores
        final_score = (ai_score * 0.6) + (heuristic_result.get('total_score', 0) * 0.4)
        
        # Determine risk category
        if final_score < 30:
            risk_category = 'High Risk'
        elif final_score < 50:
            risk_category = 'Moderate Risk'
        elif final_score < 70:
            risk_category = 'Low Risk'
        else:
            risk_category = 'Safe'
        
        # Collect contract data for continuous learning
        self.collect_contract_data(contract_code, actual_score=final_score)
        
        # Prepare detailed analysis result
        analysis_result = {
            'ai_score': ai_score,
            'heuristic_score': heuristic_result.get('score', 0),
            'final_score': final_score,
            'risk_category': risk_category,
            'complexity': complexity,
            'detected_vulnerabilities': heuristic_result.get('vulnerabilities', []),
            'confidence': 85.0,  # Placeholder confidence
            'timestamp': datetime.now()
        }
        
        return analysis_result

class ContractRegressionDataset(torch.utils.data.Dataset):
    def __init__(self, contracts, scores, tokenizer, max_length=512):
        self.contracts = contracts
        self.scores = torch.tensor(scores, dtype=torch.float32)
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.contracts)

    def __getitem__(self, idx):
        contract = self.contracts[idx]
        encoding = self.tokenizer(
            contract, 
            truncation=True, 
            padding='max_length', 
            max_length=self.max_length, 
            return_tensors='pt'
        )
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'score': self.scores[idx]
        }

def main():
    # Initialize ML Pipeline
    ml_pipeline = ZauriScoreMLPipeline()
    
    # Parse command-line arguments
    import argparse
    parser = argparse.ArgumentParser(description='ZauriScore Contract Analysis')
    parser.add_argument('--input', type=str, help='Contract file path or Ethereum address')
    parser.add_argument('--mode', type=str, choices=['file', 'address'], default='file', help='Analysis mode')
    args = parser.parse_args()
    
    # Perform analysis based on mode
    if args.mode == 'address':
        # Fetch contract source code from Etherscan
        try:
            # Dynamically import to ensure module is loaded
            from contract_source_retriever import ContractSourceRetriever
            
            # Initialize source retriever
            source_retriever = ContractSourceRetriever()
            
            # Fetch contract source code
            contract_code = source_retriever.fetch_source_code(args.input)
            
            if contract_code:
                # Analyze contract
                heuristic_analyzer = HeuristicAnalyzer()
                analysis_result = ml_pipeline.analyze_contract(contract_code, heuristic_analyzer)
                
                # Print detailed analysis
                print("\nZauriScore Contract Security Analysis")
                print(f"Contract Address: {args.input}")
                print("\nRisk Assessment:")
                print(f"  AI Risk Score:      {analysis_result.get('ai_score', 'N/A'):.2f}")
                print(f"  Heuristic Score:    {analysis_result.get('heuristic_score', 'N/A'):.2f}")
                print(f"  Final Risk Score:   {analysis_result.get('final_score', 'N/A'):.2f}")
                print(f"  Risk Category:      {analysis_result.get('risk_category', 'Unknown')}")
                print(f"  Confidence:         {analysis_result.get('confidence', 'N/A'):.2f}%")
                
                # Vulnerability Details
                vulnerabilities = analysis_result.get('detected_vulnerabilities', [])
                if vulnerabilities:
                    print("\nDetected Vulnerabilities:")
                    for vuln in vulnerabilities:
                        print(f"  - {vuln}")
                else:
                    print("\nNo significant vulnerabilities detected.")
            else:
                print(f"Could not retrieve source code for address: {args.input}")
        
        except ImportError as e:
            print(f"Import error: {e}")
        except Exception as e:
            print(f"Error analyzing contract: {e}")
    
    elif args.mode == 'file':
        # Existing file analysis logic
        result = analyze_contract_file(args.input)
        if result:
            print("Contract File Analysis Complete")
        else:
            print("Contract File Analysis Failed")


def analyze_contract_file(contract_file, heuristic_analyzer=None):
    """
    Analyze a smart contract from a file
    
    Args:
        contract_file (str): Path to the Solidity contract file
        heuristic_analyzer (HeuristicAnalyzer, optional): Pre-initialized heuristic analyzer
    
    Returns:
        dict: Comprehensive contract security analysis
    """
    # Validate input
    if not contract_file or not isinstance(contract_file, str):
        logging.error("Invalid contract file path")
        return None
    
    # Normalize file path
    contract_file = os.path.abspath(contract_file)
    
    # Initialize pipeline
    try:
        pipeline = ZauriScoreMLPipeline()
    except Exception as e:
        logging.error(f"Failed to initialize ML pipeline: {e}")
        return None
    
    # Initialize heuristic analyzer if not provided
    try:
        heuristic_analyzer = heuristic_analyzer or HeuristicAnalyzer()
    except Exception as e:
        logging.error(f"Failed to initialize heuristic analyzer: {e}")
        return None
    
    # Read contract source code
    try:
        with open(contract_file, 'r', encoding='utf-8') as f:
            contract_code = f.read().strip()
        
        # Validate contract code
        if not contract_code:
            logging.warning(f"Empty contract file: {contract_file}")
            return None
    except FileNotFoundError:
        logging.error(f"Contract file not found: {contract_file}")
        return None
    except PermissionError:
        logging.error(f"Permission denied reading contract file: {contract_file}")
        return None
    except Exception as e:
        logging.error(f"Error reading contract file: {e}")
        return None
    
    # Analyze the contract
    try:
        result = pipeline.analyze_contract(contract_code, heuristic_analyzer)
        
        # Enrich result with file context
        result['contract_file'] = contract_file
        result['analysis_timestamp'] = datetime.now()
        
        # Log analysis details
        logging.info(f"Successfully analyzed contract: {contract_file}")
        logging.info(f"Risk Score: {result.get('final_score', 'N/A')}")
        logging.info(f"Risk Category: {result.get('risk_category', 'Unknown')}")
        
        return result
    except Exception as e:
        logging.error(f"Contract analysis failed for {contract_file}: {e}")
        return None

if __name__ == '__main__':
    main()
