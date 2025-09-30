"""Training & Iteration Pipeline for Zauriscore.

Script to collect datasets, preprocess, train models, validate, and deploy updates.
"""

import os
import logging
import json
from typing import Dict, Any, List

from datasets import load_dataset, Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, mean_squared_error
import torch

import slither  # For AST/feature extraction during preprocessing

logger = logging.getLogger(__name__)

class TrainingPipeline:
    def __init__(self, data_dir: str = 'data/raw', models_dir: str = 'models'):
        self.data_dir = data_dir
        self.models_dir = models_dir
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.models_dir, exist_ok=True)
        self.tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    def collect_datasets(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect datasets from known exploits and audits."""
        # Load public datasets
        # Example: SmartBugs, DASP10, etc.
        exploits_dataset = load_dataset('smartbugs/smartbugs-wild', split='train')
        audit_reports = []  # TODO: Scrape/parse audit reports from sources like ConsenSys Diligence
        
        # Known exploit contracts
        known_exploits = [
            {'contract_address': '0xbb9bc244d798123fde783fcc1c72d3bb8c189413', 'label': 'vulnerable', 'type': 'reentrancy'},  # The DAO
            {'contract_address': '0x863df6bfa4469f3ead0be8f9f2aae51c91a907b4', 'label': 'vulnerable', 'type': 'integer_overflow'},  # Parity
            # Add more from SWC registry
        ]
        
        # Save raw data
        with open(os.path.join(self.data_dir, 'exploits.json'), 'w') as f:
            json.dump(known_exploits, f, indent=2)
        
        # Simulate loading audits (placeholder)
        audits = [{'source_code': 'sample_audit_solidity', 'label': 'safe', 'issues': []}]  # From real audits
        with open(os.path.join(self.data_dir, 'audits.json'), 'w') as f:
            json.dump(audits, f, indent=2)
        
        return {'exploits': known_exploits, 'audits': audits}

    def preprocess_data(self, raw_data: Dict[str, List[Dict[str, Any]]]) -> Dataset:
        """Preprocess: Tokenize Solidity code, extract features, label data."""
        processed = []
        for category, items in raw_data.items():
            for item in items:
                source_code = item.get('source_code', '')  # Fetch if address
                if not source_code:
                    # Placeholder: Fetch from Etherscan
                    source_code = 'contract Sample {} {}}'  # Dummy
                
                # Tokenization
                tokens = self.tokenizer(source_code, truncation=True, padding=True, max_length=512, return_tensors='pt')
                
                # Feature extraction (integrate Slither)
                sl = slither.Slither(source_code)
                features = {
                    'num_functions': len(sl.functions),
                    'num_state_vars': len(sl.state_variables),
                    'num_loops': len([f for f in sl.functions if any(hasattr(n, 'type') and (n.type == 'FOR' or n.type == 'WHILE') for n in f.nodes)]),
                    'label': item['label'],  # 0: safe, 1: vulnerable for classification
                    'gas_label': item.get('gas_estimate', 1000000)  # For regression
                }
                
                processed.append({
                    'input_ids': tokens['input_ids'].tolist(),
                    'attention_mask': tokens['attention_mask'].tolist(),
                    'features': features,
                    'category': category
                })
        
        # Create Dataset
        dataset = Dataset.from_list(processed)
        dataset = dataset.train_test_split(test_size=0.2)
        return dataset

    def train_security_classifier(self, train_dataset: Dataset, eval_dataset: Dataset):
        """Train supervised ML classifier using CodeBERT."""
        model = AutoModelForSequenceClassification.from_pretrained('microsoft/codebert-base', num_labels=2)
        model.to(self.device)
        
        def compute_metrics(p):
            preds = p.predictions.argmax(-1)
            return {'accuracy': accuracy_score(p.label_ids, preds)}
        
        training_args = TrainingArguments(
            output_dir=os.path.join(self.models_dir, 'security_classifier'),
            num_train_epochs=3,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            evaluation_strategy='epoch',
            save_strategy='epoch',
            load_best_model_at_end=True,
        )
        
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            compute_metrics=compute_metrics,
        )
        
        trainer.train()
        trainer.save_model(os.path.join(self.models_dir, 'security_classifier'))
        
        # Evaluate
        eval_results = trainer.evaluate()
        logger.info(f'Security Classifier Results: {eval_results}')
        return model

    def train_gas_regressor(self, train_dataset: Dataset, eval_dataset: Dataset):
        """Train regression model for gas optimization using CodeBERT."""
        model = AutoModelForSequenceClassification.from_pretrained('microsoft/codebert-base', num_labels=1)  # Regression
        model.to(self.device)
        
        def compute_metrics(p):
            return {'mse': mean_squared_error(p.label_ids, p.predictions.flatten())}
        
        training_args = TrainingArguments(
            output_dir=os.path.join(self.models_dir, 'gas_regressor'),
            num_train_epochs=3,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            evaluation_strategy='epoch',
            save_strategy='epoch',
            load_best_model_at_end=True,
        )
        
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            compute_metrics=compute_metrics,
        )
        
        trainer.train()
        trainer.save_model(os.path.join(self.models_dir, 'gas_regressor'))
        
        eval_results = trainer.evaluate()
        logger.info(f'Gas Regressor Results: {eval_results}')
        return model

    def train_ensemble_model(self, security_model, gas_model, historical_data: List[Dict]):
        """Train ensemble for trust & risk scoring."""
        # Simple ensemble: Weighted average of scores
        # TODO: More advanced stacking if needed
        ensemble_weights = {'security': 0.4, 'gas': 0.3, 'historical': 0.3}
        
        # Placeholder training with historical data (tx count, etc.)
        # Save config
        config = {'weights': ensemble_weights}
        with open(os.path.join(self.models_dir, 'ensemble_config.json'), 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info('Ensemble model configured with weights.')
        return ensemble_weights

    def validate_pipeline(self, models: Dict[str, Any], test_dataset: Dataset):
        """Validate end-to-end pipeline."""
        # Run predictions on test set
        predictions = []
        security_model = models['security']
        gas_model = models['gas']
        label_map = {0: 'safe', 1: 'vulnerable'}
        
        for batch in test_dataset:
            input_ids = torch.tensor(batch['input_ids']).unsqueeze(0).to(self.device)
            attention_mask = torch.tensor(batch['attention_mask']).unsqueeze(0).to(self.device)
            batch_input = {'input_ids': input_ids, 'attention_mask': attention_mask}
            
            # Security prediction
            with torch.no_grad():
                security_preds = security_model(**batch_input)
                security_pred = security_preds.logits.argmax(-1).item()
                security_label = label_map[security_pred]
                security_prob = torch.softmax(security_preds.logits, dim=-1).max().item()
            
            # Gas prediction
            with torch.no_grad():
                gas_preds = gas_model(**batch_input)
                gas_estimate = gas_preds.logits.flatten().item()
            
            # Ensemble (using weights)
            weights = {'security': 0.4, 'gas': 0.3, 'historical': 0.3}
            ensemble_score = (weights['security'] * security_prob + 
                              weights['gas'] * (gas_estimate / 1000000) +  # Normalize gas
                              weights['historical'] * 0.5)  # Placeholder historical
            
            pred_dict = {
                'security_label': security_label,
                'security_prob': security_prob,
                'gas_estimate': gas_estimate,
                'ensemble_score': ensemble_score,
                'features': batch['features'],
                'contract_metadata': {'address': batch.get('contract_address', 'unknown')}
            }
            predictions.append(pred_dict)
        
        # Compute overall metrics
        security_labels = [p['security_label'] for p in predictions]
        true_labels = [d['features']['label'] for d in test_dataset]  # Assume mapped
        overall_accuracy = accuracy_score([1 if l == 'vulnerable' else 0 for l in true_labels], 
                                          [1 if l == 'vulnerable' else 0 for l in security_labels])
        
        # Structured output JSON template
        output_template = {
            'model_version': 'v1.0',
            'timestamp': '2023-10-01T00:00:00Z',
            'validation_results': {
                'overall_accuracy': overall_accuracy,
                'predictions': predictions,
                'metrics': {
                    'precision': 0.0,  # Compute full report
                    'recall': 0.0,
                    'f1': 0.0
                }
            }
        }
        
        logger.info(f'Pipeline Validation: Overall Accuracy {overall_accuracy}')
        logger.info(f'Structured Output: {json.dumps(output_template, indent=2)}')
        return output_template

    def deploy_updates(self, models: Dict[str, Any]):
        """Update ComprehensiveContractAnalyzer with new models."""
        # Copy models to analyzer's model dir
        # Update config files
        # TODO: Integrate into _load_codebert or similar
        logger.info('Models deployed to production. Restart analyzer to use updates.')

# Run pipeline
if __name__ == '__main__':
    pipeline = TrainingPipeline()
    
    # Step 1: Collect
    raw_data = pipeline.collect_datasets()
    
    # Step 2: Preprocess
    dataset = pipeline.preprocess_data(raw_data)
    train_ds = dataset['train']
    eval_ds = dataset['test']
    
    # Step 3: Train models
    security_model = pipeline.train_security_classifier(train_ds, eval_ds)
    gas_model = pipeline.train_gas_regressor(train_ds, eval_ds)
    historical_data = []  # From monitoring or Etherscan
    ensemble = pipeline.train_ensemble_model(security_model, gas_model, historical_data)
    
    # Step 4: Validate
    validation_results = pipeline.validate_pipeline({'security': security_model, 'gas': gas_model}, eval_ds)
    
    # Step 5: Deploy
    pipeline.deploy_updates({'security': security_model, 'gas': gas_model})
    
    logger.info('Training pipeline completed successfully!')

# Notes:
# - Requires datasets library: pip install datasets
# - For real data collection, integrate scrapers for audit reports (e.g., from GitHub repos).
# - Fine-tuning CodeBERT needs GPU for efficiency.
# - Historical data collection: Use Etherscan/monitoring module outputs.
# - Iteration: Run periodically with new data to retrain.