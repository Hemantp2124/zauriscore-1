import pandas as pd
from transformers import CodeBERTModel, AutoTokenizer
import torch
import tempfile
import os
from src.zauriscore.analyzers.cfg_taint_analyzer import CFGTAintAnalyzer

class FeatureExtractor:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
        self.model = CodeBERTModel.from_pretrained('microsoft/codebert-base')
    
    def extract(self, contract_code):
        metrics = {
            'function_count': len(contract_code.split('function')),
            'security_flags': 1 if 'revert' in contract_code.lower() else 0,
            'complexity': len(contract_code.split('if'))
        }
        
        # Add CFG/Taint features
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as tmp_file:
            tmp_file.write(contract_code)
            tmp_path = tmp_file.name
        
        try:
            analyzer = CFGTAintAnalyzer(tmp_path)
            analyzer.extract_cfg()
            analyzer.perform_taint_analysis()
            ml_features = analyzer.generate_features_for_ml()
            
            # Aggregate features across functions (simple average for now)
            agg_features = {}
            for func_features in ml_features.values():
                for k, v in func_features.items():
                    if isinstance(v, (int, float)):
                        agg_features[f'{k}_avg'] = agg_features.get(f'{k}_avg', 0) + v
                        # Later: divide by num functions
                    elif isinstance(v, list):
                        agg_features['num_taint_paths'] = agg_features.get('num_taint_paths', 0) + len(v)
            
            # Num functions for normalization
            num_funcs = len(ml_features)
            if num_funcs > 0:
                for k in ['num_nodes_avg', 'num_edges_avg', 'avg_degree_avg', 'density_avg', 'longest_path_avg', 'num_tainted_ops_avg']:
                    if k[:-4] + '_avg' in agg_features:
                        agg_features[k] = agg_features[k[:-4] + '_avg'] / num_funcs
                        del agg_features[k[:-4] + '_avg']
                agg_features['taint_ratio_avg'] = agg_features.get('num_tainted_ops_avg', 0) / (self.metrics.get('function_count', 1) or 1)
            
            metrics.update(agg_features)
        except Exception as e:
            print(f"CFG/Taint extraction failed: {e}")  # Fallback to basic metrics
        finally:
            os.unlink(tmp_path)
        
        inputs = self.tokenizer(contract_code, return_tensors='pt', padding=True, truncation=True)
        with torch.no_grad():
            outputs = self.model(**inputs)
        embeddings = outputs.last_hidden_state.mean(dim=1).numpy().flatten()
        
        return pd.DataFrame([{**metrics, 'embeddings': embeddings}])

if __name__ == '__main__':
    extractor = FeatureExtractor()
    with open('sample.sol', 'r') as f:
        result = extractor.extract(f.read())
    result.to_parquet('output/contract_features.parquet')