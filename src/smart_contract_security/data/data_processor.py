import os
import json
import logging
import pandas as pd
from typing import List, Dict, Any, Tuple
from .contract_source_retriever import ContractSourceRetriever

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DataProcessor:
    """Unified data processing class for smart contract analysis"""
    
    def __init__(self, data_dir: str = '../datasets'):
        """
        Initialize data processor
        
        Args:
            data_dir (str): Directory containing dataset files
        """
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.source_retriever = ContractSourceRetriever()
    
    def prepare_training_data(self, 
                            input_file: str, 
                            output_file: str,
                            include_features: bool = True) -> pd.DataFrame:
        """
        Prepare training data from raw contract data
        
        Args:
            input_file (str): Path to input JSON file
            output_file (str): Path to save processed data
            include_features (bool): Whether to include extracted features
            
        Returns:
            pd.DataFrame: Processed dataset
        """
        logger.info("Loading raw data...")
        with open(input_file, 'r') as f:
            raw_data = json.load(f)
        
        processed_data = []
        for item in raw_data:
            try:
                processed_item = self._process_contract_data(item)
                if processed_item:
                    processed_data.append(processed_item)
            except Exception as e:
                logger.warning(f"Error processing contract: {str(e)}")
        
        df = pd.DataFrame(processed_data)
        
        if include_features:
            logger.info("Extracting features...")
            df = self._extract_features(df)
        
        # Save processed data
        df.to_csv(output_file, index=False)
        logger.info(f"Saved processed data to {output_file}")
        
        return df
    
    def _process_contract_data(self, raw_item: Dict[str, Any]) -> Dict[str, Any]:
        """Process individual contract data"""
        processed = {
            'address': raw_item.get('address'),
            'contract_name': raw_item.get('contract_name'),
            'source_code': raw_item.get('source_code'),
            'compiler_version': raw_item.get('compiler_version'),
            'optimization_used': raw_item.get('optimization_used'),
            'risk_score': raw_item.get('risk_score', 0)
        }
        
        # Fetch source code if not present
        if not processed['source_code'] and processed['address']:
            contract_data = self.source_retriever.get_contract_source(processed['address'])
            if contract_data:
                processed['source_code'] = contract_data.get('SourceCode')
                processed['contract_name'] = contract_data.get('ContractName')
                processed['compiler_version'] = contract_data.get('CompilerVersion')
        
        return processed if processed['source_code'] else None
    
    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from contract source code"""
        # Add basic code metrics
        df['code_length'] = df['source_code'].str.len()
        df['num_functions'] = df['source_code'].str.count('function')
        df['num_modifiers'] = df['source_code'].str.count('modifier')
        
        # Add security pattern features
        df['has_reentrancy_guard'] = df['source_code'].str.contains('nonReentrant|ReentrancyGuard')
        df['has_access_control'] = df['source_code'].str.contains('Ownable|AccessControl')
        df['has_safe_math'] = df['source_code'].str.contains('SafeMath')
        
        return df
    
    def split_dataset(self, 
                     df: pd.DataFrame,
                     test_size: float = 0.2,
                     val_size: float = 0.1) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Split dataset into train, validation, and test sets"""
        from sklearn.model_selection import train_test_split
        
        # First split: separate test set
        train_val, test = train_test_split(df, test_size=test_size, random_state=42)
        
        # Second split: separate validation set from training set
        val_ratio = val_size / (1 - test_size)
        train, val = train_test_split(train_val, test_size=val_ratio, random_state=42)
        
        return train, val, test

def main():
    """Example usage"""
    try:
        processor = DataProcessor()
        df = processor.prepare_training_data(
            input_file='../datasets/raw_contracts.json',
            output_file='../datasets/processed_contracts.csv'
        )
        
        train, val, test = processor.split_dataset(df)
        print(f"Dataset splits: Train={len(train)}, Val={len(val)}, Test={len(test)}")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
