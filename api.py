from fastapi import FastAPI
from pydantic import BaseModel
import torch
import numpy as np
from transformers import AutoTokenizer
import json
import logging
from zauriscore.analyzers.comprehensive_contract_analysis import ComprehensiveContractAnalyzer
from check_etherscan import get_contract_source_code, EtherscanClient, EtherscanConfig

app = FastAPI()

# Load saved model
model = HybridRiskModel()
model.load_state_dict(torch.load('best_model.pth'))
model.eval()

# Tokenizer setup
tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')

# Request models
class PredictionRequest(BaseModel):
    source_code: str
    structured_features: dict = None

# New request model for contract analysis
class ContractAnalysisRequest(BaseModel):
    contract_address: str
    api_key: str = None  # Etherscan API key, optional if set in config

# Etherscan config - require API key from env
api_key = os.getenv('ETHERSCAN_API_KEY')
if not api_key:
    raise ValueError("ETHERSCAN_API_KEY environment variable is required")
config = EtherscanConfig(api_key=api_key)
client = EtherscanClient(config)

# Initialize analyzer
analyzer = ComprehensiveContractAnalyzer()

# Explanation models
import shap

@app.post('/predict')
def predict(request: PredictionRequest):
    # Process input
    if request.structured_features:
        numeric_features = np.array([
            request.structured_features.get('function_count', 0),
            request.structured_features.get('security_flags', 0),
            request.structured_features.get('complexity', 0)
        ])
    else:
        numeric_features = np.zeros(3)
    
    # Tokenize code
    inputs = tokenizer(request.source_code, return_tensors='pt', padding=True, truncation=True)
    code_tokens = inputs['input_ids']
    
    # Get predictions
    with torch.no_grad():
        numeric_input = torch.tensor(numeric_features, dtype=torch.float32)
        code_input = torch.tensor(code_tokens, dtype=torch.long)
        prediction = model(numeric_input, code_input)
    
    # SHAP explainability
    explainer = shap.DeepExplainer(model, numeric_features)
    shap_values = explainer.shap_values(numeric_features)
    
    return {
        'risk_score': prediction.item(),
        'shap_values': shap_values.tolist()
    }

@app.post('/analyze')
def analyze_contract(request: ContractAnalysisRequest):
    """
    Analyze smart contract: Fetch from Etherscan, run Slither/Mythril/ML, compute weighted risk, return JSON.
    """
    try:
        contract_address = request.contract_address

        # Step 1: Fetch contract source
        source_result = get_contract_source_code(client, contract_address)
        if not source_result:
            raise HTTPException(status_code=404, detail="Contract source not found")

        # Extract source code (handle multi-file)
        source_code = source_result.get('SourceCode', '')
        if source_code.startswith('{{'):
            # Multi-file JSON
            source_json = json.loads(source_code[1:-1])  # Remove outer braces if needed
            # For simplicity, concatenate files or use first; in production, handle properly
            concatenated_source = '\n'.join([
                content.get('content', '') for content in source_json.get('sources', {}).values()
            ])
        else:
            concatenated_source = source_code

        # Step 2: Run analysis (Slither, Mythril, etc. via analyzer)
        analysis_result = analyzer.analyze_contract(
            contract_address=contract_address,
            source_code=concatenated_source  # Pass fetched source
        )

        # Step 3: Compute weighted risk (example: combine static findings and ML score)
        # Assume analysis_result has 'slither_issues', 'mythril_issues', 'ml_score'
        static_score = len(analysis_result.get('security_issues', [])) * 0.4  # Heuristic
        ml_score = analysis_result.get('codebert_analysis', {}).get('vulnerable_probability', 0) * 0.6
        weighted_risk = (static_score + ml_score) / 2  # Weighted average; adjust as needed

        # Step 4: Prepare JSON response
        response = {
            'contract_address': contract_address,
            'analysis_results': analysis_result,
            'weighted_risk_score': weighted_risk,
            'timestamp': analysis_result.get('analysis_timestamp', ''),
            'recommendations': [issue.get('recommendation', '') for issue in analysis_result.get('security_issues', []) if issue.get('recommendation')]
        }

        return response

    except Exception as e:
        logging.error(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))