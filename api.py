from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
import numpy as np
from transformers import AutoTokenizer
import json
import logging
import os
import shap
from zauriscore.analyzers.comprehensive_contract_analysis import ComprehensiveContractAnalyzer
from check_etherscan import get_contract_source_code, EtherscanClient, EtherscanConfig
from zauriscore.models.hybrid_model import HybridRiskModel

app = FastAPI(title="ZauriScore API", 
              description="AI-powered smart contract security analysis platform",
              version="0.1.0")

# Load saved model with error handling
try:
    model = HybridRiskModel()
    model_path = os.path.join(os.path.dirname(__file__), 'best_model.pth')
    model.load_state_dict(torch.load(model_path))
    model.eval()
    logging.info("Model loaded successfully")
except Exception as e:
    logging.error(f"Failed to load model: {str(e)}")
    model = None  # Will be checked before predictions

# Tokenizer setup
try:
    tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
    logging.info("Tokenizer loaded successfully")
except Exception as e:
    logging.error(f"Failed to load tokenizer: {str(e)}")
    tokenizer = None  # Will be checked before predictions

# Request models with validation
class PredictionRequest(BaseModel):
    source_code: str
    structured_features: dict = None
    
    class Config:
        schema_extra = {
            "example": {
                "source_code": "contract SimpleStorage { uint storedData; function set(uint x) public { storedData = x; } }",
                "structured_features": {"function_count": 1, "security_flags": 0, "complexity": 1}
            }
        }

# New request model for contract analysis
class ContractAnalysisRequest(BaseModel):
    contract_address: str
    api_key: str = None  # Etherscan API key, optional if set in config
    
    class Config:
        schema_extra = {
            "example": {
                "contract_address": "0x123abc...",
                "api_key": "YOUR_ETHERSCAN_API_KEY"
            }
        }

# Etherscan config - require API key from env
api_key = os.getenv('ETHERSCAN_API_KEY')
if not api_key:
    logging.warning("ETHERSCAN_API_KEY environment variable not found - API key must be provided in requests")
    
# Initialize client only when needed to prevent startup failures
client = None

# Initialize analyzer
analyzer = ComprehensiveContractAnalyzer()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

@app.post('/predict', 
         summary="Predict smart contract risk score",
         description="Analyzes smart contract source code and returns a risk score with SHAP explainability")
def predict(request: PredictionRequest):
    # Check if model and tokenizer are loaded
    if model is None or tokenizer is None:
        raise HTTPException(
            status_code=503, 
            detail="Model or tokenizer not available. Please check server logs."
        )
    
    # Validate input
    if not request.source_code or len(request.source_code.strip()) < 10:
        raise HTTPException(
            status_code=400,
            detail="Invalid source code. Please provide valid Solidity code."
        )
    
    try:
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
        inputs = tokenizer(
            request.source_code, 
            return_tensors='pt', 
            padding=True, 
            truncation=True,
            max_length=512  # Prevent token overflow
        )
        code_tokens = inputs['input_ids']
        
        # Get predictions
        with torch.no_grad():
            numeric_input = torch.tensor(numeric_features, dtype=torch.float32)
            code_input = torch.tensor(code_tokens, dtype=torch.long)
            prediction = model(numeric_input, code_input)
        
        # SHAP explainability
        try:
            explainer = shap.DeepExplainer(model, numeric_features)
            shap_values = explainer.shap_values(numeric_features)
            shap_data = shap_values.tolist()
        except Exception as e:
            logging.warning(f"SHAP explanation failed: {str(e)}")
            shap_data = None
        
        return {
            'risk_score': float(prediction.item()),  # Ensure JSON serializable
            'shap_values': shap_data,
            'timestamp': str(np.datetime64('now'))
        }
    
    except Exception as e:
        logging.error(f"Prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@app.post('/analyze',
         summary="Analyze smart contract security",
         description="Fetches contract source from Etherscan and performs comprehensive security analysis")
def analyze_contract(request: ContractAnalysisRequest):
    """
    Analyze smart contract: Fetch from Etherscan, run Slither/Mythril/ML, compute weighted risk, return JSON.
    """
    try:
        contract_address = request.contract_address
        
        # Initialize client with API key from request or environment
        api_key_to_use = request.api_key or os.getenv('ETHERSCAN_API_KEY')
        if not api_key_to_use:
            raise HTTPException(
                status_code=400, 
                detail="Etherscan API key required. Provide in request or set ETHERSCAN_API_KEY environment variable."
            )
            
        # Create client for this request
        config = EtherscanConfig(api_key=api_key_to_use)
        request_client = EtherscanClient(config)

        # Step 1: Fetch contract source with timeout protection
        try:
            source_result = get_contract_source_code(request_client, contract_address)
            if not source_result:
                raise HTTPException(status_code=404, detail="Contract source not found")
        except Exception as e:
            raise HTTPException(
                status_code=502, 
                detail=f"Failed to fetch contract from Etherscan: {str(e)}"
            )

        # Extract source code (handle multi-file)
        source_code = source_result.get('SourceCode', '')
        if not source_code:
            raise HTTPException(status_code=404, detail="Empty source code returned from Etherscan")
            
        try:
            if source_code.startswith('{{'):
                # Multi-file JSON
                source_json = json.loads(source_code[1:-1])  # Remove outer braces if needed
                # For simplicity, concatenate files or use first; in production, handle properly
                concatenated_source = '\n'.join([
                    content.get('content', '') for content in source_json.get('sources', {}).values()
                ])
            else:
                concatenated_source = source_code
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse multi-file contract JSON for {contract_address}")
            concatenated_source = source_code  # Fallback to raw source

        # Step 2: Run analysis (Slither, Mythril, etc. via analyzer)
        try:
            analysis_result = analyzer.analyze_contract(
                contract_address=contract_address,
                source_code=concatenated_source  # Pass fetched source
            )
        except Exception as e:
            logging.error(f"Analysis failed: {str(e)}")
            raise HTTPException(
                status_code=500, 
                detail=f"Contract analysis failed: {str(e)}"
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
            'weighted_risk_score': float(weighted_risk),  # Ensure JSON serializable
            'timestamp': analysis_result.get('analysis_timestamp', str(np.datetime64('now'))),
            'recommendations': [issue.get('recommendation', '') for issue in analysis_result.get('security_issues', []) if issue.get('recommendation')]
        }

        return response

    except HTTPException:
        # Re-raise HTTP exceptions without modification
        raise
    except Exception as e:
        logging.error(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")