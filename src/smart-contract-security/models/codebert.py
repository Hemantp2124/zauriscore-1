"""CodeBERT model for code analysis."""

import torch
import torch.nn as nn
from transformers import RobertaModel, RobertaConfig
from typing import Optional, Dict, Any

class CodeBERTRegressor(nn.Module):
    """CodeBERT-based model for code regression tasks."""

    def __init__(self, model_name: str = "microsoft/codebert-base", num_labels: int = 1):
        """Initialize the CodeBERT regressor.
        
        Args:
            model_name (str): Name of the pretrained model
            num_labels (int): Number of output labels/scores
        """
        super().__init__()
        self.config = RobertaConfig.from_pretrained(model_name)
        self.codebert = RobertaModel.from_pretrained(model_name)
        self.dropout = nn.Dropout(0.1)
        self.regressor = nn.Linear(self.config.hidden_size, num_labels)
        
    def forward(self, input_ids: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Forward pass of the model.
        
        Args:
            input_ids: Input token IDs
            attention_mask: Attention mask for padding
            
        Returns:
            torch.Tensor: Predicted scores
        """
        outputs = self.codebert(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs[1]  # Use [CLS] token representation
        pooled_output = self.dropout(pooled_output)
        return self.regressor(pooled_output)
        
    def get_embedding(self, input_ids: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Get the code embedding from CodeBERT.
        
        Args:
            input_ids: Input token IDs
            attention_mask: Attention mask for padding
            
        Returns:
            torch.Tensor: Code embedding
        """
        with torch.no_grad():
            outputs = self.codebert(input_ids=input_ids, attention_mask=attention_mask)
            return outputs[1]  # Return [CLS] token representation
