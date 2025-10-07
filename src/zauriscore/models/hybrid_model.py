import logging
from typing import Dict, Tuple, Union, Optional

import torch
import torch.nn as nn
import pytorch_lightning as pl
from transformers import CodeBERTModel, AutoTokenizer

logger = logging.getLogger(__name__)

class HybridRiskModel(pl.LightningModule):
    """
    A hybrid model that combines structured numeric features with code embeddings
    from CodeBERT to predict smart contract risk scores.
    """
    
    def __init__(
        self, 
        numeric_features_dim: int = 15,
        hidden_dim: int = 64,
        dropout_rate: float = 0.2,
        learning_rate: float = 1e-4,
        model_path: Optional[str] = None
    ):
        """
        Initialize the HybridRiskModel.
        
        Args:
            numeric_features_dim: Dimension of numeric features input
            hidden_dim: Dimension of hidden layers
            dropout_rate: Dropout rate for regularization
            learning_rate: Learning rate for optimizer
            model_path: Optional path to load a pre-trained CodeBERT model
        """
        super().__init__()
        self.save_hyperparameters()
        
        # Structured features branch with dropout for regularization
        self.numeric_layer = nn.Sequential(
            nn.Linear(numeric_features_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_rate)
        )
        
        # CodeBERT embeddings branch
        try:
            self.bert = CodeBERTModel.from_pretrained(
                model_path or 'microsoft/codebert-base'
            )
            logger.info("Successfully loaded CodeBERT model")
        except Exception as e:
            logger.error(f"Failed to load CodeBERT model: {str(e)}")
            raise
            
        self.embedding_layer = nn.Sequential(
            nn.Linear(768, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_rate)
        )
        
        # Final layers with dropout
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_dim, 1)
        )
        
        self.learning_rate = learning_rate
    
    def forward(self, numeric_features: torch.Tensor, code_tokens: torch.Tensor) -> torch.Tensor:
        """
        Forward pass of the hybrid model.
        
        Args:
            numeric_features: Tensor of shape [batch_size, numeric_features_dim]
            code_tokens: Tensor of tokenized code of shape [batch_size, seq_length]
            
        Returns:
            Tensor of risk scores between 0 and 1
        """
        # Process numeric features
        numeric_output = self.numeric_layer(numeric_features)
        
        # Process code tokens with error handling
        try:
            with torch.no_grad():
                bert_outputs = self.bert(code_tokens)
            
            # Get embeddings from last hidden state
            embeddings = bert_outputs.last_hidden_state.mean(dim=1)
            code_output = self.embedding_layer(embeddings)
            
            # Concatenate features
            combined = torch.cat([numeric_output, code_output], dim=1)
            
            # Final prediction
            return torch.sigmoid(self.fc(combined))
        except Exception as e:
            logger.error(f"Error in forward pass: {str(e)}")
            raise
    
    def configure_optimizers(self):
        """Configure the optimizer for training."""
        return torch.optim.Adam(self.parameters(), lr=self.learning_rate)
        
    def training_step(self, batch, batch_idx):
        """Training step logic."""
        numeric_features, code_tokens, labels = batch
        predictions = self(numeric_features, code_tokens)
        loss = nn.BCELoss()(predictions, labels)
        self.log('train_loss', loss)
        return loss
        
    def validation_step(self, batch, batch_idx):
        """Validation step logic."""
        numeric_features, code_tokens, labels = batch
        predictions = self(numeric_features, code_tokens)
        loss = nn.BCELoss()(predictions, labels)
        self.log('val_loss', loss)
        return loss