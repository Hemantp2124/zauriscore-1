"""Base model class for all ML models in ZauriScore."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, Union

import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from ..config import config
from ..utils.logger import setup_logger

class BaseModel(ABC, nn.Module):
    """Base class for all ML models in ZauriScore."""
    
    def __init__(self, model_name: str = "base_model"):
        """Initialize the base model.
        
        Args:
            model_name: Name of the model (used for logging and saving)
        """
        super().__init__()
        self.model_name = model_name
        self.logger = setup_logger(f"model.{model_name}")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.to(self.device)
    
    @abstractmethod
    def forward(self, *args, **kwargs):
        """Forward pass of the model."""
        pass
    
    @abstractmethod
    def train_step(
        self, 
        batch: Tuple[torch.Tensor, ...], 
        criterion: Optional[nn.Module] = None
    ) -> Dict[str, float]:
        """Perform a single training step.
        
        Args:
            batch: Input batch
            criterion: Loss function (if None, use default)
            
        Returns:
            Dictionary of metrics for the step
        """
        pass
    
    @abstractmethod
    def evaluate(
        self, 
        dataloader: DataLoader, 
        criterion: Optional[nn.Module] = None
    ) -> Dict[str, float]:
        """Evaluate the model on a dataset.
        
        Args:
            dataloader: DataLoader for evaluation
            criterion: Loss function (if None, use default)
            
        Returns:
            Dictionary of evaluation metrics
        """
        pass
    
    def save(self, path: Union[str, Path]) -> None:
        """Save the model to disk.
        
        Args:
            path: Path to save the model
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        torch.save({
            'model_state_dict': self.state_dict(),
            'model_config': self.get_config()
        }, path)
        
        self.logger.info(f"Model saved to {path}")
    
    @classmethod
    def load(
        cls, 
        path: Union[str, Path], 
        **kwargs
    ) -> 'BaseModel':
        """Load a model from disk.
        
        Args:
            path: Path to the saved model
            **kwargs: Additional arguments for model initialization
            
        Returns:
            Loaded model instance
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        
        checkpoint = torch.load(path, map_location='cpu')
        model_config = checkpoint.get('model_config', {})
        
        # Update with any new kwargs
        model_config.update(kwargs)
        
        # Create model instance
        model = cls(**model_config)
        model.load_state_dict(checkpoint['model_state_dict'])
        
        return model
    
    def get_config(self) -> Dict[str, Any]:
        """Get the model configuration.
        
        Returns:
            Dictionary containing the model configuration
        """
        return {
            'model_name': self.model_name,
            'device': str(self.device),
            'num_parameters': sum(p.numel() for p in self.parameters() if p.requires_grad)
        }
    
    def freeze_layers(self, layer_names: Optional[list] = None) -> None:
        """Freeze model layers.
        
        Args:
            layer_names: List of layer names to freeze. If None, freeze all layers.
        """
        if layer_names is None:
            # Freeze all parameters
            for param in self.parameters():
                param.requires_grad = False
            self.logger.info("Froze all model parameters")
        else:
            # Freeze specific layers
            for name, param in self.named_parameters():
                if any(layer_name in name for layer_name in layer_names):
                    param.requires_grad = False
                    self.logger.debug(f"Froze layer: {name}")
    
    def unfreeze_layers(self, layer_names: Optional[list] = None) -> None:
        """Unfreeze model layers.
        
        Args:
            layer_names: List of layer names to unfreeze. If None, unfreeze all layers.
        """
        if layer_names is None:
            # Unfreeze all parameters
            for param in self.parameters():
                param.requires_grad = True
            self.logger.info("Unfroze all model parameters")
        else:
            # Unfreeze specific layers
            for name, param in self.named_parameters():
                if any(layer_name in name for layer_name in layer_names):
                    param.requires_grad = True
                    self.logger.debug(f"Unfroze layer: {name}")
