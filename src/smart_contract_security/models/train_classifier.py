import os
from pathlib import Path
import numpy as np
import joblib
import subprocess
import json
from sklearn.model_selection import train_test_split, GridSearchCV, cross_validate, StratifiedKFold
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from imblearn.over_sampling import SMOTE, ADASYN, BorderlineSMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline
from imblearn.combine import SMOTETomek
import logging
import torch
import torch.nn.functional as F
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from torch.utils.data import Dataset, DataLoader

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - ZauriScore Training',
                    filename='model_training.log')

# --- Configuration ---
# Derive project root from this file location: src/zauriscore/models/train_classifier.py
PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = str(PROJECT_ROOT / "data")
CONTRACTS_DIR = str(PROJECT_ROOT / "contracts")  # Where .sol files are stored
EMBEDDINGS_FILE = os.path.join(DATA_DIR, "X_embeddings.npy")
LABELS_FILE = os.path.join(DATA_DIR, "y_labels.npy")
FILE_PATHS_FILE = os.path.join(DATA_DIR, "file_paths.npy")
MODELS_DIR = str(PROJECT_ROOT / "models")
MODEL_FILE = os.path.join(MODELS_DIR, "codebert_vuln_classifier.joblib")

TEST_SIZE = 0.2
RANDOM_STATE = 42

class ZauriDataset(Dataset):
    def __init__(self, contracts, labels, tokenizer):
        self.contracts = contracts
        self.labels = labels
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.contracts)

    def __getitem__(self, idx):
        encoding = self.tokenizer(
            self.contracts[idx], 
            truncation=True, 
            padding=True, 
            max_length=512, 
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(self.labels[idx])
        }

def prepare_dataset(contracts, labels, tokenizer):
    # Advanced data preparation with enhanced tokenization
    dataset = ZauriDataset(contracts, labels, tokenizer)
    
    # Compute class weights to handle imbalance
    class_counts = np.bincount(labels)
    total_samples = len(labels)
    class_weights = total_samples / (len(np.unique(labels)) * class_counts)
    class_weights = torch.FloatTensor(class_weights)
    
    return dataset, class_weights

def focal_loss(inputs, targets, class_weights=None, gamma=2.0):
    # Custom Focal Loss for better handling of class imbalance
    ce_loss = F.cross_entropy(inputs, targets, reduction='none', weight=class_weights)
    pt = torch.exp(-ce_loss)
    focal_loss = ((1 - pt) ** gamma * ce_loss).mean()
    return focal_loss

def run_slither(contract_path):
    try:
        result = subprocess.run(
            ["slither", contract_path, "--json", "slither_tmp.json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logging.warning(f"Slither failed on {contract_path}")
            return None
        with open("slither_tmp.json", "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error running Slither on {contract_path}: {e}")
        return None

def extract_binary_label(slither_output):
    if not slither_output:
        return 0
    findings = slither_output.get("results", {}).get("detectors", [])
    return 1 if findings else 0

def generate_labels_and_paths():
    logging.info("Generating labels using Slither...")
    labels = []
    paths = []
    contract_files = [f for f in os.listdir(CONTRACTS_DIR) if f.endswith(".sol")]

    for f in contract_files:
        full_path = os.path.join(CONTRACTS_DIR, f)
        slither_out = run_slither(full_path)
        label = extract_binary_label(slither_out)
        labels.append(label)
        paths.append(full_path)

    y_array = np.array(labels)
    path_array = np.array(paths)
    np.save(LABELS_FILE, y_array)
    np.save(FILE_PATHS_FILE, path_array)
    logging.info(f"Saved {len(labels)} labels and file paths.")

def analyze_feature_importance(classifier, X_train, feature_names=None):
    if hasattr(classifier, 'coef_'):
        # For Logistic Regression, use coefficients
        importances = np.abs(classifier.coef_[0])
        
        if feature_names is None:
            feature_names = [f'Feature_{i}' for i in range(len(importances))]
        
        # Sort features by importance
        indices = np.argsort(importances)[::-1]
        
        logging.info("Top 10 Most Important Features:")
        for f in range(min(10, len(indices))):
            logging.info(f"{feature_names[indices[f]]}: {importances[indices[f]]:.4f}")
    else:
        logging.warning("Feature importance not available for this model type")

def analyze_misclassifications(X_test, y_test, y_pred, paths_test, classifier):
    misclassified_indices = np.where(y_test != y_pred)[0]
    
    logging.info("Detailed Misclassification Analysis:")
    for idx in misclassified_indices:
        # Get prediction probabilities
        proba = classifier.predict_proba([X_test[idx]])
        
        logging.info(f"Misclassified Contract: {paths_test[idx]}")
        logging.info(f"True Label: {y_test[idx]}")
        logging.info(f"Predicted Label: {y_pred[idx]}")
        logging.info(f"Prediction Probabilities: {proba}")
        logging.info("---")

def create_advanced_ensemble():
    # Ensemble of multiple classifiers with different strengths
    lr = LogisticRegression(random_state=RANDOM_STATE, max_iter=1000, class_weight='balanced')
    rf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=RANDOM_STATE)
    svm = SVC(kernel='rbf', class_weight='balanced', probability=True, random_state=RANDOM_STATE)
    
    return VotingClassifier(
        estimators=[('lr', lr), ('rf', rf), ('svm', svm)],
        voting='soft'
    )

def train_classifier(X_train, X_test, y_train, y_test, n_splits=5):
    """Train a classifier model for vulnerability detection.
    
    Args:
        X_train: Training features
        X_test: Test features
        y_train: Training labels
        y_test: Test labels
        n_splits: Number of cross-validation splits
    
    Returns:
        tuple: (trained_model, test_accuracy, test_auc)
    """
    # Stratified K-Fold Cross Validation
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    
    # Performance tracking
    cv_scores = {
        'precision': [],
        'recall': [],
        'f1_score': []
    }
    
    tokenizer = RobertaTokenizer.from_pretrained('roberta-base')
    model = RobertaForSequenceClassification.from_pretrained('roberta-base', num_labels=2)
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)
    
    for fold, (train_index, val_index) in enumerate(skf.split(X_train, y_train), 1):
        print(f'Training Fold {fold}/{n_splits}')
        
        # Split data
        X_train_fold, X_val_fold = X_train[train_index], X_train[val_index]
        y_train_fold, y_val_fold = y_train[train_index], y_train[val_index]
        
        # Prepare dataset with class weights
        train_data, class_weights = prepare_dataset(X_train_fold, y_train_fold, tokenizer)
        val_data, _ = prepare_dataset(X_val_fold, y_val_fold, tokenizer)
        
        # Training loop with advanced techniques
        optimizer = torch.optim.AdamW(
            model.parameters(), 
            lr=1e-5,
            eps=1e-8,
            weight_decay=0.01
        )
        
        model.train()
        for epoch in range(3):  # Reduced epochs for demonstration
            optimizer.zero_grad()
            inputs = {
                'input_ids': train_data.dataset[idx]['input_ids'].to(device),
                'attention_mask': train_data.dataset[idx]['attention_mask'].to(device),
                'labels': train_data.dataset[idx]['labels'].to(device)
            }
            
            outputs = model(**inputs)
            
            # Use Focal Loss
            loss = focal_loss(
                outputs.logits, 
                inputs['labels'], 
                class_weights,
                gamma=2.0
            )
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(
                model.parameters(), 
                1.0
            )
            optimizer.step()
        
        # Validation
        model.eval()
        with torch.no_grad():
            val_outputs = model(
                input_ids=val_data.dataset[idx]['input_ids'].to(device),
                attention_mask=val_data.dataset[idx]['attention_mask'].to(device)
            )
            preds = torch.argmax(val_outputs.logits, dim=1).cpu().numpy()
            
            # Compute metrics
            report = classification_report(
                val_data.dataset[idx]['labels'].numpy(), 
                preds, 
                output_dict=True
            )
            
            cv_scores['precision'].append(report['weighted avg']['precision'])
            cv_scores['recall'].append(report['weighted avg']['recall'])
            cv_scores['f1_score'].append(report['weighted avg']['f1-score'])
    
    # Final model evaluation
    print('Cross-Validation Results:')
    for metric, scores in cv_scores.items():
        print(f'{metric.capitalize()}: {np.mean(scores):.4f} ± {np.std(scores):.4f}')

def main():
    logging.info("Starting advanced classifier training process...")

    # Auto-generate labels if missing
    if not (os.path.exists(LABELS_FILE) and os.path.exists(FILE_PATHS_FILE)):
        logging.warning("Label or path files missing. Generating with Slither...")
        generate_labels_and_paths()

    # Load data
    if not os.path.exists(EMBEDDINGS_FILE):
        logging.error(f"Missing embeddings file: {EMBEDDINGS_FILE}")
        return

    try:
        X = np.load(EMBEDDINGS_FILE)
        y = np.load(LABELS_FILE)
        file_paths = np.load(FILE_PATHS_FILE, allow_pickle=True)
        logging.info(f"Data loaded. X: {X.shape}, y: {y.shape}, paths: {file_paths.shape}")
    except Exception as e:
        logging.error(f"Failed to load data: {e}")
        return

    if not (X.shape[0] == y.shape[0] == file_paths.shape[0]):
        logging.error("Mismatch between data shapes.")
        return

    if X.shape[0] == 0:
        logging.error("Empty dataset.")
        return

    # Advanced Sampling Strategy
    pipeline = Pipeline([
        ('scaler', MinMaxScaler()),  # Better for ensemble methods
        ('sampler', SMOTETomek(random_state=RANDOM_STATE)),  # Combine over and under sampling
        ('classifier', create_advanced_ensemble())
    ])

    # Stratified K-Fold for more robust evaluation
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    
    # Detailed performance tracking
    cv_scores = {
        'accuracy': [],
        'precision': [],
        'recall': [],
        'f1': [],
        'roc_auc': []
    }

    # Cross-validation with detailed tracking
    for train_index, test_index in skf.split(X, y):
        X_train, X_test = X[train_index], X[test_index]
        y_train, y_test = y[train_index], y[test_index]
        
        # Fit pipeline
        pipeline.fit(X_train, y_train)
        
        # Predictions
        y_pred = pipeline.predict(X_test)
        y_pred_proba = pipeline.predict_proba(X_test)[:, 1]
        
        # Compute metrics
        cv_scores['accuracy'].append(accuracy_score(y_test, y_pred))
        cv_scores['precision'].append(classification_report(y_test, y_pred, output_dict=True)['weighted avg']['precision'])
        cv_scores['recall'].append(classification_report(y_test, y_pred, output_dict=True)['weighted avg']['recall'])
        cv_scores['f1'].append(classification_report(y_test, y_pred, output_dict=True)['weighted avg']['f1-score'])
        cv_scores['roc_auc'].append(roc_auc_score(y_test, y_pred_proba))

    # Log cross-validation results
    logging.info("Cross-Validation Results:")
    for metric, scores in cv_scores.items():
        logging.info(f"{metric}: {np.mean(scores):.4f} (+/- {np.std(scores):.4f})")

    # Final training on full dataset
    pipeline.fit(X, y)

    # Detailed analysis
    y_pred = pipeline.predict(X_test)
    y_pred_proba = pipeline.predict_proba(X_test)[:, 1]
    
    logging.info("Classification Report:\n" + classification_report(y_test, y_pred))
    logging.info("Confusion Matrix:\n" + str(confusion_matrix(y_test, y_pred)))
    
    # Advanced misclassification analysis
    paths_test_fold = file_paths[test_index]
    analyze_misclassifications(X_test, y_test, y_pred, paths_test_fold, pipeline)

    # Save model
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(pipeline, MODEL_FILE)
    logging.info(f"Advanced ensemble model saved to {MODEL_FILE}")

if __name__ == "__main__":
    main()
