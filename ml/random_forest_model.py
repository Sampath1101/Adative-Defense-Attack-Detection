import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from imblearn.over_sampling import SMOTE
import os

class RandomForestModel:
    """Random Forest model for supervised anomaly detection"""
    
    def __init__(self, random_state=42):
        """
        Initialize Random Forest model
        
        Args:
            random_state: Random seed for reproducibility
        """
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=random_state,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def train(self, X, y, use_smote=True, test_size=0.2):
        """
        Train the Random Forest model
        
        Args:
            X: Feature matrix
            y: Labels (0=normal, 1=suspicious)
            use_smote: Whether to use SMOTE for handling imbalanced data
            test_size: Proportion of data for testing
        
        Returns:
            metrics: Dictionary with evaluation metrics
        """
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Handle imbalanced data with SMOTE
        if use_smote and len(np.unique(y_train)) > 1:
            try:
                smote = SMOTE(random_state=42)
                X_train_scaled, y_train = smote.fit_resample(X_train_scaled, y_train)
                print(f"✓ SMOTE applied: {len(X_train_scaled)} samples after resampling")
            except Exception as e:
                print(f"⚠ SMOTE failed: {e}. Training without resampling.")
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        self.is_trained = True
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        metrics = {
            'classification_report': classification_report(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_pred_proba) if len(np.unique(y_test)) > 1 else None,
            'train_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        print(f"\n✓ Random Forest trained on {len(X_train_scaled)} samples")
        print(f"\nClassification Report:\n{metrics['classification_report']}")
        if metrics['roc_auc']:
            print(f"ROC AUC Score: {metrics['roc_auc']:.4f}")
        
        return metrics
    
    def predict(self, X):
        """
        Predict classes
        
        Args:
            X: Feature matrix
        
        Returns:
            predictions: 0 for normal, 1 for suspicious
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        return predictions
    
    def predict_proba(self, X):
        """
        Get prediction probabilities
        
        Args:
            X: Feature matrix
        
        Returns:
            probabilities: Probability of being suspicious (class 1)
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        X_scaled = self.scaler.transform(X)
        probabilities = self.model.predict_proba(X_scaled)[:, 1]
        return probabilities
    
    def save(self, model_path, scaler_path):
        """Save model and scaler to disk"""
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        print(f"✓ Random Forest model saved to {model_path}")
    
    def load(self, model_path, scaler_path):
        """Load model and scaler from disk"""
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            return False
        
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        self.is_trained = True
        print(f"✓ Random Forest model loaded from {model_path}")
        return True
    
    def get_feature_importance(self, feature_names=None):
        """
        Get feature importance scores
        
        Args:
            feature_names: Optional list of feature names
        
        Returns:
            importance_dict: Dictionary mapping features to importance scores
        """
        if not self.is_trained:
            return None
        
        importances = self.model.feature_importances_
        
        if feature_names:
            importance_dict = dict(zip(feature_names, importances))
            # Sort by importance
            importance_dict = dict(sorted(
                importance_dict.items(), 
                key=lambda x: x[1], 
                reverse=True
            ))
            return importance_dict
        
        return importances