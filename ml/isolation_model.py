import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import os

class IsolationForestModel:
    """Isolation Forest model for unsupervised anomaly detection"""
    
    def __init__(self, contamination=0.1, random_state=42):
        """
        Initialize Isolation Forest model
        
        Args:
            contamination: Expected proportion of anomalies in dataset
            random_state: Random seed for reproducibility
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
            max_samples='auto',
            bootstrap=False,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def train(self, X):
        """
        Train the Isolation Forest model
        
        Args:
            X: Feature matrix (numpy array or pandas DataFrame)
        """
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print(f"✓ Isolation Forest trained on {len(X)} samples")
    
    def predict(self, X):
        """
        Predict anomalies
        
        Args:
            X: Feature matrix
        
        Returns:
            predictions: -1 for anomalies, 1 for normal
            scores: Anomaly scores (lower = more anomalous)
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get predictions (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(X_scaled)
        
        # Get anomaly scores (lower = more anomalous)
        scores = self.model.score_samples(X_scaled)
        
        return predictions, scores
    
    def predict_proba(self, X):
        """
        Get anomaly probabilities
        
        Args:
            X: Feature matrix
        
        Returns:
            probabilities: Anomaly probability for each sample
        """
        predictions, scores = self.predict(X)
        
        # Convert scores to probabilities (0-1 scale)
        # Normalize scores to [0, 1] where 1 = likely anomaly
        min_score = scores.min()
        max_score = scores.max()
        
        if max_score - min_score == 0:
            probabilities = np.zeros(len(scores))
        else:
            # Invert so higher value = more anomalous
            probabilities = 1 - (scores - min_score) / (max_score - min_score)
        
        return probabilities
    
    def save(self, model_path, scaler_path):
        """Save model and scaler to disk"""
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        print(f"✓ Isolation Forest model saved to {model_path}")
    
    def load(self, model_path, scaler_path):
        """Load model and scaler from disk"""
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            return False
        
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        self.is_trained = True
        print(f"✓ Isolation Forest model loaded from {model_path}")
        return True
    
    def get_feature_importance(self):
        """Get feature importance scores"""
        # Isolation Forest doesn't have built-in feature importance
        # We return None
        return None