"""
Random Forest Detector
Classification-based threat detection using Random Forest
"""

import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import logging

logger = logging.getLogger(__name__)


class RandomForestDetector:
    """
    Threat detection using Random Forest classifier
    Supervised learning approach for known threat patterns
    """
    
    def __init__(self, n_estimators=100, max_depth=None, random_state=42):
        """
        Initialize Random Forest detector
        
        Args:
            n_estimators (int): Number of trees in the forest
            max_depth (int): Maximum depth of trees (None = unlimited)
            random_state (int): Random seed for reproducibility
        """
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        
        # Initialize model and scaler
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,  # Use all available cores
            class_weight='balanced'  # Handle imbalanced classes
        )
        
        self.scaler = StandardScaler()
        self.is_trained = False
        self.classes_ = None
        
        logger.info(f"✅ RandomForestDetector initialized (n_estimators={n_estimators})")
    
    def train(self, X_train, y_train, X_val=None, y_val=None):
        """
        Train the Random Forest model
        
        Args:
            X_train (np.array): Training features
            y_train (np.array): Training labels (0=benign, 1=malicious)
            X_val (np.array): Validation features (optional)
            y_val (np.array): Validation labels (optional)
            
        Returns:
            dict: Training results
        """
        logger.info(f"🔧 Training Random Forest on {len(X_train)} samples...")
        
        try:
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            
            # Train model
            self.model.fit(X_train_scaled, y_train)
            self.is_trained = True
            self.classes_ = self.model.classes_
            
            # Evaluate on training data
            train_predictions = self.model.predict(X_train_scaled)
            train_accuracy = accuracy_score(y_train, train_predictions)
            train_precision = precision_score(y_train, train_predictions, zero_division=0)
            train_recall = recall_score(y_train, train_predictions, zero_division=0)
            train_f1 = f1_score(y_train, train_predictions, zero_division=0)
            
            results = {
                'success': True,
                'num_samples': len(X_train),
                'num_malicious': int(np.sum(y_train == 1)),
                'num_benign': int(np.sum(y_train == 0)),
                'train_accuracy': float(train_accuracy),
                'train_precision': float(train_precision),
                'train_recall': float(train_recall),
                'train_f1': float(train_f1)
            }
            
            # Validation metrics if provided
            if X_val is not None and y_val is not None:
                X_val_scaled = self.scaler.transform(X_val)
                val_predictions = self.model.predict(X_val_scaled)
                
                results['val_accuracy'] = float(accuracy_score(y_val, val_predictions))
                results['val_precision'] = float(precision_score(y_val, val_predictions, zero_division=0))
                results['val_recall'] = float(recall_score(y_val, val_predictions, zero_division=0))
                results['val_f1'] = float(f1_score(y_val, val_predictions, zero_division=0))
                
                logger.info(f"✅ Training complete - Val Accuracy: {results['val_accuracy']:.3f}")
            else:
                logger.info(f"✅ Training complete - Train Accuracy: {train_accuracy:.3f}")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Training error: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e)
            }
    
    def predict(self, X):
        """
        Predict if samples are malicious
        
        Args:
            X (np.array): Feature data
            
        Returns:
            np.array: Predictions (0=benign, 1=malicious)
        """
        if not self.is_trained:
            logger.warning("⚠️  Model not trained yet!")
            return np.zeros(len(X))
        
        try:
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Predict
            predictions = self.model.predict(X_scaled)
            
            return predictions
            
        except Exception as e:
            logger.error(f"❌ Prediction error: {e}")
            return np.zeros(len(X))
    
    def predict_proba(self, X):
        """
        Get prediction probabilities
        
        Args:
            X (np.array): Feature data
            
        Returns:
            np.array: Probability of malicious class
        """
        if not self.is_trained:
            logger.warning("⚠️  Model not trained yet!")
            return np.zeros(len(X))
        
        try:
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Get probabilities
            probabilities = self.model.predict_proba(X_scaled)
            
            # Return probability of malicious class (class 1)
            if probabilities.shape[1] > 1:
                return probabilities[:, 1]
            else:
                return probabilities[:, 0]
            
        except Exception as e:
            logger.error(f"❌ Probability prediction error: {e}")
            return np.zeros(len(X))
    
    def detect_threat(self, features):
        """
        Detect if single sample is a threat
        
        Args:
            features (np.array): Feature vector
            
        Returns:
            dict: Detection result with is_threat, probability, confidence
        """
        if not self.is_trained:
            return {
                'is_threat': False,
                'probability': 0.0,
                'confidence': 0.0,
                'error': 'Model not trained'
            }
        
        try:
            # Reshape if needed
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            
            # Get prediction and probability
            prediction = self.predict(features)[0]
            probability = self.predict_proba(features)[0]
            
            is_threat = (prediction == 1)
            
            # Confidence: how far probability is from decision boundary (0.5)
            confidence = abs(probability - 0.5) * 2  # 0 to 1
            
            return {
                'is_threat': bool(is_threat),
                'probability': float(probability),
                'confidence': float(confidence),
                'prediction': int(prediction)
            }
            
        except Exception as e:
            logger.error(f"❌ Threat detection error: {e}")
            return {
                'is_threat': False,
                'probability': 0.0,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def get_feature_importance(self):
        """
        Get feature importance scores
        
        Returns:
            np.array: Feature importance scores
        """
        if not self.is_trained:
            logger.warning("⚠️  Model not trained yet!")
            return np.array([])
        
        return self.model.feature_importances_
    
    def get_top_features(self, feature_names, top_n=10):
        """
        Get top N most important features
        
        Args:
            feature_names (list): List of feature names
            top_n (int): Number of top features to return
            
        Returns:
            list: List of (feature_name, importance) tuples
        """
        if not self.is_trained:
            return []
        
        importances = self.get_feature_importance()
        
        if len(importances) != len(feature_names):
            logger.warning("⚠️  Feature names length mismatch!")
            return []
        
        # Sort by importance
        indices = np.argsort(importances)[::-1][:top_n]
        
        top_features = [(feature_names[i], importances[i]) for i in indices]
        
        return top_features
    
    def evaluate(self, X_test, y_test):
        """
        Evaluate model on test data
        
        Args:
            X_test (np.array): Test features
            y_test (np.array): Test labels
            
        Returns:
            dict: Evaluation metrics
        """
        if not self.is_trained:
            return {'error': 'Model not trained'}
        
        try:
            predictions = self.predict(X_test)
            probabilities = self.predict_proba(X_test)
            
            metrics = {
                'accuracy': float(accuracy_score(y_test, predictions)),
                'precision': float(precision_score(y_test, predictions, zero_division=0)),
                'recall': float(recall_score(y_test, predictions, zero_division=0)),
                'f1': float(f1_score(y_test, predictions, zero_division=0)),
                'num_samples': len(y_test),
                'num_correct': int(np.sum(predictions == y_test)),
                'num_incorrect': int(np.sum(predictions != y_test))
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"❌ Evaluation error: {e}")
            return {'error': str(e)}
    
    def save_model(self, filepath):
        """
        Save model to file
        
        Args:
            filepath (str): Path to save model
            
        Returns:
            bool: Success status
        """
        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Save model and scaler
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'is_trained': self.is_trained,
                'classes': self.classes_,
                'n_estimators': self.n_estimators,
                'max_depth': self.max_depth
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            logger.info(f"✅ Model saved to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error saving model: {e}")
            return False
    
    def load_model(self, filepath):
        """
        Load model from file
        
        Args:
            filepath (str): Path to load model from
            
        Returns:
            bool: Success status
        """
        try:
            if not os.path.exists(filepath):
                logger.error(f"❌ Model file not found: {filepath}")
                return False
            
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.is_trained = model_data['is_trained']
            self.classes_ = model_data['classes']
            self.n_estimators = model_data['n_estimators']
            self.max_depth = model_data['max_depth']
            
            logger.info(f"✅ Model loaded from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error loading model: {e}")
            return False
    
    def get_model_info(self):
        """Get information about the model"""
        return {
            'type': 'RandomForest',
            'is_trained': self.is_trained,
            'n_estimators': self.n_estimators,
            'max_depth': self.max_depth,
            'n_features': self.scaler.n_features_in_ if self.is_trained else 0,
            'classes': self.classes_.tolist() if self.classes_ is not None else []
        }


# Test function
def test_random_forest():
    """Test the Random Forest detector"""
    
    print("\n" + "="*70)
    print("🧪 TESTING RANDOM FOREST DETECTOR")
    print("="*70 + "\n")
    
    # Create synthetic data
    np.random.seed(42)
    
    # Benign data
    benign_data = np.random.randn(400, 10) * 0.5 + 5
    benign_labels = np.zeros(400)
    
    # Malicious data
    malicious_data = np.random.randn(400, 10) * 0.8 + 8
    malicious_labels = np.ones(400)
    
    # Combine and shuffle
    X = np.vstack([benign_data, malicious_data])
    y = np.concatenate([benign_labels, malicious_labels])
    
    # Shuffle
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]
    
    # Split train/test
    split = int(0.8 * len(X))
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]
    
    print(f"📊 Data:")
    print(f"   Train: {len(X_train)} samples ({np.sum(y_train==0)} benign, {np.sum(y_train==1)} malicious)")
    print(f"   Test:  {len(X_test)} samples ({np.sum(y_test==0)} benign, {np.sum(y_test==1)} malicious)")
    
    # Initialize detector
    detector = RandomForestDetector(n_estimators=50)
    
    # Train
    print("\n🔧 Training model...")
    results = detector.train(X_train, y_train, X_test, y_test)
    
    print("\n📊 Training Results:")
    for key, value in results.items():
        if isinstance(value, float):
            print(f"   {key}: {value:.4f}")
        else:
            print(f"   {key}: {value}")
    
    # Test prediction
    print("\n🔍 Testing predictions on first 10 test samples...")
    predictions = detector.predict(X_test[:10])
    probabilities = detector.predict_proba(X_test[:10])
    
    print("\n📊 Sample Predictions:")
    for i in range(10):
        pred_label = "MALICIOUS" if predictions[i] == 1 else "BENIGN"
        true_label = "MALICIOUS" if y_test[i] == 1 else "BENIGN"
        print(f"   Sample {i}: Predicted={pred_label:10s}, True={true_label:10s}, Prob={probabilities[i]:.3f}")
    
    # Test single detection
    print("\n🎯 Testing single threat detection...")
    test_sample = malicious_data[0]
    result = detector.detect_threat(test_sample)
    
    print("\n📊 Detection Result:")
    for key, value in result.items():
        print(f"   {key}: {value}")
    
    # Feature importance
    print("\n📊 Top 5 Important Features:")
    feature_names = [f"feature_{i}" for i in range(10)]
    top_features = detector.get_top_features(feature_names, top_n=5)
    
    for name, importance in top_features:
        print(f"   {name}: {importance:.4f}")
    
    # Evaluate
    print("\n📊 Full Evaluation:")
    eval_results = detector.evaluate(X_test, y_test)
    for key, value in eval_results.items():
        if isinstance(value, float):
            print(f"   {key}: {value:.4f}")
        else:
            print(f"   {key}: {value}")
    
    # Test model save/load
    print("\n💾 Testing model save/load...")
    model_path = 'test_rf_model.pkl'
    
    if detector.save_model(model_path):
        print("✅ Model saved")
        
        # Load in new detector
        new_detector = RandomForestDetector()
        if new_detector.load_model(model_path):
            print("✅ Model loaded")
            
            # Test loaded model
            new_result = new_detector.detect_threat(test_sample)
            print(f"✅ Loaded model works: {new_result['is_threat']}")
    
    # Clean up
    try:
        os.remove(model_path)
    except:
        pass
    
    print("\n" + "="*70)
    print("✅ TEST COMPLETE")
    print("="*70 + "\n")


if __name__ == '__main__':
    test_random_forest()