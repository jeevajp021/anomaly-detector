# Create ml/classifier.py

import joblib
import numpy as np
import sys
sys.path.append('.')

from ml.feature_extractor import FeatureExtractor

class MLPostFilter:
    """
    ML-based post-filter to reduce false positives
    """
    
    def __init__(self, model_path='ml/models/random_forest.joblib'):
        self.model = joblib.load(model_path)
        self.extractor = FeatureExtractor()
        print(f"✅ ML Post-Filter loaded from {model_path}")
    
    def predict(self, event_data):
        """
        Predict if event is truly anomalous
        Returns: (is_attack, confidence)
        """
        # Extract features
        features = self.extractor.extract_single(event_data)
        X = self.extractor.to_numpy([features])
        
        # Predict
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        is_attack = (prediction == 1)
        confidence = probabilities[1] if is_attack else probabilities[0]
        
        return is_attack, confidence
    
    def filter_alert(self, alert_data, min_confidence=0.85):
        """
        Filter an alert through the ML model
        Returns: (should_alert, confidence, reason)
        """
        is_attack, confidence = self.predict(alert_data)
        
        if is_attack and confidence >= min_confidence:
            return True, confidence, "ML confirmed attack"
        elif is_attack:
            return False, confidence, f"Low confidence ({confidence:.2f} < {min_confidence})"
        else:
            return False, confidence, "ML classified as benign"

# Test the filter
if __name__ == "__main__":
    filter = MLPostFilter()
    
    # Test case 1: Likely attack
    attack_event = {
        'cpu_time_ms': 5000,
        'duration_ms': 2000,
        'syscalls': ['accept', 'read'] * 50,
        'event_timestamps': list(range(0, 100, 2))
    }
    
    should_alert, conf, reason = filter.filter_alert(attack_event)
    print(f"Attack event: {should_alert} (confidence={conf:.2f}) - {reason}")
    
    # Test case 2: Likely benign
    benign_event = {
        'cpu_time_ms': 50,
        'duration_ms': 100,
        'syscalls': ['accept', 'read', 'write', 'close'],
        'event_timestamps': [0, 10, 20, 30]
    }
    
    should_alert, conf, reason = filter.filter_alert(benign_event)
    print(f"Benign event: {should_alert} (confidence={conf:.2f}) - {reason}")
