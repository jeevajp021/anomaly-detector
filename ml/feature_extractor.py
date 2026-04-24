# Create ml/feature_extractor.py

import numpy as np
from collections import Counter

class FeatureExtractor:
    """
    Extract features from connection events for ML classification
    """
    
    def __init__(self):
        self.feature_names = [
            'cpu_time',
            'duration',
            'cpu_ratio',          # CPU time / Duration
            'syscall_count',
            'syscall_diversity',  # Unique syscalls / Total syscalls
            'temporal_burstiness' # Variance in inter-arrival times
        ]
    
    def extract_single(self, event_data):
        """Extract features from a single event"""
        
        cpu_time = event_data.get('cpu_time_ms', 0)
        duration = event_data.get('duration_ms', 1)  # Avoid divide by zero
        
        # Basic features
        features = {
            'cpu_time': cpu_time,
            'duration': duration,
            'cpu_ratio': cpu_time / max(duration, 1),
        }
        
        # Syscall features (if available)
        syscalls = event_data.get('syscalls', [])
        if syscalls:
            unique_syscalls = len(set(syscalls))
            total_syscalls = len(syscalls)
            
            features['syscall_count'] = total_syscalls
            features['syscall_diversity'] = unique_syscalls / max(total_syscalls, 1)
        else:
            features['syscall_count'] = 0
            features['syscall_diversity'] = 0
        
        # Temporal burstiness (requires time series data)
        timestamps = event_data.get('event_timestamps', [])
        if len(timestamps) > 1:
            inter_arrivals = np.diff(timestamps)
            features['temporal_burstiness'] = float(np.var(inter_arrivals))
        else:
            features['temporal_burstiness'] = 0.0
        
        return features
    
    def extract_batch(self, events):
        """Extract features from multiple events"""
        feature_list = []
        
        for event in events:
            features = self.extract_single(event)
            feature_list.append(features)
        
        return feature_list
    
    def to_numpy(self, feature_dicts):
        """Convert feature dicts to numpy array"""
        features_array = []
        
        for feat_dict in feature_dicts:
            row = [feat_dict[name] for name in self.feature_names]
            features_array.append(row)
        
        return np.array(features_array)

# Test feature extraction
if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    # Sample event
    test_event = {
        'cpu_time_ms': 150,
        'duration_ms': 200,
        'syscalls': ['accept', 'read', 'write', 'read', 'close'],
        'event_timestamps': [0, 10, 15, 20, 30]
    }
    
    features = extractor.extract_single(test_event)
    
    print("📊 Extracted Features:")
    for key, value in features.items():
        print(f"   {key}: {value:.4f}")
