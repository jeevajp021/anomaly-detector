# Create tests/test_phase1.py

import pytest
import numpy as np
import sys
import time
import subprocess
import json
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from ml.feature_extractor import FeatureExtractor
from ml.threshold_calculator import DynamicThresholdCalculator

class TestPhase1:
    """Test suite for Phase 1 components"""
    
    def test_feature_extraction(self):
        """Test feature extraction"""
        extractor = FeatureExtractor()
        
        test_event = {
            'cpu_time_ms': 150,
            'duration_ms': 200,
            'syscalls': ['accept', 'read', 'write', 'close'],
            'event_timestamps': [0, 10, 20, 30]
        }
        
        features = extractor.extract_single(test_event)
        
        assert 'cpu_time' in features
        assert 'duration' in features
        assert 'cpu_ratio' in features
        assert features['cpu_ratio'] == 150 / 200
    
    def test_threshold_calculator(self):
        """Test dynamic threshold calculation"""
        calc = DynamicThresholdCalculator()
        
        # Add normal traffic
        for i in range(1000):
            cpu_time = np.random.normal(100, 20)
            calc.update(container_id=123, cpu_time_ms=cpu_time)
        
        # Get threshold
        threshold = calc.get_threshold(123)
        assert threshold is not None
        assert threshold > 100  # Should be above mean
        
        # Test anomaly detection
        assert calc.is_anomaly(123, 50) == False   # Below threshold
        assert calc.is_anomaly(123, 300) == True   # Above threshold
    
    def test_ml_post_filter(self):
        """Test ML post-filter (if model exists)"""
        try:
            from ml.classifier import MLPostFilter
            filter = MLPostFilter()
            
            # Test attack event
            attack_event = {
                'cpu_time_ms': 5000,
                'duration_ms': 1000,
                'syscalls': ['read'] * 100,
                'event_timestamps': list(range(100))
            }
            
            should_alert, conf, reason = filter.filter_alert(attack_event)
            assert isinstance(should_alert, bool)
            assert 0 <= conf <= 1
            
        except FileNotFoundError:
            pytest.skip("ML model not trained yet")
    
    def test_docker_integration(self):
        """Test detection with Docker container"""
        # Start a container
        cmd = [
            'docker', 'run', '-d', '--rm', '--name', 'test-container',
            'python:3.9', 'python3', '-c',
            'import time; time.sleep(5)'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        
        # Wait for container
        time.sleep(2)
        
        # Clean up
        subprocess.run(['docker', 'stop', 'test-container'])
    
    def test_phase1_targets(self):
        """Verify Phase 1 targets are achievable"""
        # Load results if they exist
        results_file = Path('data/output/phase1_results.json')
        
        if not results_file.exists():
            pytest.skip("Phase 1 not fully executed yet")
        
        with open(results_file, 'r') as f:
            results = json.load(f)
        
        # Check targets
        assert results['adr'] >= 0.90, f"ADR {results['adr']} < 0.90"
        assert results['fpr'] <= 0.02, f"FPR {results['fpr']} > 0.02"
        assert results['latency_ms'] <= 100, f"Latency {results['latency_ms']} > 100ms"

if __name__ == "__main__":
    pytest.main([__file__, '-v'])
