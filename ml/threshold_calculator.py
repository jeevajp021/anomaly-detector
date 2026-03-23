# Create ml/threshold_calculator.py

import numpy as np
from collections import deque
import yaml

class DynamicThresholdCalculator:
    """
    Implements dynamic threshold calculation using Chebyshev's inequality.
    θ = μ + k*σ
    """
    
    def __init__(self, config_path="config/config.yaml"):
        # Load configuration
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.k = config['ebpf']['threshold']['k_value']  # 4.0
        self.window_size = config['ebpf']['threshold']['window_size']  # 10000
        
        # Rolling window for CPU times (per container)
        self.container_windows = {}
        
        print(f"✅ Threshold Calculator initialized (k={self.k}, window={self.window_size})")
    
    def update(self, container_id, cpu_time_ms):
        """Add new CPU time measurement"""
        if container_id not in self.container_windows:
            self.container_windows[container_id] = deque(maxlen=self.window_size)
        
        self.container_windows[container_id].append(cpu_time_ms)
    
    def get_threshold(self, container_id):
        """Calculate threshold using Chebyshev's inequality"""
        if container_id not in self.container_windows:
            return None  # No data yet
        
        window = self.container_windows[container_id]
        
        if len(window) < 100:  # Need minimum samples
            return None
        
        # Calculate statistics
        data = np.array(window)
        mu = np.mean(data)      # Mean
        sigma = np.std(data)     # Standard deviation
        
        # Chebyshev threshold: θ = μ + k*σ
        threshold = mu + (self.k * sigma)
        
        return threshold
    
    def is_anomaly(self, container_id, cpu_time_ms):
        """Check if CPU time exceeds threshold"""
        threshold = self.get_threshold(container_id)
        
        if threshold is None:
            return False  # Not enough data
        
        return cpu_time_ms > threshold
    
    def get_statistics(self, container_id):
        """Get current statistics for a container"""
        if container_id not in self.container_windows:
            return None
        
        window = self.container_windows[container_id]
        data = np.array(window)
        
        return {
            'container_id': container_id,
            'sample_count': len(window),
            'mean': float(np.mean(data)),
            'std': float(np.std(data)),
            'min': float(np.min(data)),
            'max': float(np.max(data)),
            'threshold': float(self.get_threshold(container_id))
        }

# Test the calculator
if __name__ == "__main__":
    calc = DynamicThresholdCalculator()
    
    # Simulate normal traffic (CPU time 50-150ms)
    for i in range(1000):
        cpu_time = np.random.normal(100, 20)  # Mean=100, Std=20
        calc.update(container_id=123, cpu_time_ms=cpu_time)
    
    # Check statistics
    stats = calc.get_statistics(123)
    print("\n📊 Container Statistics:")
    print(f"   Mean: {stats['mean']:.2f} ms")
    print(f"   Std:  {stats['std']:.2f} ms")
    print(f"   Threshold: {stats['threshold']:.2f} ms")
    
    # Test anomaly detection
    print("\n🧪 Testing Anomaly Detection:")
    test_values = [100, 150, 200, 250, 300]
    for val in test_values:
        is_anomaly = calc.is_anomaly(123, val)
        print(f"   CPU={val}ms → {'🚨 ANOMALY' if is_anomaly else '✅ Normal'}")
