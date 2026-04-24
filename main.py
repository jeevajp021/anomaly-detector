# Create main.py (Root of project)

#!/usr/bin/env python3
"""
AI-Driven Network Anomaly Detection Framework
Phase 1: Live Anomaly Detector
"""

import sys
import argparse
import yaml
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from ebpf.loader import EBPFConnectionTracker
from ml.classifier import MLPostFilter

class AnomalyDetectionSystem:
    """
    Complete anomaly detection system integrating:
    - eBPF kernel monitoring
    - Dynamic threshold calculation
    - ML post-filtering
    """
    
    def __init__(self, config_path='config/config.yaml'):
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        print(f"\n{'='*70}")
        print(f"🚀 AI-Driven Network Anomaly Detection Framework")
        print(f"   Phase 1: Live Anomaly Detector")
        print(f"{'='*70}\n")
        
        # Initialize components
        self._init_ebpf_tracker()
        self._init_ml_filter()
        
        print(f"\n{'='*70}")
        print(f"✅ System initialization complete")
        print(f"{'='*70}\n")
    
    def _init_ebpf_tracker(self):
        """Initialize eBPF connection tracker"""
        print("⏳ Initializing eBPF tracker...")
        self.tracker = EBPFConnectionTracker(
            ebpf_program_path="ebpf/programs/connection_tracker.c",
            use_dynamic_threshold=True
        )
    
    def _init_ml_filter(self):
        """Initialize ML post-filter"""
        print("\n⏳ Initializing ML post-filter...")
        try:
            self.ml_filter = MLPostFilter()
            self.use_ml = True
        except FileNotFoundError:
            print("⚠️  ML model not found - running without post-filter")
            print("   Train model first: python ml/training/train_model.py")
            self.use_ml = False
    
    def start(self):
        """Start the detection system"""
        try:
            self.tracker.start_monitoring()
        except KeyboardInterrupt:
            print("\n\n🛑 System shutdown requested")
        finally:
            self.tracker.cleanup()
            self._print_summary()
    
    def _print_summary(self):
        """Print detection summary"""
        print(f"\n{'='*70}")
        print(f"📊 Detection Summary")
        print(f"{'='*70}")
        print(f"Total Alerts:  {len(self.tracker.alerts)}")
        print(f"Normal Events: {len(self.tracker.normal_traffic)}")
        
        if self.tracker.alerts:
            # Calculate metrics
            severities = [a['severity'] for a in self.tracker.alerts]
            print(f"\nAlert Breakdown:")
            print(f"  CRITICAL: {severities.count('CRITICAL')}")
            print(f"  HIGH:     {severities.count('HIGH')}")
            print(f"  MEDIUM:   {severities.count('MEDIUM')}")
            print(f"  LOW:      {severities.count('LOW')}")
        
        print(f"{'='*70}\n")

def main():
    parser = argparse.ArgumentParser(
        description='AI-Driven Network Anomaly Detection Framework'
    )
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    # Create and start system
    system = AnomalyDetectionSystem(config_path=args.config)
    system.start()

if __name__ == "__main__":
    main()
