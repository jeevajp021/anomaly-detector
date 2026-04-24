# ml/training/create_dataset.py

import json
import numpy as np
from pathlib import Path
import sys
import random

# Add project root to path
ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT))

from ml.feature_extractor import FeatureExtractor


def load_training_data():
    """Load all collected training data"""
    
    normal_dir = ROOT / "data/training"
    attack_dir = ROOT / "data/output"
    
    normal_files = list(normal_dir.glob("normal_*.json"))
    attack_files = list(attack_dir.glob("alerts_*.json"))
    
    print(f"📂 Normal dir: {normal_dir}")
    print(f"📂 Attack dir: {attack_dir}")
    print(f"📄 Found {len(normal_files)} normal files")
    print(f"📄 Found {len(attack_files)} attack files")
    
    normal_data = []
    for file in normal_files:
        with open(file, 'r') as f:
            normal_data.extend(json.load(f))
    
    attack_data = []
    for file in attack_files:
        with open(file, 'r') as f:
            attack_data.extend(json.load(f))
    
    print(f"✅ Loaded {len(normal_data)} normal samples")
    print(f"✅ Loaded {len(attack_data)} attack samples")
    
    return normal_data, attack_data


def create_labeled_dataset():
    """Create labeled dataset with features"""
    
    normal_data, attack_data = load_training_data()
    
    extractor = FeatureExtractor()
    
    # Extract features
    normal_features = extractor.extract_batch(normal_data)
    attack_features = extractor.extract_batch(attack_data)
    
    if len(normal_features) == 0 or len(attack_features) == 0:
        print("❌ No features extracted. Check input data format.")
        return None, None

    # 🔥 STEP 1: Balance dataset (downsample majority class)
    min_samples = min(len(normal_features), len(attack_features))
    
    normal_features = normal_features[:min_samples]
    attack_features = attack_features[:min_samples]
    
    normal_labels = [0] * len(normal_features)
    attack_labels = [1] * len(attack_features)
    
    # Combine
    all_features = normal_features + attack_features
    all_labels = normal_labels + attack_labels

    # 🔥 STEP 2: Shuffle dataset
    combined = list(zip(all_features, all_labels))
    random.shuffle(combined)
    all_features, all_labels = zip(*combined)

    # Convert to numpy
    X = extractor.to_numpy(all_features)
    y = np.array(all_labels)
    
    print(f"\n📊 Dataset Created (Balanced):")
    print(f"   Total samples: {len(X)}")
    print(f"   Features: {X.shape[1]}")
    print(f"   Normal: {sum(y == 0)}")
    print(f"   Attack: {sum(y == 1)}")
    print(f"   Balance: {sum(y == 1) / len(y) * 100:.1f}% attacks")
    
    # Save dataset
    output_path = ROOT / "data/training/dataset.npz"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    np.savez(
        output_path,
        X=X,
        y=y,
        feature_names=extractor.feature_names
    )
    
    print(f"💾 Saved to {output_path}")
    
    return X, y


if __name__ == "__main__":
    X, y = create_labeled_dataset()
