# Create ml/training/train_model.py

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import yaml
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]

def load_dataset():
    """Load the preprocessed dataset"""
    data_path = ROOT / "data/training/dataset.npz"
    data = np.load(data_path, allow_pickle=True)
    return data['X'], data['y'], data['feature_names']

def train_model():
    """Train Random Forest classifier"""
    
    # Load data
    X, y, feature_names = load_dataset()
    
    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"🎓 Training Set: {len(X_train)} samples")
    print(f"🧪 Test Set: {len(X_test)} samples")
    
    # Load config
    config_path = ROOT / "config/config.yaml"
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    ml_config = config['ml']['model']
    
    # Train Random Forest
    print("\n⏳ Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=ml_config['n_estimators'],
        max_depth=ml_config['max_depth'],
        random_state=ml_config['random_state'],
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    print("✅ Training complete!")
    
    # Evaluate
    print("\n📊 Evaluation Results:")
    
    # Test accuracy
    test_score = model.score(X_test, y_test)
    print(f"   Test Accuracy: {test_score:.4f}")
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5)
    print(f"   CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Predictions
    y_pred = model.predict(X_test)
    
    # Classification report
    print("\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Normal', 'Attack']))
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\n📐 Confusion Matrix:")
    print(f"                Predicted")
    print(f"                Normal  Attack")
    print(f"Actual Normal     {cm[0][0]:4d}    {cm[0][1]:4d}")
    print(f"       Attack     {cm[1][0]:4d}    {cm[1][1]:4d}")
    
    # Feature importance
    print("\n🎯 Feature Importance:")
    importances = model.feature_importances_
    for name, importance in sorted(zip(feature_names, importances), 
                                  key=lambda x: x[1], reverse=True):
        print(f"   {name:25s}: {importance:.4f}")
    
    # Save model
    model_path = ROOT / "ml/models/random_forest.joblib"
    model_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, model_path)
    print(f"\n💾 Model saved to {model_path}")
    
    # Calculate metrics for Phase 1 targets
    tn, fp, fn, tp = cm.ravel()
    
    adr = (tp + tn) / (tp + tn + fp + fn)  # Attack Detection Rate
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
    
    print(f"\n🎯 Phase 1 Target Metrics:")
    print(f"   ADR (Attack Detection Rate): {adr:.4f} (Target: ≥0.90)")
    print(f"   FPR (False Positive Rate):   {fpr:.4f} (Target: ≤0.02)")
    
    if adr >= 0.90 and fpr <= 0.02:
        print("   ✅ PHASE 1 TARGETS MET!")
    else:
        print("   ⚠️  Targets not met - continue training")
    
    return model

if __name__ == "__main__":
    model = train_model()
