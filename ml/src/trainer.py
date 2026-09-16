import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, confusion_matrix
)
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
import lightgbm as lgb
import xgboost as xgb
import shap

from ml.src.feature_extractor import FEATURE_NAMES, FEATURE_DESCRIPTIONS
from ml.src.dataset_generator import create_dataset


def train_phishguard_pipeline(data_path: str = "ml/data/processed_features.csv", artifacts_dir: str = "ml/artifacts"):
    """
    Train LightGBM, XGBoost, and Random Forest classifiers,
    assemble an optimal Soft Voting Ensemble, calculate SHAP explainability,
    and persist production artifacts.
    """
    os.makedirs(artifacts_dir, exist_ok=True)

    # 1. Load or generate feature dataset
    if not os.path.exists(data_path):
        print(f"[*] Dataset not found at {data_path}. Generating benchmark dataset...")
        create_dataset(total_samples=12000)

    print(f"[*] Loading processed feature dataset from {data_path}...")
    df = pd.read_csv(data_path)
    
    X = df[FEATURE_NAMES]
    y = df["label"]

    # Compute feature stats for normalization and frontend display
    feature_stats = {}
    for col in FEATURE_NAMES:
        feature_stats[col] = {
            "mean": float(X[col].mean()),
            "std": float(X[col].std()),
            "min": float(X[col].min()),
            "max": float(X[col].max()),
            "description": FEATURE_DESCRIPTIONS.get(col, "")
        }

    # 2. Train-test split (80/20 stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[+] Dataset split: {len(X_train)} training samples, {len(X_test)} testing samples.")

    # 3. Model definitions
    print("[*] Training LightGBM Classifier...")
    model_lgb = lgb.LGBMClassifier(
        n_estimators=150,
        learning_rate=0.05,
        num_leaves=31,
        random_state=42,
        verbose=-1
    )
    model_lgb.fit(X_train, y_train)

    print("[*] Training XGBoost Classifier...")
    model_xgb = xgb.XGBClassifier(
        n_estimators=150,
        learning_rate=0.05,
        max_depth=5,
        eval_metric='logloss',
        random_state=42
    )
    model_xgb.fit(X_train, y_train)

    print("[*] Training Random Forest Classifier...")
    model_rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        random_state=42,
        n_jobs=-1
    )
    model_rf.fit(X_train, y_train)

    # 4. Soft Voting Ensemble
    print("[*] Constructing Soft-Voting Ensemble Classifier...")
    ensemble = VotingClassifier(
        estimators=[
            ('lgb', model_lgb),
            ('xgb', model_xgb),
            ('rf', model_rf)
        ],
        voting='soft'
    )
    ensemble.fit(X_train, y_train)

    # 5. Evaluate all models
    models_dict = {
        "LightGBM": model_lgb,
        "XGBoost": model_xgb,
        "Random Forest": model_rf,
        "Ensemble (PhishGuard)": ensemble
    }

    comparison_results = {}
    best_metrics = None

    for name, model in models_dict.items():
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred))
        rec = float(recall_score(y_test, y_pred))
        f1 = float(f1_score(y_test, y_pred))
        auc = float(roc_auc_score(y_test, y_prob))

        cm = confusion_matrix(y_test, y_pred).tolist()

        fpr, tpr, _ = roc_curve(y_test, y_prob)
        # Sample down ROC curve points for clean JSON payload
        step = max(1, len(fpr) // 50)
        roc_data = [
            {"fpr": round(float(f), 4), "tpr": round(float(t), 4)}
            for f, t in zip(fpr[::step], tpr[::step])
        ]

        metrics_obj = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "confusion_matrix": {
                "true_negative": cm[0][0],
                "false_positive": cm[0][1],
                "false_negative": cm[1][0],
                "true_positive": cm[1][1]
            },
            "roc_curve": roc_data
        }
        comparison_results[name] = metrics_obj
        print(f"    - {name}: Accuracy={acc*100:.2f}%, F1={f1*100:.2f}%, AUC={auc:.4f}")

        if name == "Ensemble (PhishGuard)":
            best_metrics = metrics_obj

    # 6. SHAP TreeExplainer for Explainable AI (XAI)
    print("[*] Computing SHAP explainability on LightGBM anchor model...")
    explainer = shap.TreeExplainer(model_lgb)
    
    # Representative sample of test set for global importance
    shap_sample = X_test.iloc[:500]
    shap_values = explainer.shap_values(shap_sample)

    # For binary classification, shap_values might be array of shape (N, num_features) or list of two arrays
    if isinstance(shap_values, list):
        shap_vals_arr = shap_values[1]
    else:
        shap_vals_arr = shap_values

    mean_abs_shap = np.abs(shap_vals_arr).mean(axis=0)
    importance_indices = np.argsort(mean_abs_shap)[::-1]

    feature_importances = []
    for idx in importance_indices:
        feat = FEATURE_NAMES[idx]
        feature_importances.append({
            "feature": feat,
            "importance": round(float(mean_abs_shap[idx]), 4),
            "description": FEATURE_DESCRIPTIONS.get(feat, "")
        })

    # 7. Persist Artifacts
    print(f"[*] Saving model artifacts to {artifacts_dir}...")
    
    # Save ensemble and sub-models
    pipeline_bundle = {
        "ensemble": ensemble,
        "lgb": model_lgb,
        "xgb": model_xgb,
        "rf": model_rf,
        "feature_names": FEATURE_NAMES
    }
    joblib.dump(pipeline_bundle, os.path.join(artifacts_dir, "phishguard_ensemble.joblib"), compress=3)

    # Save 100 background samples for live SHAP local attribution
    shap_bg = shap.sample(X_train, 100, random_state=42)
    joblib.dump(shap_bg, os.path.join(artifacts_dir, "shap_background.joblib"), compress=3)

    # Save feature metadata
    metadata = {
        "features": FEATURE_NAMES,
        "descriptions": FEATURE_DESCRIPTIONS,
        "statistics": feature_stats,
        "global_importance": feature_importances
    }
    with open(os.path.join(artifacts_dir, "feature_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    # Save metrics and comparison data
    metrics_summary = {
        "primary_model": "Ensemble (PhishGuard)",
        "test_samples_count": len(X_test),
        "primary_metrics": best_metrics,
        "model_comparison": comparison_results,
        "global_importance": feature_importances[:15]
    }
    with open(os.path.join(artifacts_dir, "metrics.json"), "w") as f:
        json.dump(metrics_summary, f, indent=2)

    print(f"[SUCCESS] PhishGuard ML Pipeline successfully trained and artifacts saved!")
    return metrics_summary


if __name__ == "__main__":
    train_phishguard_pipeline()
