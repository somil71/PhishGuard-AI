import nbformat as nbf

nb = nbf.v4.new_notebook()

# Metadata
nb.metadata = {
    "kernelspec": {
        "display_name": "Python 3",
        "language": "python",
        "name": "python3"
    },
    "language_info": {
        "name": "python",
        "version": "3.11.6"
    }
}

cells = []

# Title & Overview
cells.append(nbf.v4.new_markdown_cell("""# PhishGuard-AI: Intelligent Phishing URL Detection Using ML and Explainable Analytics

Welcome to the **PhishGuard-AI** Machine Learning and Explainable AI (XAI) training pipeline notebook.
Phishing attacks remain one of the most persistent and devastating vectors in cybersecurity, responsible for over 80% of reported security incidents. Traditional signature-based blacklists suffer from zero-hour latency, failing against newly spun disposable domains, typosquats, and homograph obfuscation.

### Notebook Objectives:
1. **Dataset Ingestion & Exploration**: Load balanced high-entropy phishing and authentic legitimate URL corpora.
2. **Feature Engineering**: Extract 34 structural, lexical, entropy, cryptographic, and brand impersonation features.
3. **Model Development**: Train and tune multiple ensemble learning architectures:
   - LightGBM (Gradient Boosting with leaf-wise tree growth)
   - XGBoost (Extreme Gradient Boosting with second-order gradients)
   - Random Forest (Bagging ensemble of decorrelated decision trees)
   - Soft Voting Ensemble (Calibrated weighted consensus)
4. **Model Evaluation**: ROC-AUC, Precision, Recall, F1-Score, and Confusion Matrix diagnostics.
5. **Explainable AI (XAI) with SHAP**: Compute global feature importance and granular local SHAP attributions."""))

# Imports
cells.append(nbf.v4.new_code_cell("""import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_curve, roc_auc_score, accuracy_score, f1_score
)
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
import lightgbm as lgb
import xgboost as xgb
import shap

# Ensure root directory is in sys.path
sys.path.append(os.path.abspath('..'))
from src.feature_extractor import FEATURE_NAMES, FEATURE_DESCRIPTIONS, extract_features
from src.dataset_generator import create_dataset

# Visualization styling
sns.set_theme(style="whitegrid", palette="muted")
plt.rcParams['figure.figsize'] = (10, 6)
print("Libraries loaded successfully.")"""))

# Dataset Loading
cells.append(nbf.v4.new_markdown_cell("""## 1. Dataset Generation and Feature Engineering

We use our comprehensive dataset generator containing 12,000 URLs (6,000 Phishing and 6,000 Legitimate) across diverse attack vectors (typosquatting, punycode, subdomain spoofing, IP hosting, abusive TLDs, and credential parameter injection)."""))

cells.append(nbf.v4.new_code_cell("""DATA_PATH = '../data/processed_features.csv'

if not os.path.exists(DATA_PATH):
    print("Generating dataset...")
    df_raw, df_features = create_dataset(total_samples=12000, data_dir='../data')
else:
    df_features = pd.read_csv(DATA_PATH)

print(f"Dataset Shape: {df_features.shape}")
df_features.head()"""))

# Exploratory Data Analysis
cells.append(nbf.v4.new_markdown_cell("""## 2. Exploratory Data Analysis (EDA)

Let's examine the label balance, feature correlations, and key distribution differences between legitimate and phishing URLs."""))

cells.append(nbf.v4.new_code_cell("""print("Class distribution:")
print(df_features['label'].value_counts())

# Plot distribution of Shannon Entropy and URL Length
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

sns.kdeplot(data=df_features, x='url_entropy', hue='label', common_norm=False, fill=True, ax=axes[0], palette=['#10b981', '#f43f5e'])
axes[0].set_title("Shannon Entropy Distribution by Class (0: Legit, 1: Phish)")
axes[0].set_xlabel("URL Shannon Entropy")

sns.boxplot(data=df_features, x='label', y='sensitive_keywords_count', ax=axes[1], palette=['#10b981', '#f43f5e'])
axes[1].set_title("Sensitive Keywords Count by Class")
axes[1].set_xticklabels(["Legitimate", "Phishing"])

plt.tight_layout()
plt.show()"""))

# Train Test Split
cells.append(nbf.v4.new_markdown_cell("""## 3. Train-Test Split

We use an 80/20 stratified split to preserve balanced class proportions in both sets."""))

cells.append(nbf.v4.new_code_cell("""X = df_features[FEATURE_NAMES]
y = df_features['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print(f"Training set: {X_train.shape[0]} samples")
print(f"Testing set:  {X_test.shape[0]} samples")
print(f"Features:     {X_train.shape[1]}")"""))

# Model Training
cells.append(nbf.v4.new_markdown_cell("""## 4. Model Training & Soft Voting Ensemble

We train three distinct gradient boosted and bagged tree architectures, and fuse them into a calibrated soft-voting meta-classifier."""))

cells.append(nbf.v4.new_code_cell("""# 1. LightGBM
lgb_model = lgb.LGBMClassifier(
    n_estimators=150,
    learning_rate=0.05,
    num_leaves=31,
    random_state=42,
    verbose=-1
)
lgb_model.fit(X_train, y_train)

# 2. XGBoost
xgb_model = xgb.XGBClassifier(
    n_estimators=150,
    learning_rate=0.05,
    max_depth=5,
    eval_metric='logloss',
    random_state=42
)
xgb_model.fit(X_train, y_train)

# 3. Random Forest
rf_model = RandomForestClassifier(
    n_estimators=120,
    max_depth=12,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train, y_train)

# 4. Soft Voting Ensemble
ensemble_model = VotingClassifier(
    estimators=[('lgb', lgb_model), ('xgb', xgb_model), ('rf', rf_model)],
    voting='soft'
)
ensemble_model.fit(X_train, y_train)

print("All models trained successfully!")"""))

# Evaluation
cells.append(nbf.v4.new_markdown_cell("""## 5. Comparative Evaluation & Performance Metrics

Let's evaluate each model on the holdout test set."""))

cells.append(nbf.v4.new_code_cell("""models = {
    "LightGBM": lgb_model,
    "XGBoost": xgb_model,
    "Random Forest": rf_model,
    "Ensemble (PhishGuard)": ensemble_model
}

results = []
for name, model in models.items():
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)
    
    results.append({
        "Model": name,
        "Accuracy (%)": round(acc * 100, 2),
        "F1-Score (%)": round(f1 * 100, 2),
        "ROC-AUC": round(auc, 4)
    })

results_df = pd.DataFrame(results)
display(results_df)"""))

# Confusion Matrix and ROC Curve
cells.append(nbf.v4.new_markdown_cell("""### Confusion Matrix and ROC Curve Visualization"""))

cells.append(nbf.v4.new_code_cell("""fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Confusion Matrix
y_pred_ens = ensemble_model.predict(X_test)
cm = confusion_matrix(y_test, y_pred_ens)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0],
            xticklabels=['Legitimate', 'Phishing'],
            yticklabels=['Legitimate', 'Phishing'])
axes[0].set_title("Ensemble Confusion Matrix")
axes[0].set_xlabel("Predicted Label")
axes[0].set_ylabel("True Label")

# ROC Curve for all models
for name, model in models.items():
    probs = model.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, probs)
    auc = roc_auc_score(y_test, probs)
    axes[1].plot(fpr, tpr, label=f"{name} (AUC = {auc:.4f})")

axes[1].plot([0, 1], [0, 1], 'k--', alpha=0.5)
axes[1].set_title("Receiver Operating Characteristic (ROC) Comparison")
axes[1].set_xlabel("False Positive Rate")
axes[1].set_ylabel("True Positive Rate")
axes[1].legend(loc="lower right")

plt.tight_layout()
plt.show()"""))

# SHAP Explainable AI
cells.append(nbf.v4.new_markdown_cell("""## 6. Explainable AI (XAI) with SHAP

Explainability is essential for security analysts to trust automated ML detections. Using SHAP (SHapley Additive exPlanations), we calculate Shapley values based on cooperative game theory to quantify exact feature attributions."""))

cells.append(nbf.v4.new_code_cell("""explainer = shap.TreeExplainer(lgb_model)
shap_sample = X_test.iloc[:300]
shap_values = explainer.shap_values(shap_sample)

# Handle binary classification output format
if isinstance(shap_values, list):
    vals_to_plot = shap_values[1]
else:
    vals_to_plot = shap_values

# Global Summary Plot
plt.figure(figsize=(10, 8))
shap.summary_plot(vals_to_plot, shap_sample, show=True)"""))

# Live Inference Example
cells.append(nbf.v4.new_markdown_cell("""## 7. Real-Time Inference on Arbitrary URLs

Let's test our complete pipeline on a live sample URL."""))

cells.append(nbf.v4.new_code_cell("""sample_test_url = "http://paypa1-security-verification.xyz/login.php?user=victim"

features_sample = extract_features(sample_test_url)
df_sample = pd.DataFrame([features_sample])[FEATURE_NAMES]

prob_phish = ensemble_model.predict_proba(df_sample)[0][1]
print(f"Target URL: {sample_test_url}")
print(f"Phishing Probability: {prob_phish * 100:.2f}%")
print(f"Classification: {'PHISHING DETECTED' if prob_phish > 0.5 else 'LEGITIMATE'}")"""))

nb['cells'] = cells

with open('ml/notebooks/PhishGuard_ML_Explainability_Pipeline.ipynb', 'w', encoding='utf-8') as f:
    nbf.write(nb, f)

print("Jupyter Notebook created successfully at ml/notebooks/PhishGuard_ML_Explainability_Pipeline.ipynb")
