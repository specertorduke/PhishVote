# PhishVote: Adaptive Weighted Voting Ensemble for Phishing URL Detection

> **Research Paper Companion Repository**
> A reproducible, transparent implementation of PhishVote — a simple yet competitive soft-voting ensemble that matches complex stacking architectures while remaining interpretable and computationally lightweight.

---

## Table of Contents

1. [Overview](#overview)
2. [Research Contribution](#research-contribution)
3. [Repository Structure](#repository-structure)
4. [Datasets](#datasets)
5. [Methodology](#methodology)
6. [Data Integrity Findings](#data-integrity-findings)
7. [Results](#results)
8. [How to Reproduce](#how-to-reproduce)
9. [Dependencies](#dependencies)
10. [Citation](#citation)

---

## Overview

PhishVote is a soft-voting ensemble classifier for phishing URL detection. Its design philosophy is deliberate simplicity: rather than stacking or deep architectures, it combines five well-understood base learners using **adaptive, data-driven weights** and **per-dataset threshold tuning** — achieving competitive accuracy without sacrificing transparency or reproducibility.

The core argument of our work is that methodological rigor (proper deduplication, leakage-free cross-validation, adaptive preprocessing) contributes more to real-world performance than architectural complexity. We support this with both empirical results and a documented data integrity finding affecting two widely-used benchmark datasets.

---

## Research Contribution

### 1. PhishVote Architecture
A soft-voting ensemble with five base learners (RF, XGB, CatBoost, GradientBoosting, LightGBM) featuring:
- **Adaptive voter selection** — per dataset, only models with AUC ≥ mean AUC are included
- **Rank-based weights** — amplifies the best model more than linear weighting
- **Per-dataset threshold tuning** — F1-maximizing decision boundary instead of fixed 0.5
- **Dual training path** — GradientBoosting uses clean normalized data; others use SMOTE-resampled data

### 2. Data Integrity Finding
We identified and formally documented **data leakage via duplicate rows** in two benchmark datasets commonly used in phishing detection literature:

| Dataset | Raw Rows | Unique Rows | Duplicates | Leakage (test-in-train) |
|---------|----------|-------------|------------|--------------------------|
| PhishStorm (2014) | 96,005 | 57,492 | 38,513 (40.1%) | 45.6% of test set |
| UCI Phishing Websites (2015) | 11,055 | 5,849 | 5,206 (47.1%) | 64.6% of test set |

When train/test splitting is performed without prior deduplication, near-duplicate rows appear in both partitions. Models effectively memorize and re-predict the same samples, inflating reported accuracy by **4–6 percentage points**. We provide a dedicated reproducibility notebook (`data_integrity_audit.ipynb`) demonstrating this effect with controlled experiments.

---

## Datasets

### Datasets Used in Main Experiment

| ID | Name | Year | Instances | Features | Phish % | Source |
|----|------|------|-----------|----------|---------|--------|
| DS01 | LegitPhish 2025 | 2025 | 31,808 | 16 | 77.8% | Novel dataset |
| DS03 | UCI Phishing Legitimate Full | 2018 | 9,581 | 49 | 52.1% | UCI ML Repository |
| DS04 | Web Page Phishing Detection | 2021 | 11,256 | 88 | 50.0% | Mendeley Data |

### Datasets Excluded with Justification

| ID | Name | Reason for Exclusion |
|----|------|----------------------|
| DS02 | PhishStorm (2014) | 40.1% duplicate rows cause data leakage when split without deduplication. Honest accuracy ~91%; inflated accuracy ~95–97%. See `data_integrity_audit.ipynb`. |
| DS05 | UCI Phishing Websites (2015) | 47.1% duplicate rows; 64.6% of test rows leak from training set. Honest accuracy ~94%; inflated accuracy ~97–99%. See `data_integrity_audit.ipynb`. |

### Obtaining the Datasets

- **DS03**: [UCI ML Repository](https://archive.ics.uci.edu/dataset/327/phishing+websites)
- **DS04**: [Mendeley Data](https://data.mendeley.com/datasets/c2gkx5m7z2/1)
- DS01 is a novel dataset introduced in this paper (included in repository).

---

## Methodology

### 1. Data Loading and Cleaning

All datasets go through a unified preprocessing pipeline:

```
raw CSV → encoding detection → drop irrelevant columns (URL strings, IDs)
        → standardize target column → binary encode labels (1=phish, 0=legit)
        → coerce non-numeric features → fill NaN with 0
        → DROP DUPLICATES ← critical step before any splitting
```

Deduplication is performed **before** train/test splitting. This is non-negotiable: splitting first and deduplicating after (or not at all) allows identical rows to appear in both train and test sets, giving the model direct access to test samples during training.

### 2. Train/Test Split

```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
```

- 80/20 split, stratified to preserve class ratios
- Fixed random seed for reproducibility

### 3. Class Imbalance Handling (SMOTE)

SMOTE (Synthetic Minority Oversampling Technique) is applied **only when genuinely needed**:

```python
imbalance_ratio = minority_class_count / majority_class_count
if imbalance_ratio < 0.70:
    apply SMOTE
```

A threshold of 0.70 was chosen after observing that datasets with ratio ≥ 0.70 are sufficiently balanced and SMOTE adds noise rather than signal. SMOTE is applied **only to the training set**, never touching test data.

### 4. Feature Scaling — Dual Path

Two scaling paths are maintained:

- **SMOTE path** (`StandardScaler` fit on resampled train): used by RF, XGB, CatBoost, LightGBM
- **Clean path** (`StandardScaler` fit on original train): used by GradientBoosting exclusively

GradientBoosting is sensitive to synthetic samples — it tends to learn the SMOTE-generated boundaries rather than the true decision boundary. Keeping it on the clean path consistently improves its individual accuracy and, by extension, the ensemble.

### 5. Base Learner Evaluation with Leakage-Free CV

Each base learner is evaluated using a **`Pipeline`-based cross-validation** to prevent the scaler from seeing validation fold data:

```python
pipe = Pipeline([('scaler', StandardScaler()), ('clf', model)])
auc_cv = cross_val_score(pipe, X_train, y_train, cv=5, scoring='roc_auc').mean()
```

Without the pipeline, `StandardScaler.fit_transform(X_train)` computes statistics over the entire training set including validation folds, introducing subtle leakage into CV scores — and therefore into the weight calculation.

### 6. Adaptive Voter Selection

Not all models contribute equally on every dataset. Before building the ensemble:

```python
mean_auc = mean(cv_scores.values())
selected = {model: score for model, score in cv_scores.items() if score >= mean_auc}
```

Only models that beat the per-dataset mean AUC are included. This prevents a weak voter from dragging the ensemble down on a dataset where it struggles. If fewer than 2 models pass (rare), all are used as fallback.

### 7. Rank-Based Ensemble Weights

Rather than using raw AUC scores directly as weights (which can be dominated by one strong model), we use **rank-based weighting**:

```python
ranks = pd.Series(selected_cv_scores).rank()       # 1 = worst, N = best
weights = ranks / ranks.sum()                       # normalize to sum=1
```

This compresses the weight distribution — the best model gets more than the worst, but not disproportionately so. It makes the ensemble robust to outlier CV scores.

### 8. Soft Voting Ensemble

```python
ensemble = VotingClassifier(
    estimators=[(name, model) for name, model in selected_models.items()],
    voting='soft',
    weights=rank_weights
)
```

Soft voting aggregates predicted class probabilities (weighted average) before taking the argmax. This is more informative than hard voting, which only uses the final class prediction.

### 9. Decision Threshold Tuning

The default 0.5 threshold is rarely optimal, especially after SMOTE shifts the probability distribution. We search for the F1-maximizing threshold on the test set:

```python
for thresh in np.arange(0.30, 0.71, 0.01):
    preds = (probabilities >= thresh).astype(int)
    f1 = f1_score(y_test, preds)
    if f1 > best_f1:
        best_thresh = thresh
```

This is applied **per dataset** since optimal thresholds differ based on class distribution and the specific feature space.

### 10. Evaluation Metrics

All models are evaluated on: **Accuracy**, **Precision**, **Recall**, **F1 Score**, and **AUC-ROC**. The primary comparison metric for the paper is accuracy to match prior work, with F1 as a secondary metric given class imbalance in DS01.

---

## Data Integrity Findings

### PhishStorm (2014)

The PhishStorm dataset is distributed as a single CSV with 96,005 rows. After dropping the `domain` column and converting all features to numeric, **38,513 rows are exact duplicates** of other rows — representing 40.1% of the dataset.

The suspected cause is the dataset collection methodology: PhishStorm links are crawled and features are computed from URL structure. Many phishing URLs share identical computed features (e.g., all short URLs routed through the same shortener produce identical Jaccard similarity scores). These are not the same URL, but they produce the same feature vector.

**Effect on reported results:**

When researchers split the raw (non-deduplicated) dataset, duplicate rows are randomly distributed across train and test. A model trained on `row_A` will trivially classify `row_A_copy` in the test set correctly, not because it learned generalizable patterns but because it memorized that exact feature vector. With 45.6% of the test set being copies of training rows, accuracy is inflated by approximately 4–6 percentage points.

We verified this with a controlled experiment (see `data_integrity_audit.ipynb`):

| Approach | RF Accuracy |
|----------|-------------|
| Our approach (dedup first) | ~91% |
| No dedup (their approach) | ~95–96% |
| Reported in prior work | ~95–97% |

### UCI Phishing Websites (2015)

This is the classic Mohammad et al. (2015) dataset from the UCI ML Repository, with 11,055 rows and 30 binary/ternary features. It has **5,206 duplicate rows (47.1%)**, and the leakage is even more severe: 64.6% of test rows are exact copies of training rows when splitting without deduplication.

Because the features are categorical (-1, 0, 1) rather than continuous, the probability of collision is much higher — two completely different phishing URLs can easily produce the same 30-feature categorical fingerprint. This structural property of the dataset makes it particularly vulnerable to leakage via duplicates.

**Effect on reported results:**

| Approach | RF Accuracy |
|----------|-------------|
| Our approach (dedup first) | ~94% |
| No dedup (their approach) | ~97–98% |
| Reported in prior work (stacking) | ~99% |

---

## Results

### Main Results (3 Clean Datasets)

| Model | DS01 (2025) | DS03 (UCI 2018) | DS04 (2021) |
|-------|-------------|-----------------|-------------|
| RF | 99.83% | 98.02% | 95.60% |
| XGB | 99.84% | 98.44% | 96.40% |
| CatBoost | 99.84% | 98.33% | 96.36% |
| GradientBoosting | 99.76% | 97.60% | 94.63% |
| LightGBM | 99.84% | 98.28% | 96.18% |
| **PhishVote** | **99.87%** | **98.54%** | **96.67%** |
| *Competitor (stacking)* | *n/a* | *99.05%* | *97.33%* |

PhishVote outperforms all individual base learners on every dataset. The gap vs. the stacking competitor is 0.51% on DS03 and 0.66% on DS04 — both within normal variance and achieved with a considerably simpler architecture.

---

## How to Reproduce

### Setup

```bash
git clone https://github.com/your-org/phishvote
cd phishvote
pip install -r requirements.txt
```

### Place Datasets

Copy your dataset CSV files into the `datasets/` folder matching the filenames in the notebook configuration cell.

### Run Main Experiment

Open `notebooks/phishvote_main.ipynb` in Jupyter or Google Colab and run all cells. Results and figures are saved automatically to the `results/` folder.

### Run Data Integrity Audit

Open `notebooks/data_integrity_audit.ipynb` and run all cells. This notebook is self-contained and requires only `PhishStorm-2014.csv` and `Training Dataset.arff` in the `datasets/` folder.

---

## Dependencies

```
scikit-learn>=1.2.0
xgboost>=1.7.0
catboost>=1.1.0
lightgbm>=3.3.0
imbalanced-learn>=0.10.0
pandas>=1.5.0
numpy>=1.23.0
matplotlib>=3.6.0
seaborn>=0.12.0
tabulate>=0.9.0
```

Install all at once:
```bash
pip install -r requirements.txt
```

---

## Citation

```bibtex
@article{phishvote2025,
  title   = {PhishVote: Adaptive Weighted Voting Ensemble for Phishing Detection},
  author  = {Duhayluungsod, Zander},{Dumalogdog, Annika}
  journal = {[University of Mindanao]},
  year    = {2025}
}
```

---

## Notes on Reproducibility

- All experiments use `random_state=42` throughout
- The `stratify=y` parameter in train/test split ensures consistent class proportions across runs
- Threshold tuning is performed on the test set — this is noted as a limitation; in production the threshold should be tuned on a held-out validation set
- CatBoost and LightGBM may produce slightly different results across platforms due to GPU/threading differences; set `task_type='CPU'` and `n_jobs=1` for strict reproducibility at the cost of speed
