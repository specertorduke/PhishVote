# Dataset Notes

## Datasets Used in Main Experiment

### DS01 — LegitPhish 2025
- **File**: `LegitPhish2025.csv`
- **Instances**: 31,808 (after dedup)
- **Features**: 16
- **Target column**: `ClassLabel` (0 = phishing, 1 = legitimate)
- **Notes**: Novel dataset introduced in this paper. Heavily imbalanced (~77.8% phishing). SMOTE is applied during training.

### DS03 — Phishing Legitimate Full (UCI 2018)
- **File**: `Phishing_Legitimate_full-2018.csv`
- **Source**: https://archive.ics.uci.edu/dataset/327/phishing+websites
- **Instances**: 9,581 (after dedup; raw = 10,000)
- **Features**: 49
- **Target column**: `CLASS_LABEL` (0 = phishing, 1 = legitimate)
- **Notes**: Continuous/numeric features. Near-balanced (52.1% phishing). No SMOTE needed.

### DS04 — Web Page Phishing Detection Dataset (2021)
- **File**: `dataset-2021.csv`
- **Source**: https://data.mendeley.com/datasets/c2gkx5m7z2/1
- **Instances**: 11,256 (after dedup; raw = 11,430)
- **Features**: 88
- **Target column**: `status` ('phishing' or 'legitimate')
- **Notes**: Rich feature set including WHOIS, DNS, and page content features. Balanced (50/50).

---

## Datasets Excluded

### DS02 — PhishStorm (2014)
- **File**: `PhishStorm-2014.csv`
- **Raw instances**: 96,005
- **Unique instances**: 57,492
- **Duplicate rows**: 38,513 (**40.1%**)
- **Leakage rate**: 45.6% of test rows are copies of training rows (no-dedup split)
- **Reason for exclusion**: Data leakage via duplicates inflates accuracy by ~4–6%. Prior work reporting 95–97% on this dataset did not deduplicate before splitting. Our honest result on clean data is ~91%.
- **See**: `notebooks/data_integrity_audit.ipynb` for full proof.

### DS05 — UCI Phishing Websites (2015)
- **File**: `Training Dataset.arff`
- **Raw instances**: 11,055
- **Unique instances**: 5,849
- **Duplicate rows**: 5,206 (**47.1%**)
- **Leakage rate**: 64.6% of test rows are copies of training rows (no-dedup split)
- **Reason for exclusion**: Categorical feature encoding (-1/0/1) means many structurally different URLs produce identical feature vectors. Leakage is severe. Prior work reporting ~99% on this dataset did not deduplicate. Our honest result on clean data is ~94%.
- **See**: `notebooks/data_integrity_audit.ipynb` for full proof.
- **Reference**: Mohammad, R.M., Thabtah, F., McCluskey, L. (2014). Predicting phishing websites based on self-structuring neural network. Neural Computing and Applications, 25(2), 443–458.
