import os
import pandas as pd
import joblib
from datetime import datetime

# Repo root (one level up from src/)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load multi-class trained model and label encoder
model = joblib.load(os.path.join(REPO_ROOT, "models", "random_forest_multiclass_model.joblib"))
label_encoder = joblib.load(os.path.join(REPO_ROOT, "models", "multiclass_label_encoder.joblib"))

# Raw CSV locations — works for both brian and bagsg
DATA_ROOTS = [
    r"C:\Users\brian\OneDrive - Sacred Heart University\CIC-IDS-2017\MachineLearningCSV\MachineLearningCVE",
    r"C:\Users\bagsg\OneDrive - Sacred Heart University\CIC-IDS-2017\MachineLearningCSV\MachineLearningCVE",
]
DATA_DIR = next((p for p in DATA_ROOTS if os.path.exists(p)), None)
if DATA_DIR is None:
    raise FileNotFoundError("CIC-IDS-2017 dataset not found. Update DATA_ROOTS in predict.py.")

files = [
    os.path.join(DATA_DIR, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"),
    os.path.join(DATA_DIR, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"),
    os.path.join(DATA_DIR, "Tuesday-WorkingHours.pcap_ISCX.csv"),
    os.path.join(DATA_DIR, "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"),
]

# Load and randomly sample rows from each file
dfs = []

for file in files:
    temp_df = pd.read_csv(file)

    # Randomly sample 2000 rows per file
    if len(temp_df) > 2000:
        temp_df = temp_df.sample(
            n=2000,
            random_state=42
        )

    dfs.append(temp_df)

df = pd.concat(
    dfs,
    ignore_index=True
)

# Clean data
df = df.drop_duplicates()
df = df.replace([float("inf"), float("-inf")], pd.NA)
df = df.dropna()

# Keep a copy of labels if they exist, but do not use them for prediction
if " Label" in df.columns:
    X = df.drop(" Label", axis=1)
else:
    X = df.copy()

# Make predictions
predictions = model.predict(X)

# Get confidence scores
confidence_scores = model.predict_proba(X).max(axis=1)

# Convert numeric predictions back to readable labels
attack_labels = label_encoder.inverse_transform(predictions)

# Severity mapping
def get_severity(label):
    if label == "DDoS":
        return "High"
    elif label == "Web Attack":
        return "High"
    elif label == "Brute Force":
        return "Medium"
    elif label == "Port Scan":
        return "Low"
    elif label == "BENIGN":
        return "Low"
    else:
        return "Medium"

# Create dashboard-ready output
results = pd.DataFrame({
    "timestamp": [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * len(attack_labels),
    "attack_type": attack_labels,
    "confidence": confidence_scores.round(2),
    "severity": [get_severity(label) for label in attack_labels]
})

# Save prediction output for dashboard
results.to_csv(os.path.join(REPO_ROOT, "data", "prediction_output.csv"), index=False)

print("Multi-class predictions generated successfully.")
print(results.head())
print("\nPrediction counts:")
print(results["attack_type"].value_counts())