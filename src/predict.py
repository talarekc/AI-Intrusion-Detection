import pandas as pd
import joblib
from datetime import datetime

# Load saved model and label encoder
model = joblib.load("models/random_forest_model.joblib")
label_encoder = joblib.load("models/label_encoder.joblib")

# Load sample traffic data
# For now, this uses the same local dataset sample for testing
file_path = "data/combine.csv"
df = pd.read_csv(file_path, nrows=1000)

# Clean data
df = df.drop_duplicates()
df = df.replace([float("inf"), float("-inf")], pd.NA)
df = df.dropna()

# Separate features from label
X = df.drop(" Label", axis=1)

# Make predictions
predictions = model.predict(X)

# Get confidence scores
confidence_scores = model.predict_proba(X).max(axis=1)

# Convert numeric predictions back to labels
attack_labels = label_encoder.inverse_transform(predictions)

# Severity mapping
def get_severity(label):
    if label == "DDoS":
        return "High"
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

# Save results for dashboard
results.to_csv("data/prediction_output.csv", index=False)

print("Predictions generated successfully.")
print(results.head())