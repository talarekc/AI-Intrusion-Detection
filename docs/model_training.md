# Model Training

## Overview
This phase focused on training the first machine learning model for the AI-Powered Network Intrusion Detection project.

The goal was to train a model that can classify network traffic as either normal traffic or attack traffic.

---

## Model Used
The initial model used was a **Random Forest Classifier**.

Random Forest was selected because it performs well on structured tabular data, handles many input features, and is commonly used for classification tasks.

---

## Dataset
The model was trained using a sample of the CICIDS2017 dataset.

The dataset included two classes:

- **BENIGN** — normal network traffic
- **DDoS** — distributed denial-of-service attack traffic

---

## Preprocessing Steps
Before training, the dataset was prepared using the following steps:

- Removed duplicate rows
- Replaced infinite values with NaN
- Dropped missing values
- Separated features and labels
- Encoded text labels into numerical values
- Split the dataset into training and testing sets

---

## Train-Test Split
The data was split into:

- **80% training data**
- **20% testing data**

The training set was used to teach the model patterns in the data, while the testing set was used to evaluate performance on unseen data.

---

## Model Performance
The Random Forest model achieved very high performance on the test set.

### Accuracy
The model achieved approximately:

```text
99.99%