#Data Preprocessing and Exploration
##Overview

This phase focused on preparing the CICIDS2017 dataset for machine learning. The goal was to clean the data, understand its structure, and prepare it for model training.

#Dataset Description

The dataset consists of network traffic flows with multiple features representing characteristics such as packet counts, flow duration, and byte rates.

Each row represents a network flow, and the dataset includes both normal (BENIGN) traffic and malicious traffic (e.g., DDoS attacks).

#Data Loading

The dataset was loaded using pandas from a CSV file located in the data directory.

#Data Exploration

Initial exploration included:

Inspecting the shape of the dataset (rows and columns)
Viewing the first few rows of data
Listing all feature (column) names
Identifying the label column used for classification

The label column was identified as ' Label', which contains values such as BENIGN and DDoS.

#Class Distribution

The dataset contains two classes:

BENIGN (normal traffic)
DDoS (attack traffic)

The distribution was analyzed to understand class balance before training.

#Data Cleaning

The following preprocessing steps were applied:

Removed duplicate rows to eliminate redundant data
Replaced infinite values with NaN to handle invalid entries
Dropped rows with missing values to ensure data consistency

These steps ensured that the dataset was clean and suitable for machine learning.

#Feature and Label Separation

The dataset was split into:

Features (X): all columns except the label
Labels (y): the target column (' Label')
Label Encoding

The label values (BENIGN, DDoS) were converted into numerical form using label encoding so that they could be used by machine learning models.

#Train-Test Split

The dataset was split into:

80% training data
20% testing data

This ensures that the model can be evaluated on unseen data.

##Summary

At the end of this phase, the dataset was fully cleaned and transformed into a format suitable for training machine learning models. The data is now ready for model development and evaluation.