import pandas as pd
import numpy as np
import re
import math
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

df = pd.read_csv(
    "malicious_phish.csv"
)
print("Original Shape")
print(df.shape)
df = df.sample(
    n=50000,
    random_state=42
)

df.reset_index(
    drop=True,
    inplace=True
)
print("\nSample Shape")
print(df.shape)

print("\nFirst Five Rows")
print(df.head())
print("\nDataset Info")
print(df.info())
print("\nMissing Values")
print(df.isnull().sum())
print("\nDuplicates")
print(df.duplicated().sum())

plt.figure(figsize=(8,5))
sns.countplot(
    x="type",
    data=df
)
plt.title(
    "Class Distribution"
)
plt.savefig(
    "class_distribution.png"
)
plt.show()

def entropy(string):
    if len(string) == 0:
        return 0
    prob = [
        float(string.count(c))
        / len(string)

        for c in dict.fromkeys(
            list(string)
        )
    ]
    return -sum(
        p * math.log2(p)
        for p in prob
    )

def extract_features(url):
    url = str(url)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    features = {}
    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_slashes"] = url.count("/")
    features["num_digits"] = sum(
        c.isdigit()
        for c in url
    )
    features["https"] = (
        1 if parsed.scheme == "https"
        else 0
    )
    features["num_subdomains"] = max(
        domain.count(".") - 1,
        0
    )
    features["special_chars"] = len(
        re.findall(
            r'[@#$%^&*_=+~]',
            url
        )
    )
    features["has_ip"] = (
        1
        if re.search(
            r'(\d{1,3}\.){3}\d{1,3}',
            url
        )
        else 0
    )
    suspicious_words = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "bank",
        "paypal",
        "signin",
        "confirm",
        "password"
    ]
    features["suspicious_words"] = sum(
        word in url.lower()
        for word in suspicious_words
    )
    features["entropy"] = entropy(url)
    return features

feature_rows = []
for url in df["url"]:
    feature_rows.append(
        extract_features(
            str(url)
        )
    )

X = pd.DataFrame(
    feature_rows
)
print("\nFeature Dataset")
print(X.head())
print("\nFeature Shape")
print(X.shape)

encoder = LabelEncoder()
y = encoder.fit_transform(
    df["type"]
)
print(df["type"].value_counts())
print("\nClasses")
print(
    encoder.classes_
)

plt.figure(
    figsize=(10,8)
)
sns.heatmap(
    X.corr(),
    annot=True,
    cmap="coolwarm"
)
plt.title(
    "Feature Correlation"
)
plt.savefig(
    "heatmap.png"
)
plt.show()

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)
print("\nTrain Shape")
print(X_train.shape)
print("\nTest Shape")
print(X_test.shape)

lr = LogisticRegression(
    max_iter=5000
)
lr.fit(
    X_train,
    y_train
)
pred_lr = lr.predict(
    X_test
)
acc_lr = accuracy_score(
    y_test,
    pred_lr
)
print("\nLOGISTIC REGRESSION")
print(
    f"Accuracy: {acc_lr:.4f}"
)

dt = DecisionTreeClassifier(
    random_state=42
)
dt.fit(
    X_train,
    y_train
)
pred_dt = dt.predict(
    X_test
)
acc_dt = accuracy_score(
    y_test,
    pred_dt
)
print("\nDECISION TREE")
print(
    f"Accuracy: {acc_dt:.4f}"
)

rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)
rf.fit(
    X_train,
    y_train
)
pred_rf = rf.predict(
    X_test
)
acc_rf = accuracy_score(
    y_test,
    pred_rf
)
print("\nRANDOM FOREST")
print(
    f"Accuracy: {acc_rf:.4f}"
)

comparison = pd.DataFrame({
    "Model":[
        "Logistic Regression",
        "Decision Tree",
        "Random Forest"
    ],
    "Accuracy":[
        acc_lr,
        acc_dt,
        acc_rf
    ]
})
print("\nModel Comparison")
print(comparison)
comparison.to_csv(
    "model_comparison.csv",
    index=False
)

print(
    "\nClassification Report"
)
print(
    classification_report(
        y_test,
        pred_rf,
        target_names=
        encoder.classes_
    )
)

cm = confusion_matrix(
    y_test,
    pred_rf
)
plt.figure(
    figsize=(8,6)
)
sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues"
)
plt.title(
    "Confusion Matrix"
)
plt.xlabel(
    "Predicted"
)
plt.ylabel(
    "Actual"
)
plt.savefig(
    "confusion_matrix.png"
)
plt.show()

importance = pd.DataFrame({
    "Feature":
    X.columns,
    "Importance":
    rf.feature_importances_
})
importance = importance.sort_values(
    by="Importance",
    ascending=False
)
print(
    "\nFeature Importance"
)
print(
    importance
)
plt.figure(
    figsize=(8,5)
)
sns.barplot(
    x="Importance",
    y="Feature",
    data=importance
)
plt.title(
    "Feature Importance"
)
plt.savefig(
    "feature_importance.png"
)
plt.show()

joblib.dump(
    rf,
    "url_detector.pkl"

)
joblib.dump(
    encoder,
    "label_encoder.pkl"
)
print(
    "\nModel Saved Successfully"
)
print(
    "\nFiles Generated:"
)
print(
    "url_detector.pkl"
)
print(
    "label_encoder.pkl"
)
print(
    "class_distribution.png"
)
print(
    "heatmap.png"
)
print(
    "confusion_matrix.png"
)
print(
    "feature_importance.png"
)