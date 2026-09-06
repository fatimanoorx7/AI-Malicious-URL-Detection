# AI-Based Malicious URL Detection

## Project Overview

The Intelligent Agent-Based Malicious URL Detection and Cyber Risk Assessment System is a machine learning-based cybersecurity project designed to analyze URLs and predict whether they are benign, phishing, malware, or defacement.

The system also provides cyber risk assessment and security recommendations to help users make informed decisions before visiting suspicious websites.

## Objectives

- Detect malicious URLs using machine learning algorithms.
- Classify URLs into benign, phishing, malware, and defacement categories.
- Perform cyber risk assessment based on prediction confidence.
- Compare multiple machine learning algorithms.
- Develop a user-friendly Streamlit web application.
- Generate downloadable security reports.

## Dataset

The project uses the Malicious Phish Dataset from Kaggle.

- Total Records: 651,191
- Sample Used: 50,000
- Input: URL
- Target Variable: Type
- Classes: Benign, Phishing, Malware, Defacement

## Feature Engineering

The following numerical features were extracted from URLs:

- URL Length
- Domain Length
- Number of Dots
- Number of Hyphens
- Number of Slashes
- Number of Digits
- HTTPS Presence
- Number of Subdomains
- Special Characters
- IP Address Detection
- Suspicious Words
- Entropy

## Machine Learning Models

Three machine learning models were implemented and compared:

- Logistic Regression
- Decision Tree Classifier
- Random Forest Classifier

### Model Results

| Model | Accuracy |
|---|---:|
| Logistic Regression | 73.72% |
| Decision Tree | 82.10% |
| Random Forest | 87.44% |

Random Forest achieved the highest accuracy of 87.44% and was selected as the final model.

## Streamlit Application

A web-based application was developed using Streamlit.

The application provides:

- URL Input Interface
- Machine Learning Prediction
- Risk Assessment
- Security Recommendations
- Probability Visualization
- Downloadable CSV Report

## Cyber Risk Assessment

The system calculates risk levels based on model confidence.

| Risk Percentage | Risk Level |
|---|---|
| 0–29% | Low |
| 30–59% | Medium |
| 60–79% | High |
| 80–100% | Critical |

## Technologies Used

- Python
- Pandas
- NumPy
- Matplotlib
- Seaborn
- Scikit-learn
- Joblib
- Streamlit

## Project Files

- `app.py` — Streamlit application code for URL analysis, prediction, risk assessment, security recommendations, and report generation.
- `url_detection.py` — Python code for data processing, feature extraction, machine learning model training, comparison, and evaluation.
- `Malicious URL Detection Report.pdf` — Detailed project report containing the methodology, analysis, results, screenshots, limitations, and future work.

## Limitations

The current system primarily relies on handcrafted statistical URL features such as URL length, domain length, entropy, number of dots, and suspicious keywords.

Some legitimate websites may occasionally be misclassified because the model does not fully analyze the semantic meaning of domain names.

## Future Work

Possible future enhancements include:

- TF-IDF based URL text analysis
- Deep Learning Models
- Real-time Threat Intelligence Integration
- Domain Reputation Services
- Browser Extension Integration
- Automated Threat Reporting

## Author

**Fatima Noor**

BS Cyber Security  
HITEC University, Taxila, Pakistan
