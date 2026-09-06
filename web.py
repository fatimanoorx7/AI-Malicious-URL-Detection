import streamlit as st
import pandas as pd
import joblib
import math
import re
from urllib.parse import urlparse
SAFE_DOMAINS = [
    "google.com",
    "www.google.com",
    "facebook.com",
    "www.facebook.com",
    "github.com",
    "www.github.com",
    "youtube.com",
    "www.youtube.com",
    "microsoft.com",
    "www.microsoft.com"
]

model = joblib.load(
    "url_detector.pkl"
)
encoder = joblib.load(
    "label_encoder.pkl"
)

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

st.set_page_config(

    page_title=
    "Malicious URL Detection",

    page_icon="🔒",

    layout="wide"

)

st.title(
    "🔒 Intelligent Agent Based Malicious URL Detection System"
)
st.markdown(
    """
    Enter a URL below and the AI model will
    analyze whether it is benign, phishing,
    malware, or defacement.
    """
)

url = st.text_input(
    "Enter URL"
)

if st.button("Analyze URL"):
    if url.strip() == "":
        st.error("Please enter a URL.")
    else:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        features = extract_features(url)
        X = pd.DataFrame([features])
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain in SAFE_DOMAINS:
            label = "benign"
            confidence = 99.0
            prob_df = pd.DataFrame({
                "Class": ["benign"],
                "Probability": [0.99]
            })
        else:
            prediction = model.predict(X)[0]
            label = encoder.inverse_transform(
                [prediction]
            )[0]
            probs = model.predict_proba(X)[0]
            confidence = max(probs) * 100
            prob_df = pd.DataFrame({
                "Class": encoder.classes_,
                "Probability": probs
            })
        if label.lower() == "benign":
            risk = 100 - confidence
        else:
            risk = confidence
        if risk < 30:
            level = "LOW"
        elif risk < 60:
            level = "MEDIUM"
        elif risk < 80:
            level = "HIGH"
        else:
            level = "CRITICAL"
        if label.lower() == "benign":
            recommendation = """
            Safe website detected.
            Continue browsing normally.
            """
        elif label.lower() == "phishing":
            recommendation = """
            Do NOT enter passwords.
            Do NOT enter banking details.
            Leave website immediately.
            """
        elif label.lower() == "malware":
            recommendation = """
            Possible malware distribution site.
            Avoid downloading files.
            Close website immediately.
            """
        else:
            recommendation = """
            Suspicious defacement detected.
            Proceed with caution.
            """
        st.success(
            f"Prediction: {label}"
        )
        st.warning(
            f"Risk Level: {level}"
        )
        st.info(
            f"Confidence: {confidence:.2f}%"
        )
        st.subheader("Recommendation")
        st.write(recommendation)
        st.subheader("Extracted Features")
        st.dataframe(X)
        st.subheader("Prediction Probabilities")
        st.bar_chart(
            prob_df.set_index("Class")
        )
        report = pd.DataFrame({

            "URL": [url],
            "Prediction": [label],
            "Risk Level": [level],
            "Confidence": [confidence]
        })
        st.subheader("Analysis Report")
        st.dataframe(report)
        csv = report.to_csv(
            index=False
        )
        st.download_button(
            "Download Report",
            csv,
            "url_report.csv",
            "text/csv"
        )

st.markdown("---")
st.markdown(
    """
    Intelligent Agent Based Malicious URL Detection and Cyber Risk Assessment System
    """
)