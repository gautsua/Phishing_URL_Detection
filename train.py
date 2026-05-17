import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.calibration import CalibratedClassifierCV
import pickle
import os
import re

# ===================================
# Advanced Feature Extraction Functions
# ===================================
# These functions are used in randomforest.py for enhanced phishing detection
# Documentation: See ENHANCEMENTS_GUIDE.md for detailed descriptions

def get_port_number(url):
    """Analyze port number for phishing indicators
    Returns: 0=Safe (80/443), 1=Suspicious (non-standard), 2=High Risk (phishing ports)
    """
    phishing_ports = {8080, 8081, 8888, 3000, 5000, 9000, 8443, 8000, 3389}
    default_ports = {80, 443}
    
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        port = parsed.port
        
        if port is None:
            return 0  # Default port - Safe
        elif port in phishing_ports:
            return 2  # Known phishing port - High Risk
        elif port not in default_ports:
            return 1  # Non-standard port - Suspicious
        else:
            return 0  # Safe default port
    except:
        return 0

def calculate_entropy(url):
    """Calculate Shannon entropy of URL to detect randomness
    High entropy (0.4-1.0) indicates phishing, low entropy (0.0-0.3) is legitimate
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path_and_query = parsed.path + parsed.query
        
        if not path_and_query:
            return 0.0
        
        # Calculate probability of each character
        entropy = 0
        for char in set(path_and_query):
            p = path_and_query.count(char) / len(path_and_query)
            entropy -= p * np.log2(p) if p > 0 else 0
        
        # Normalize to 0-1 range
        return min(entropy / 5.0, 1.0)
    except:
        return 0.0

def contains_suspicious_keyword(url):
    """Detect suspicious keywords in URL (verify, confirm, login, etc.)
    Returns normalized score 0-1
    """
    suspicious_keywords = [
        'verify', 'confirm', 'account', 'password', 'update', 'secure',
        'click', 'urgent', 'login', 'signin', 'suspend', 'action',
        'authenticate', 'validate', 'confirm identity', 'unusual',
        'activity', 'alert', 'unusual activity', 'suspicious'
    ]
    url_lower = url.lower()
    count = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
    return min(count / 3.0, 1.0)  # Normalize to 0-1

def vowel_consonant_ratio(hostname):
    """Calculate vowel to consonant ratio in hostname
    Legitimate domains: balanced ratio ~0.4
    Phishing domains: unusual ratios indicating homograph attacks
    """
    try:
        if not hostname:
            return 0.5
        
        # Remove numbers and special characters
        letters = ''.join(c.lower() for c in hostname if c.isalpha())
        
        if not letters:
            return 0.5
        
        vowels = sum(1 for c in letters if c in 'aeiou')
        consonants = len(letters) - vowels
        
        if consonants == 0:
            return 1.0
        
        ratio = vowels / len(letters)
        # Legitimate domains typically have 0.3-0.5 ratio
        return abs(ratio - 0.4) / 0.6  # Distance from ideal ratio, normalized
    except:
        return 0.5

def consecutive_digits(url):
    """Count sequences of 4+ consecutive digits
    Phishing URLs often embed hidden numbers or use IP addresses
    """
    try:
        sequences = re.findall(r'\d{4,}', url)
        count = len(sequences)
        return min(count / 2.0, 1.0)  # Normalize to 0-1
    except:
        return 0.0

def domain_reputation_indicators(url):
    """Detect homograph attack patterns (rn→m, l1→I, 0o→O, il)
    Used to mimic legitimate domains with visually similar characters
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else ""
        
        # Common homograph substitutions
        homoglyph_chars = {
            'rn': 0.2,  # rn looks like m
            'l1': 0.2,  # l and 1 look similar
            '0o': 0.2,  # 0 and o look similar
            'il': 0.15, # i and l look similar
        }
        
        score = 0
        hostname_lower = hostname.lower()
        
        for pattern, weight in homoglyph_chars.items():
            if pattern in hostname_lower:
                score += weight
        
        return min(score, 1.0)
    except:
        return 0.0

def special_chars_in_domain(url):
    """Count special characters in domain
    Legitimate domains avoid special chars; phishing sites use them
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else ""
        
        special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?/')
        count = sum(1 for char in hostname if char in special_chars)
        
        return count  # Raw count
    except:
        return 0

def detect_phishing_hosting_platforms(url):
    """Detect phishing URLs hosted on legitimate free services
    Returns: 0=Not hosted on phishing platform, 1=Suspicious platform, 2=High risk platform
    
    Common platforms abused for phishing:
    - Weebly/Wix (website builders)
    - Webflow/Netlify (hosting)
    - GitHub Pages (free hosting)
    - Heroku (app hosting)
    """
    from urllib.parse import urlparse
    
    phishing_platforms = {
        # Free website builders commonly abused for phishing
        'weebly': 2, 'weeblysite': 2,
        'wix': 2, 'wixsite': 2,
        'webflow': 2, 'webflow.io': 2,
        'wordpress': 1, 'wordpress.com': 1,
        'github.io': 2,
        'netlify': 2, 'netlify.app': 2,
        'vercel': 2, 'vercel.app': 2,
        'heroku': 2, 'herokuapp': 2,
        'blogspot': 1, 'blogger': 1,
        'google.sites': 1,
        'carrd': 2,
        'pages.github': 2,
        # Short URL services (common for phishing redirection)
        'bit.ly': 2, 'bitly': 2,
        'tinyurl': 2,
        'shorturl': 2,
        'ow.ly': 2,
        'goo.gl': 1,
        'is.gd': 1,
    }
    
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        
        for platform, risk_level in phishing_platforms.items():
            if platform in hostname:
                return risk_level
        
        return 0  # Not hosted on known phishing platform
    except:
        return 0

def detect_brand_mimicry(url):
    """Detect URLs that mimic popular brands with slight variations
    Examples: bitfinex-x, amazon-verify, paypal-confirm, etc.
    Returns: 0=No mimicry, 1=Suspicious, 2=High probability of brand mimicry
    """
    from urllib.parse import urlparse
    
    known_brands = {
        'amazon', 'apple', 'microsoft', 'google', 'facebook', 'twitter', 'linkedin',
        'paypal', 'ebay', 'netflix', 'instagram', 'whatsapp', 'telegram',
        'bank', 'citibank', 'chase', 'wellsfargo', 'bofa',
        'bitfinex', 'coinbase', 'kraken', 'binance', 'gemini',
        'stripe', 'square', 'adyen',
        'github', 'gitlab', 'bitbucket',
        'dropbox', 'onedrive', 'gdrive',
        'slack', 'discord', 'telegram'
    }
    
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        full_url = url.lower()
        
        # Check if brand appears but with modification/mimicry
        for brand in known_brands:
            # Look for brand followed by dash, underscore, or numbers
            mimicry_patterns = [
                f'{brand}-', f'{brand}_', f'{brand}0', f'{brand}1',
                f'{brand}x', f'{brand}z', f'{brand}s',  # Common suffixes
                f'{brand}-confirm', f'{brand}-verify', f'{brand}-login'
            ]
            
            for pattern in mimicry_patterns:
                if pattern in hostname or pattern in full_url:
                    return 2  # High probability of brand mimicry
        
        return 0
    except:
        return 0

def train_and_save_model():
    """Train the phishing detection model and save it to disk"""

    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, "Phishing_Legitimate_full.csv")
    model_path = os.path.join(script_dir, "phishing_model.pkl")

    if not os.path.exists(csv_path):
        print(f"❌ CSV file not found at: {csv_path}")
        return

    print("Loading dataset...")
    df = pd.read_csv(csv_path)

    # Remove id column if it exists
    if "id" in df.columns:
        df = df.drop("id", axis=1)

    # Separate features and labels
    X = df.drop("CLASS_LABEL", axis=1)
    y = df["CLASS_LABEL"]

    # HTML-specific and HTML-derived columns are excluded from the URL-only model.
    html_only_columns = [
        "EmbeddedBrandName",
        "PctExtHyperlinks",
        "PctExtResourceUrls",
        "ExtFavicon",
        "InsecureForms",
        "RelativeFormAction",
        "ExtFormAction",
        "AbnormalFormAction",
        "PctNullSelfRedirectHyperlinks",
        "FrequentDomainNameMismatch",
        "FakeLinkInStatusBar",
        "RightClickDisabled",
        "PopUpWindow",
        "SubmitInfoToEmail",
        "IframeOrFrame",
        "MissingTitle",
        "ImagesOnlyInForm",
    ]
    html_derived_columns = [
        "PctExtResourceUrlsRT",
        "AbnormalExtFormActionR",
        "ExtMetaScriptLinkRT",
        "PctExtNullSelfRedirectHyperlinksRT",
    ]

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    full_feature_columns = X.columns.tolist()
    url_only_feature_columns = [
        column
        for column in full_feature_columns
        if column not in html_only_columns and column not in html_derived_columns
    ]

    print("Training full Random Forest model...")
    full_base_model = RandomForestClassifier(
        n_estimators=500,        # More trees
        max_depth=20,            # Deeper trees
        min_samples_split=3,     # Allow more specific splits
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1
    )
    full_base_model.fit(X_train, y_train)

    # Calibrate the model for better probability estimates
    print("Calibrating full model for accurate confidence scores...")
    full_model = CalibratedClassifierCV(full_base_model, method='sigmoid', cv=3)
    full_model.fit(X_train, y_train)

    print("Training URL-only Random Forest model...")
    X_url = X[url_only_feature_columns]
    X_url_train, X_url_test, y_url_train, y_url_test = train_test_split(
        X_url, y, test_size=0.2, random_state=42
    )

    url_base_model = RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        min_samples_split=3,
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1
    )
    url_base_model.fit(X_url_train, y_url_train)

    print("Calibrating URL-only model for accurate confidence scores...")
    url_only_model = CalibratedClassifierCV(url_base_model, method='sigmoid', cv=3)
    url_only_model.fit(X_url_train, y_url_train)

    # Evaluate
    full_y_pred = full_model.predict(X_test)
    full_y_pred_proba = full_model.predict_proba(X_test)
    full_accuracy = accuracy_score(y_test, full_y_pred)
    full_precision = precision_score(y_test, full_y_pred)
    full_recall = recall_score(y_test, full_y_pred)
    full_f1 = f1_score(y_test, full_y_pred)

    url_y_pred = url_only_model.predict(X_url_test)
    url_y_pred_proba = url_only_model.predict_proba(X_url_test)
    url_accuracy = accuracy_score(y_url_test, url_y_pred)
    url_precision = precision_score(y_url_test, url_y_pred)
    url_recall = recall_score(y_url_test, url_y_pred)
    url_f1 = f1_score(y_url_test, url_y_pred)

    print("\nFull Model Performance:")
    print(f"Accuracy: {full_accuracy:.2f}")
    print(f"Precision: {full_precision:.2f}")
    print(f"Recall: {full_recall:.2f}")
    print(f"F1-Score: {full_f1:.2f}")

    print("\nURL-Only Model Performance:")
    print(f"Accuracy: {url_accuracy:.2f}")
    print(f"Precision: {url_precision:.2f}")
    print(f"Recall: {url_recall:.2f}")
    print(f"F1-Score: {url_f1:.2f}")

    # Save both models and their feature columns in one pickle file
    model_data = {
        'version': 2,
        'full_model': {
            'model': full_model,
            'feature_columns': full_feature_columns,
            'accuracy': full_accuracy,
            'precision': full_precision,
            'recall': full_recall,
            'f1': full_f1
        },
        'url_only_model': {
            'model': url_only_model,
            'feature_columns': url_only_feature_columns,
            'accuracy': url_accuracy,
            'precision': url_precision,
            'recall': url_recall,
            'f1': url_f1
        }
    }

    print(f"Saving model to {model_path}...")
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)

    print("✅ Model trained and saved successfully!")
    print(f"Model file: {model_path}")

    return model_data

if __name__ == "__main__":
    train_and_save_model()