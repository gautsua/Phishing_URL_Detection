import pandas as pd
import numpy as np
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.calibration import CalibratedClassifierCV
import pickle
import streamlit as st
import os
import time
from urllib.robotparser import RobotFileParser

# ===================================
# Streamlit Configuration

st.set_page_config(
    page_title="Phishing URL Detection",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom CSS for better UI with smooth animations and transitions
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap');
    
    * {
        font-family: 'Poppins', sans-serif;
    }
    
    .main-title {
        text-align: center;
        background: linear-gradient(135deg, #d32f2f 0%, #f44336 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 2.8em;
        margin-bottom: 10px;
        font-weight: 700;
        animation: slideInDown 0.8s ease-out;
    }
    
    .subtitle {
        text-align: center;
        color: #757575;
        font-size: 1.1em;
        margin-bottom: 20px;
        font-weight: 300;
        animation: fadeIn 1s ease-out 0.3s both;
    }
    
    .result-phishing {
        background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
        padding: 20px;
        border-radius: 12px;
        border-left: 5px solid #d32f2f;
        color: #c62828;
        font-weight: 600;
        animation: slideInLeft 0.6s ease-out;
        box-shadow: 0 4px 12px rgba(211, 47, 47, 0.15);
    }
    
    .result-legitimate {
        background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
        padding: 20px;
        border-radius: 12px;
        border-left: 5px solid #00c853;
        color: #1b5e20;
        font-weight: 600;
        animation: slideInLeft 0.6s ease-out;
        box-shadow: 0 4px 12px rgba(0, 200, 83, 0.15);
    }
    
    .loading-spinner {
        display: inline-block;
        animation: spin 2s linear infinite;
    }
    
    @keyframes slideInDown {
        from {
            opacity: 0;
            transform: translateY(-30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    @keyframes slideInLeft {
        from {
            opacity: 0;
            transform: translateX(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
        }
        to {
            opacity: 1;
        }
    }
    
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    
    .feature-card {
        background: linear-gradient(135deg, #f5f5f5 0%, #fafafa 100%);
        padding: 15px;
        border-radius: 10px;
        margin: 8px 0;
        border-left: 4px solid #2196F3;
        animation: slideInLeft 0.5s ease-out;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
        padding: 15px;
        border-radius: 10px;
        text-align: center;
        animation: fadeIn 0.8s ease-out;
    }
    
    .confidence-meter {
        background: linear-gradient(90deg, #4CAF50, #FFC107, #FF5722);
        height: 8px;
        border-radius: 4px;
        animation: slideInLeft 0.6s ease-out;
    }
    
    </style>
""", unsafe_allow_html=True)

# ===================================
# 1. Load Pre-trained Model with Animation
# ===================================
@st.cache_resource
def load_model():
    """Load pre-trained model from disk"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "phishing_model.pkl")

    if not os.path.exists(model_path):
        st.error(f"❌ Model file not found at: {model_path}")
        st.error("Please run 'python train.py' first to train the model.")
        st.stop()

    try:
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)

        return model_data['model'], model_data['feature_columns'], model_data['accuracy']
    except Exception as e:
        st.error(f"❌ Error loading model: {e}")
        st.stop()

# ===================================
# 2. Expand Short URLs (with timeout handling)
# ===================================
def expand_url(url):
    """Expand shortened URLs"""
    try:
        response = requests.get(url, timeout=5, allow_redirects=True, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return response.url
    except:
        return url

# ===================================
# 2.5. Extract HTML Features from Webpage
# ===================================
def extract_html_features(url):
    """Extract phishing indicators from HTML content"""
    html_features = {}
    
    # Sensitive keywords commonly in phishing pages
    sensitive_keywords = [
        'login', 'password', 'verify', 'confirm', 'account', 'update',
        'secure', 'authenticate', 'billing', 'payment', 'credit', 'bank',
        'reset', 'confirm identity', 'validate', 'urgent', 'action required',
        'click here', 'suspicious activity', 'unusual', 'alert', 'suspended'
    ]
    
    phishing_brands = ['amazon', 'apple', 'microsoft', 'google', 'facebook', 
                       'paypal', 'ebay', 'netflix', 'instagram', 'twitter',
                       'linkedin', 'bank of america', 'wells fargo', 'chase']
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        response.encoding = response.apparent_encoding
        html_content = response.text
        
        if response.status_code != 200 or not html_content:
            return None
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract domain for comparison
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace('www.', '')
        
        # 1. Count forms and their properties
        forms = soup.find_all('form')
        html_features['InsecureForms'] = 0
        html_features['RelativeFormAction'] = 0
        html_features['ExtFormAction'] = 0
        html_features['AbnormalFormAction'] = 0
        html_features['SubmitInfoToEmail'] = 0
        
        for form in forms:
            action = form.get('action', '').lower()
            method = form.get('method', '').lower()
            
            # Check for insecure forms (GET instead of POST for sensitive data)
            if method == 'get' and form.find(['input[name*="pass"]', 'input[name*="credit"]']):
                html_features['InsecureForms'] += 1
            
            # Check form action type
            if not action or action.startswith('#'):
                html_features['RelativeFormAction'] += 1
            elif action.startswith('http'):
                if domain not in action:
                    html_features['ExtFormAction'] += 1
                    # Check if external domain different from current
                    if not any(domain_part in action for domain_part in domain.split('.')):
                        html_features['AbnormalFormAction'] += 1
            
            # Check for email submission
            if 'mailto:' in action:
                html_features['SubmitInfoToEmail'] += 1
        
        # 2. Count embedded brand names
        html_text = soup.get_text().lower()
        html_features['EmbeddedBrandName'] = sum(1 for brand in phishing_brands 
                                                  if brand in html_text)
        
        # 3. Count sensitive keywords
        html_features['NumSensitiveWords'] = sum(1 for keyword in sensitive_keywords 
                                                 if keyword.lower() in html_text)
        
        # 4. Check for iframe or frame elements
        html_features['IframeOrFrame'] = 1 if soup.find_all(['iframe', 'frame']) else 0
        
        # 5. Check for missing title
        html_features['MissingTitle'] = 0 if soup.find('title') else 1
        
        # 6. Check for images only in form (no text forms)
        all_inputs = soup.find_all('input')
        image_inputs = [i for i in all_inputs if i.get('type') == 'image']
        html_features['ImagesOnlyInForm'] = 1 if image_inputs and not forms else 0
        
        # 7. Count external hyperlinks
        all_links = soup.find_all('a', href=True)
        external_links = 0
        null_redirect_links = 0
        
        for link in all_links:
            href = link.get('href', '').lower()
            if href.startswith('http') and domain not in href:
                external_links += 1
            elif href.startswith('#') or href == '' or href == 'javascript:void(0)':
                null_redirect_links += 1
        
        total_links = len(all_links) if all_links else 1
        html_features['PctExtHyperlinks'] = min(1.0, external_links / total_links)
        html_features['PctNullSelfRedirectHyperlinks'] = min(1.0, null_redirect_links / total_links)
        
        # 8. Check for external resources (images, scripts, stylesheets, objects)
        scripts = soup.find_all('script', src=True)
        images = soup.find_all('img', src=True)
        stylesheets = soup.find_all('link', rel='stylesheet', href=True)
        objects = soup.find_all(['object', 'embed'])
        
        external_resources = 0
        total_resources = 0
        
        for script in scripts:
            src = script.get('src', '').lower()
            total_resources += 1
            if src.startswith('http') and domain not in src:
                external_resources += 1
        
        for img in images:
            src = img.get('src', '').lower()
            if src.startswith('http'):
                total_resources += 1
                if domain not in src:
                    external_resources += 1
        
        for stylesheet in stylesheets:
            href = stylesheet.get('href', '').lower()
            if href.startswith('http'):
                total_resources += 1
                if domain not in href:
                    external_resources += 1
        
        for obj in objects:
            src = obj.get('src') or obj.get('data') or ''
            if src and src.startswith('http'):
                total_resources += 1
                if domain not in src:
                    external_resources += 1
        
        total_resources = total_resources if total_resources > 0 else 1
        html_features['PctExtResourceUrls'] = min(1.0, external_resources / total_resources)
        
        # 9. Check for favicon
        favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        html_features['ExtFavicon'] = 1 if favicon else 0
        
        # 10. Check for right-click disabled and popup windows
        page_source = html_content.lower()
        html_features['RightClickDisabled'] = 1 if 'oncontextmenu' in page_source else 0
        html_features['PopUpWindow'] = 1 if 'window.open' in page_source else 0
        html_features['FakeLinkInStatusBar'] = 1 if 'onmouseover' in page_source else 0
        
        return html_features
        
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException:
        return None
    except Exception as e:
        return None

# ===================================
# 2.7. Advanced Feature Extraction Functions
# ===================================

def get_port_number(url):
    """Analyze port number for phishing indicators"""
    phishing_ports = {8080, 8081, 8888, 3000, 5000, 9000, 8443, 8000, 3389}
    default_ports = {80, 443}
    
    try:
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
    """Calculate Shannon entropy of URL to detect randomness"""
    try:
        # Remove protocol and domain for more accurate analysis
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
    """Detect suspicious keywords in URL"""
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
    """Calculate vowel to consonant ratio in hostname"""
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
        # Phishing often deviates from this
        return abs(ratio - 0.4) / 0.6  # Distance from ideal ratio, normalized
    except:
        return 0.5

def consecutive_digits(url):
    """Count sequences of 4+ consecutive digits"""
    try:
        sequences = re.findall(r'\d{4,}', url)
        count = len(sequences)
        return min(count / 2.0, 1.0)  # Normalize to 0-1
    except:
        return 0.0

def domain_reputation_indicators(url):
    """Detect homograph attack patterns"""
    try:
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
    """Count special characters in domain"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else ""
        
        special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?/')
        count = sum(1 for char in hostname if char in special_chars)
        
        return count  # Raw count, will be normalized later if needed
    except:
        return 0

# ===================================
# 3. Feature Extraction from URL
# ===================================
def extract_features(url, feature_columns):
    """Extract features from URL and HTML for model prediction"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else ""
        path = parsed.path if parsed.path else ""
        query = parsed.query if parsed.query else ""
        
        features = {}
        
        # ===== URL FEATURES =====
        # Basic URL characteristics
        features['NumDots'] = url.count('.')
        features['SubdomainLevel'] = max(0, hostname.count('.') - 1) if hostname else 0
        features['PathLevel'] = path.count('/')
        features['UrlLength'] = len(url)
        features['NumDash'] = url.count('-')
        features['NumDashInHostname'] = hostname.count('-') if hostname else 0
        features['AtSymbol'] = 1 if '@' in url else 0
        features['TildeSymbol'] = 1 if '~' in url else 0
        features['NumUnderscore'] = url.count('_')
        features['NumPercent'] = url.count('%')
        features['NumQueryComponents'] = query.count('&') if query else 0
        features['NumAmpersand'] = url.count('&')
        features['NumHash'] = url.count('#')
        features['NumNumericChars'] = sum(c.isdigit() for c in url)
        features['NoHttps'] = 0 if parsed.scheme == "https" else 1
        features['HostnameLength'] = len(hostname)
        features['PathLength'] = len(path)
        features['QueryLength'] = len(query)
        features['DoubleSlashInPath'] = 1 if '//' in path else 0
        features['RandomString'] = 1 if re.search(r'[a-z0-9]{10,}', url, re.IGNORECASE) else 0
        
        # Check if hostname is IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        features['IpAddress'] = 1 if re.match(ip_pattern, hostname) else 0
        
        # ===== NEW URL FEATURES =====
        # Domain in subdomains (phishing tactic: www.amazon.attacersite.com)
        if hostname:
            subdomains = hostname.split('.')
            domain_name = subdomains[-2] if len(subdomains) >= 2 else subdomains[-1]
            features['DomainInSubdomains'] = 1 if domain_name in '.'.join(subdomains[:-1]) else 0
        else:
            features['DomainInSubdomains'] = 0
        
        # Domain in path (phishing tactic: attacker.com/amazon)
        features['DomainInPaths'] = 1 if hostname and hostname.split('.')[0] in path.lower() else 0
        
        # HTTPS text in hostname (phishing tactic: https-verify-account.com)
        features['HttpsInHostname'] = 1 if 'https' in hostname.lower() else 0
        
        # Count sensitive phishing keywords in URL
        sensitive_keywords = ['login', 'verify', 'confirm', 'account', 'update', 
                              'password', 'secure', 'authenticate', 'billing', 'payment']
        url_lower = url.lower()
        features['NumSensitiveWords'] = sum(1 for keyword in sensitive_keywords if keyword in url_lower)
        
        # ===== ADVANCED URL FEATURES (from enhancements guide) =====
        # Port number analysis
        features['PortAnalysis'] = get_port_number(url)
        
        # Shannon entropy of URL (measures randomness)
        features['URLEntropy'] = calculate_entropy(url)
        
        # Suspicious keywords score
        features['SuspiciousKeywordScore'] = contains_suspicious_keyword(url)
        
        # Vowel to consonant ratio (homograph detection)
        features['VowelConsonantRatio'] = vowel_consonant_ratio(hostname)
        
        # Consecutive digits sequences
        features['ConsecutiveDigits'] = consecutive_digits(url)
        
        # Homograph attack indicators
        features['HomographScore'] = domain_reputation_indicators(url)
        
        # Special characters in domain
        features['SpecialCharsInDomain'] = special_chars_in_domain(url)
        
        # ===== HTML FEATURES =====
        # Try to extract HTML features from the actual webpage
        html_features = extract_html_features(url)
        html_analysis_possible = html_features is not None
        
        if html_features:
            features.update(html_features)
        else:
            # Set default values for HTML features if page couldn't be fetched
            html_default_features = {
                'DomainInPaths': features.get('DomainInPaths', 0),  # Use URL-based value
                'HttpsInHostname': features.get('HttpsInHostname', 0),  # Use URL-based value
                'NumSensitiveWords': features.get('NumSensitiveWords', 0),  # Use URL-based value
                'EmbeddedBrandName': 0,
                'PctExtHyperlinks': 0.0,
                'PctExtResourceUrls': 0.0,
                'ExtFavicon': 1,  # Assume legitimate if can't check
                'InsecureForms': 0,
                'RelativeFormAction': 0,
                'ExtFormAction': 0,
                'AbnormalFormAction': 0,
                'PctNullSelfRedirectHyperlinks': 0.0,
                'FrequentDomainNameMismatch': 0,
                'FakeLinkInStatusBar': 0,
                'RightClickDisabled': 0,
                'PopUpWindow': 0,
                'SubmitInfoToEmail': 0,
                'IframeOrFrame': 0,
                'MissingTitle': 0,
                'ImagesOnlyInForm': 0,
            }
            features.update(html_default_features)
        
        # ===== RATIO TEST FEATURES (RT) =====
        # These are derived features from other features
        features['SubdomainLevelRT'] = features.get('SubdomainLevel', 0)  # Ratio test variant
        features['UrlLengthRT'] = min(1.0, features.get('UrlLength', 0) / 75.0)  # Normalized
        features['PctExtResourceUrlsRT'] = features.get('PctExtResourceUrls', 0.0)
        features['AbnormalExtFormActionR'] = features.get('AbnormalFormAction', 0)
        features['ExtMetaScriptLinkRT'] = 1 if re.search(r'<meta|<script', str(html_features or '')) else 0
        features['PctExtNullSelfRedirectHyperlinksRT'] = features.get('PctNullSelfRedirectHyperlinks', 0.0)
        
        # DomainInSubdomains affects this ratio test
        if features.get('DomainInSubdomains', 0):
            features['FrequentDomainNameMismatch'] = 1
        else:
            features['FrequentDomainNameMismatch'] = 0
        
        # Fill any remaining missing features with default values
        for col in feature_columns:
            if col not in features:
                features[col] = 0
        
        # Create DataFrame with proper column order
        feature_df = pd.DataFrame([features], columns=list(feature_columns))
        
        # Store whether HTML analysis was successful (for UI display)
        feature_df.attrs['html_analysis_success'] = html_analysis_possible
        
        return feature_df
    
    except Exception as e:
        st.error(f"Error extracting features: {e}")
        return None


# ===================================
# 4. Streamlit UI with Smooth Animations
# ===================================

# Title with animation
st.markdown('<div class="main-title">🔒 Phishing URL Detection</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Advanced Machine Learning-Based Detection System</div>', unsafe_allow_html=True)

# Load model with smooth transition
with st.spinner("⏳ Loading AI Model..."):
    time.sleep(0.5)  # Slight delay for smooth animation effect
    model, feature_columns, accuracy = load_model()

# Display model info with animated metric cards
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric("🎯 Model Accuracy", f"{accuracy*100:.2f}%")
    st.markdown('</div>', unsafe_allow_html=True)
    
with col2:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric("⚙️ Model Type", "Random Forest")
    st.markdown('</div>', unsafe_allow_html=True)
    
with col3:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric("📊 Features", len(feature_columns))
    st.markdown('</div>', unsafe_allow_html=True)

st.divider()

# URL Input Section
st.subheader("📍 Enter URL to Check")

# URL input form
with st.form(key="url_form", clear_on_submit=True):
    url_input = st.text_input(
        "URL:",
        placeholder="e.g., https://example.com:8080/verify-account",
        label_visibility="collapsed"
    )
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        search_button = st.form_submit_button("🔍 Check URL", use_container_width=True)
    with col2:
        clear_button = st.form_submit_button("🗑️ Clear", use_container_width=True)
    with col3:
        st.empty()

# Process URL with smooth animations
if search_button and url_input:
    # Create progress container for smooth animations
    progress_placeholder = st.empty()
    analysis_placeholder = st.empty()
    
    with progress_placeholder.container():
        # Progress bar animation
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Step 1: URL expansion
        status_text.text("⏳ Step 1/4: Expanding URL...")
        for i in range(25):
            progress_bar.progress(i / 100)
            time.sleep(0.01)
        
        expanded_url = expand_url(url_input)
        if expanded_url != url_input:
            st.success(f"✅ Expanded URL: {expanded_url}")
        
        # Step 2: Feature extraction
        status_text.text("⏳ Step 2/4: Extracting Features...")
        for i in range(25, 50):
            progress_bar.progress(i / 100)
            time.sleep(0.01)
        
        url_features = extract_features(expanded_url, feature_columns)
        
        # Step 3: Model prediction
        status_text.text("⏳ Step 3/4: Running AI Analysis...")
        for i in range(50, 75):
            progress_bar.progress(i / 100)
            time.sleep(0.01)
        
        if url_features is not None:
            prediction = model.predict(url_features)[0]
            confidence = model.predict_proba(url_features).max() * 100
            prediction_proba = model.predict_proba(url_features)[0]
            html_success = url_features.attrs.get('html_analysis_success', False)
            
            # Step 4: Generating results
            status_text.text("⏳ Step 4/4: Generating Results...")
            for i in range(75, 100):
                progress_bar.progress(i / 100)
                time.sleep(0.01)
            
            progress_bar.progress(100)
            time.sleep(0.3)
    
    # Clear progress bar and show results with animation
    progress_placeholder.empty()
    
    st.divider()
    st.subheader("📊 Analysis Result")
    
    # Show whether HTML analysis was successful
    if not html_success:
        st.info("🔗 HTML page analysis not available. Using URL-based detection only.")
    else:
        st.success("✅ HTML page analysis completed successfully.")
    
    # Display result with color-coded box and animation
    if prediction == 1:
        st.markdown(
            f'<div class="result-phishing">⚠️ PHISHING URL DETECTED<br><br>Confidence Level: {confidence:.2f}%</div>',
            unsafe_allow_html=True
        )
        st.markdown("---")
        st.warning("This URL shows characteristics commonly associated with phishing attacks. Exercise caution!", icon="⚠️")
    else:
        st.markdown(
            f'<div class="result-legitimate">✅ LEGITIMATE URL<br><br>Confidence Level: {confidence:.2f}%</div>',
            unsafe_allow_html=True
        )
        st.markdown("---")
        st.success("This URL appears to be safe based on analysis.")
    
    # Confidence visualization
    st.subheader("📈 Confidence Meter")
    col1, col2 = st.columns([3, 1])
    with col1:
        st.progress(confidence / 100)
    with col2:
        st.metric("Score", f"{confidence:.1f}%")
    
    # Display probability breakdown
    col1, col2 = st.columns(2)
    with col1:
        st.metric("🟢 Legitimate", f"{prediction_proba[0]:.1%}")
    with col2:
        st.metric("🔴 Phishing", f"{prediction_proba[1]:.1%}")
    
    # Detailed URL Features
    with st.expander("📊 Detailed URL Analysis", expanded=False):
        st.info(f"**Full URL:** {expanded_url}")
        
        parsed = urlparse(expanded_url)
        
        # Create organized feature display with sections
        st.subheader("🔗 URL Components")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f'<div class="feature-card"><b>Protocol:</b> {parsed.scheme.upper()}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="feature-card"><b>Domain:</b> {parsed.netloc}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="feature-card"><b>Path:</b> {parsed.path if parsed.path else "/"}</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown(f'<div class="feature-card"><b>Query:</b> {parsed.query if parsed.query else "None"}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="feature-card"><b>Fragment:</b> {parsed.fragment if parsed.fragment else "None"}</div>', unsafe_allow_html=True)
            port = parsed.port or "Default"
            st.markdown(f'<div class="feature-card"><b>Port:</b> {port}</div>', unsafe_allow_html=True)
        
        # Security Features
        st.subheader("🔐 Security Indicators")
        sec_col1, sec_col2 = st.columns(2)
        
        with sec_col1:
            https_status = "✅ Yes" if parsed.scheme == "https" else "❌ No"
            st.markdown(f'<div class="feature-card"><b>HTTPS:</b> {https_status}</div>', unsafe_allow_html=True)
        
        with sec_col2:
            ip_status = "⚠️ Yes" if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else "✅ No"
            st.markdown(f'<div class="feature-card"><b>IP Address:</b> {ip_status}</div>', unsafe_allow_html=True)
        
        # URL Characteristics
        st.subheader("📏 URL Characteristics")
        char_col1, char_col2 = st.columns(2)
        
        with char_col1:
            st.markdown(f'<div class="feature-card"><b>Length:</b> {len(expanded_url)} chars</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="feature-card"><b>Dots:</b> {expanded_url.count(".")}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="feature-card"><b>Dashes:</b> {expanded_url.count("-")}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="feature-card"><b>Underscores:</b> {expanded_url.count("_")}</div>', unsafe_allow_html=True)
        
        with char_col2:
            st.markdown(f'<div class="feature-card"><b>Percent Signs:</b> {expanded_url.count("%")}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="feature-card"><b>Numeric Chars:</b> {sum(c.isdigit() for c in expanded_url)}</div>', unsafe_allow_html=True)
            doublesl = "⚠️ Yes" if '//' in parsed.path else "✅ No"
            st.markdown(f'<div class="feature-card"><b>Double Slash in Path:</b> {doublesl}</div>', unsafe_allow_html=True)
            num_query = parsed.query.count('&') if parsed.query else 0
            st.markdown(f'<div class="feature-card"><b>Query Parameters:</b> {num_query}</div>', unsafe_allow_html=True)
        
        # Phishing Pattern Detection
        st.subheader("⚠️ Phishing Pattern Detection")
        phishing_col1, phishing_col2 = st.columns(2)
        
        hostname = parsed.hostname if parsed.hostname else ""
        
        with phishing_col1:
            # Domain in subdomains
            if hostname:
                subdomains = hostname.split('.')
                domain_name = subdomains[-2] if len(subdomains) >= 2 else subdomains[-1]
                domain_in_subdomain = domain_name in '.'.join(subdomains[:-1])
            else:
                domain_in_subdomain = False
            status = "⚠️ Yes" if domain_in_subdomain else "✅ No"
            st.markdown(f'<div class="feature-card"><b>Domain in Subdomain:</b> {status}</div>', unsafe_allow_html=True)
            
            # HTTPS in hostname
            https_in_hostname = "⚠️ Yes" if 'https' in hostname.lower() else "✅ No"
            st.markdown(f'<div class="feature-card"><b>HTTPS in Hostname:</b> {https_in_hostname}</div>', unsafe_allow_html=True)
        
        with phishing_col2:
            # Sensitive keywords in URL
            url_lower = expanded_url.lower()
            sensitive_keywords = ['login', 'verify', 'confirm', 'account', 'password']
            keyword_count = sum(1 for keyword in sensitive_keywords if keyword in url_lower)
            st.markdown(f'<div class="feature-card"><b>Sensitive Keywords:</b> {keyword_count}</div>', unsafe_allow_html=True)
            
            # Random string detection
            has_random = "⚠️ Yes" if re.search(r'[a-z0-9]{10,}', expanded_url, re.IGNORECASE) else "✅ No"
            st.markdown(f'<div class="feature-card"><b>Random String:</b> {has_random}</div>', unsafe_allow_html=True)
        
        # HTML Analysis Results (if available)
        if html_success:
            st.subheader("🌐 HTML Content Analysis")
            html_col1, html_col2 = st.columns(2)
            
            # Get HTML features from the extraction
            try:
                html_feats = extract_html_features(expanded_url)
                if html_feats:
                    with html_col1:
                        st.markdown(f'<div class="feature-card"><b>Forms Detected:</b> {html_feats.get("InsecureForms", 0)}</div>', unsafe_allow_html=True)
                        st.markdown(f'<div class="feature-card"><b>Embed Brand Names:</b> {html_feats.get("EmbeddedBrandName", 0)}</div>', unsafe_allow_html=True)
                        st.markdown(f'<div class="feature-card"><b>Iframes/Frames:</b> {'⚠️ Yes' if html_feats.get("IframeOrFrame", 0) else '✅ No'}</div>', unsafe_allow_html=True)
                        st.markdown(f'<div class="feature-card"><b>External Forms:</b> {html_feats.get("ExtFormAction", 0)}</div>', unsafe_allow_html=True)
                    
                    with html_col2:
                        st.markdown(f'<div class="feature-card"><b>External Hyperlinks:</b> {html_feats.get("PctExtHyperlinks", 0.0):.1%}</div>', unsafe_allow_html=True)
                        st.markdown(f'<div class="feature-card"><b>External Resources:</b> {html_feats.get("PctExtResourceUrls", 0.0):.1%}</div>', unsafe_allow_html=True)
                        st.markdown(f'<div class="feature-card"><b>Right-Click Disabled:</b> {'⚠️ Yes' if html_feats.get("RightClickDisabled", 0) else '✅ No'}</div>', unsafe_allow_html=True)
                        st.markdown(f'<div class="feature-card"><b>Popup Windows:</b> {'⚠️ Yes' if html_feats.get("PopUpWindow", 0) else '✅ No'}</div>', unsafe_allow_html=True)
            except:
                pass

elif clear_button:
    st.success("Form cleared! Enter a new URL to check.")

elif url_input and not search_button:
    st.info("👉 Click 'Check URL' button to analyze the URL")

st.divider()

# Footer with professional styling
st.markdown("""
    <div style="text-align: center; color: #999; font-size: 0.85em; margin-top: 20px; animation: fadeIn 1s ease-out;">
    <br>
    ⚠️ <b>Disclaimer:</b> This tool provides predictions based on URL structural analysis and machine learning patterns. 
    Always exercise caution and verify suspicious URLs through additional security means.
    <br><br>
    <b>Supported Features:</b> HTTPS Analysis • Port Detection • IP Address Recognition • Domain Reputation • Entropy Analysis • Keyword Detection
    </div>
""", unsafe_allow_html=True)