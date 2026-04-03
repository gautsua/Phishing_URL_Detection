import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.calibration import CalibratedClassifierCV
import pickle
import os

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

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("Training Random Forest model...")
    # Train base model
    base_model = RandomForestClassifier(
        n_estimators=500,        # More trees
        max_depth=20,            # Deeper trees
        min_samples_split=3,     # Allow more specific splits
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1
    )
    base_model.fit(X_train, y_train)

    # Calibrate the model for better probability estimates
    print("Calibrating model for accurate confidence scores...")
    model = CalibratedClassifierCV(base_model, method='sigmoid', cv=3)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\nModel Performance:")
    print(f"Accuracy: {accuracy:.2f}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    print(f"F1-Score: {f1:.2f}")

    # Save model and feature columns
    model_data = {
        'model': model,
        'feature_columns': X.columns.tolist(),
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1
    }

    print(f"Saving model to {model_path}...")
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)

    print("✅ Model trained and saved successfully!")
    print(f"Model file: {model_path}")

    return model_data

if __name__ == "__main__":
    train_and_save_model()