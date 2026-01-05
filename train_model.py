import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.linear_model import SGDClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
import joblib

# Load dataset
df = pd.read_csv("email_dataset.csv")

# Combine all fields into full text
df["text"] = df["from"] + " " + df["subject"] + " " + df["body"]
df = df[["text", "label"]]  # only keep required columns

# Split data
X_train, X_test, y_train, y_test = train_test_split(df["text"], df["label"], test_size=0.2, random_state=42)

# Create and train pipeline
model = make_pipeline(
    TfidfVectorizer(max_features=5000, ngram_range=(1, 2)),
    SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, max_iter=1000, class_weight="balanced")
)

model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("📊 Evaluation Report:")
print(classification_report(y_test, y_pred))

# Save
joblib.dump(model, "email_classifier.pkl")
print("✅ New model trained and saved as email_classifier.pkl")
