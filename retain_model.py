import pandas as pd
import joblib
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import mysql.connector

# 🧽 Text cleaning function
def clean_text(text):
    text = text.lower()
    text = re.sub(r'[^\w\s]', '', text)  # Remove punctuation
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# ✅ DB connection — update based on your MySQL setup
conn = mysql.connector.connect(
    host='localhost',
    user='rooteco',
    password='Eco123@#',
    database='ecoclean_db'
)

# Step 1: Fetch user-labeled feedback from DB
df = pd.read_sql("SELECT text, updated_category FROM email_feedback", conn)
conn.close()

# Optional: Filter out blank texts
df = df[df['text'].str.strip().astype(bool)]

# 🧠 Clean the feedback text before vectorizing
df['text'] = df['text'].apply(clean_text)

if df.empty:
    print("No feedback data available to retrain.")
    exit()

# Step 2: Text Vectorization
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df['text'])
y = df['updated_category']

# Step 3: Train the classifier
model = MultinomialNB()
model.fit(X, y)

# Step 4: Save model and vectorizer
joblib.dump(model, 'email_classifier.pkl')
joblib.dump(vectorizer, 'email_vectorizer.pkl')

print("Model retrained and saved as email_classifier.pkl")
