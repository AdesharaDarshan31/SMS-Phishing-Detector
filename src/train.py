import os
import joblib
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report

def train_model(X_train, y_train, vectorizer):
    print("🧠 Transforming text into math vectors...")
    X_train_vectors = vectorizer.fit_transform(X_train)
    
    print("🏋️‍♂️ Training the Naive Bayes AI brain...")
    model = MultinomialNB()
    model.fit(X_train_vectors, y_train)
    
    # MASTER'S UPGRADE: Save the trained model and vectorizer to files!
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/spam_model.pkl")
    joblib.dump(vectorizer, "models/vectorizer.pkl")
    print("💾 Model assets successfully saved to 'models/' directory!")
    
    return model

def evaluate_model(model, vectorizer, X_test, y_test):
    print("\n📊 Evaluating the model on unseen testing data...")
    X_test_vectors = vectorizer.transform(X_test)
    predictions = model.predict(X_test_vectors)
    
    print(f"🎯 Overall Model Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
    print("\n📋 Detailed Performance Report:")
    print(classification_report(y_test, predictions, target_names=['Ham', 'Spam']))