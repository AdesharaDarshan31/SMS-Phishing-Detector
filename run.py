from src.data_loader import load_and_split_data
from src.pipeline import build_vectorizer
from src.train import train_model, evaluate_model

if __name__ == "__main__":
    # 1. Load data
    X_train, X_test, y_train, y_test = load_and_split_data("data/spam.tsv")
    
    # 2. Initialize text-to-number translator
    vectorizer = build_vectorizer()
    
    # 3. Train the AI model
    model = train_model(X_train, y_train, vectorizer)
    
    # 4. Run performance tests
    evaluate_model(model, vectorizer, X_test, y_test)