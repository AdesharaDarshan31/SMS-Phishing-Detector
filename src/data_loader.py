import pandas as pd
from sklearn.model_selection import train_test_split

def load_and_split_data(file_path="data/spam.tsv"):
    print("🔄 Loading dataset...")
    
    # Read the TSV file using tab separator (\t)
    df = pd.read_csv(file_path, sep='\t', names=['label', 'message'])
    
    # Convert text labels to numbers: ham = 0, spam = 1
    df['label'] = df['label'].map({'ham': 0, 'spam': 1})
    
    # Split: 80% for training, 20% for testing
    X_train, X_test, y_train, y_test = train_test_split(
        df['message'], 
        df['label'], 
        test_size=0.2, 
        random_state=42
    )
    
    print(f"✅ Data loaded! Training rows: {len(X_train)}, Testing rows: {len(X_test)}")
    return X_train, X_test, y_train, y_test