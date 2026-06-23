import re
from sklearn.feature_extraction.text import TfidfVectorizer

def clean_text(text):
    text = text.lower()
    
    # MASTER'S UPGRADE: Fix spacing tricks before removing punctuation
    text = re.sub(r'(?<=\b[a-z])[\s._]+(?=[a-z]\b)', '', text)
    
    # Strip punctuation BUT leave common URL characters so we can parse domains
    text = re.sub(r'[^\w\s.-://]', '', text)
    
    return text

def build_vectorizer():
    return TfidfVectorizer(
        preprocessor=clean_text, 
        stop_words='english'
    )