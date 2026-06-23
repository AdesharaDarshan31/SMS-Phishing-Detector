# 🛡️ SMS Threat Assessment Gateway (Hybrid Zero-Trust Architecture)

### 🔍 Deterministic Adversarial Heuristics
* **Character Obfuscation Defusal:** Employs lookahead regular expressions to catch interspersed formatting strings and non-standard spacing (e.g., `V.e.r.i.f.y`) designed to bypass structural tokenization layers.
* **Expanded Brand Spoof Protection:** Maps incoming domain URLs against a verified mapping array covering global infrastructure anchors (AWS, GitHub, PayPal, Google, FedEx, Microsoft, DHL, and French/UK tax/logistic services). Unofficial domains or typosquatting variations trigger an automatic threat level override.
* **Intent Vector Extraction:** Scans raw text payloads against high-risk token pools categorized by tactical vectors: Credential Requests (`login`, `verification`), Urgency Framing (`suspended`, `restricted`), and Financial Triggers (`refund`, `fees`).

### 🧠 Probabilistic Machine Learning Core
* **TF-IDF Vectorization Matrix:** Transforms raw text into weighted token frequencies, discounting common stop words while emphasizing critical semantic indicators.
* **Multinomial Naive Bayes Classification:** Computes underlying statistical match confidence percentages from a historical spam feature corpus.
* **Intelligent Score Harmonization:** Bridges the gap between rule-based and probabilistic outputs. If the AI core generates a high-confidence anomaly mismatch, it automatically scales the global index to apply a persistent warning overlay.

---

## 🛠️ Tech Stack & System Architecture

* **Core Engine Language:** Python 3.11
* **Machine Learning Core:** Scikit-Learn (TF-IDF + Naive Bayes), Joblib for model artifact serialization.
* **Web Server Framework:** FastAPI for asynchronous, non-blocking request routing and high-concurrency capability.
* **Template Engine:** Jinja2 for server-side HTML context rendering and asset integration.
* **UI Interface Layer:** Tailwind CSS engine deployed over a single-page view dashboard, complete with dynamic SVG status meters and responsive layout boundaries.
* **DevOps Infrastructure:** Docker containerization utilizing light, secure Linux base images, continuously integrated and deployed via Render cloud web services.

---

## 🔄 Multi-Tiered Gateway Pipeline Logic

The application coordinates an intersecting defensive stack to analyze text payloads within a single, optimized runtime pass:

1. **Ingress & Normalization:** The payload text is stripped of hidden escaping flags and normalized into downcased tokens.
2. **Heuristic Intersections:** The text runs through parallel structural regex extractors to compute rule-based vulnerability risk scores.
3. **ML Prediction Vector:** Simultaneously, the text is fed into the loaded `.pkl` pipeline where the Naive Bayes engine calculates statistical classification probability.
4. **Aggregation & Tier Mapping:** The composite threat score is normalized on a 1–100 scale, assigning the appropriate tier styling (`bg-red-100`, `bg-orange-100`) and system operational recommendations directly to the UI panel.

---

## 📂 Project Repository Structure

```text
sms-spam-classifier/
├── src/
│   ├── pipeline.py       # Vector cleaning and NLP transformation pipelines
│   ├── data_loader.py    # Dataset parsing arrays
│   └── train.py          # Naive Bayes core execution script
├── templates/
│   └── index.html        # Premium single-viewport frontend dashboard
├── models/
│   ├── spam_model.pkl    # Serialized ML classifier weights
│   └── vectorizer.pkl    # Tokenizer matrix features
├── app.py                # Asynchronous FastAPI Gateway engine
├── predict.py            # Local terminal diagnostic sandbox interface
├── Dockerfile            # Container replication layer configurations
└── requirements.txt      # Production environment package array

🎯 **Live Web Deployment:** - https://sms-phishing-detector.onrender.com
