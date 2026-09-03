import csv
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


def train_model(dataset_path: Path, model_output_path: Path) -> None:
    print(f"[*] Loading dataset from {dataset_path}...")
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    texts = []
    labels = []
    with open(dataset_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if "text" in row and "label" in row:
                texts.append(row["text"] or "")
                labels.append(int(row["label"]))

    if not texts:
        raise ValueError("Dataset CSV contains no valid text/label rows")

    phishing_count = sum(labels)
    ham_count = len(labels) - phishing_count
    print(f"[*] Dataset loaded: {len(texts)} samples ({phishing_count} phishing, {ham_count} ham)")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    max_features=1000,
                    lowercase=True,
                    stop_words="english",
                ),
            ),
            (
                "clf",
                LogisticRegression(C=1.0, random_state=42, max_iter=500),
            ),
        ]
    )

    print("[*] Training TF-IDF + Logistic Regression model...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("[+] Evaluation Results:")
    print(f"    - Test Accuracy: {acc:.4f}")
    print(f"    - Test F1 Score: {f1:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Ham", "Phishing"], zero_division=0))

    # Retrain on full dataset for production artifact
    print("[*] Retraining final model on full dataset...")
    pipeline.fit(texts, labels)

    model_output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_output_path)
    print(f"[+] Model saved successfully to {model_output_path}")


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    dataset_path = project_root / "ml" / "dataset" / "sample_emails.csv"
    model_output_path = project_root / "ml" / "model.joblib"

    train_model(dataset_path, model_output_path)


if __name__ == "__main__":
    main()
