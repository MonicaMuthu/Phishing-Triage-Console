from pathlib import Path

import joblib

MODEL_PATH = Path(__file__).resolve().parent.parent / "ml" / "model.joblib"
_model_cache = None


def get_model():
    global _model_cache
    if _model_cache is not None:
        return _model_cache

    if MODEL_PATH.exists():
        try:
            _model_cache = joblib.load(MODEL_PATH)
            return _model_cache
        except Exception as exc:
            print(f"[!] Warning: Failed to load ML model from {MODEL_PATH}: {exc}")
            return None
    return None


def is_model_available() -> bool:
    return get_model() is not None


def predict_phishing_text(subject: str = "", body: str = "") -> dict:
    model = get_model()
    if model is None:
        return {
            "enabled": False,
            "phishing_probability": 0.0,
            "phishing_percent": 0,
            "prediction": "disabled",
            "note": "ML model not trained. Run python ml/train.py to enable.",
        }

    combined_text = f"{subject} {body}".strip()
    if not combined_text:
        return {
            "enabled": True,
            "phishing_probability": 0.0,
            "phishing_percent": 0,
            "prediction": "ham",
        }

    try:
        # LogisticRegression proba output: [prob_ham, prob_phishing]
        probabilities = model.predict_proba([combined_text])[0]
        phishing_prob = float(probabilities[1])
        percent = int(round(phishing_prob * 100))
        prediction = "phishing" if phishing_prob >= 0.5 else "ham"

        return {
            "enabled": True,
            "phishing_probability": round(phishing_prob, 4),
            "phishing_percent": percent,
            "prediction": prediction,
        }
    except Exception as exc:
        return {
            "enabled": False,
            "phishing_probability": 0.0,
            "phishing_percent": 0,
            "prediction": "error",
            "error": str(exc),
        }
