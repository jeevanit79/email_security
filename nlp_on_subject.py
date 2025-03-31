import subprocess
import sys

# ✅ Ensure transformers is installed
try:
    from transformers import pipeline
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "transformers"])
    from transformers import pipeline

def run_phishing_detection(subject):
    try:
        classifier = pipeline("text-classification", model="mrm8488/bert-mini-finetuned-sms-spam-detection")
        result = classifier(subject)

        return f"📊 NLP Phishing Detection Result: {result[0]['label']} (Confidence: {result[0]['score']:.2f})"

    except Exception as e:
        return f"❌ NLP Phishing Detection Failed: {e}"
