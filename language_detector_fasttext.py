import fasttext
import re
import os

# Load the model once
MODEL_PATH = "email_security/lid.176.ftz"
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("FastText model not found. Download 'lid.176.ftz' first.")
model = fasttext.load_model(MODEL_PATH)

def detect_language_fasttext(text):
    prediction = model.predict(text.strip().replace("\n", " "), k=1)
    lang = prediction[0][0].replace("__label__", "")
    confidence = prediction[1][0]
    return lang, confidence


def detect_language_subject(subject):
    lang, conf = detect_language_fasttext(subject)
    print(f"Subject Language Detected: {lang.upper()} ({conf:.2f})")
    return lang, conf


def detect_languages_body(body):
    sentence_pattern = r'(?<=[.!?])\s+'
    sentences = re.split(sentence_pattern, body)
    
    language_map = {}

    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence or len(sentence) < 3:
            continue
        lang, conf = detect_language_fasttext(sentence)
        if lang != "en":
            if lang not in language_map:
                language_map[lang] = []
            language_map[lang].append((sentence, conf))

    if language_map:
        print("\nForeign Language(s) Detected in Body:")
        for lang, entries in language_map.items():
            for sentence, conf in entries:
                print(f"- {lang.upper()} ({conf:.2f}): {sentence}")
    else:
        print("\nBody appears to be entirely in English.")

    return language_map
