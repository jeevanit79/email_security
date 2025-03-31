from langdetect import detect_langs
import re

def detect_language_subject(subject):
    try:
        detections = detect_langs(subject)
        primary = detections[0]
        lang = primary.lang
        confidence = primary.prob
        print(f"📌 Subject Language Detected: {lang.upper()} ({confidence:.2f})")
        return lang, confidence
    except Exception as e:
        print(f"❌ Language detection failed for subject: {e}")
        return None, 0.0


def detect_languages_body(body):
    sentence_pattern = r'(?<=[.!?])\s+'
    sentences = re.split(sentence_pattern, body)
    
    language_map = {}

    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence or len(sentence) < 3:
            continue
        try:
            detections = detect_langs(sentence)
            primary = detections[0]
            lang = primary.lang
            confidence = primary.prob
            if lang != "en":
                if lang not in language_map:
                    language_map[lang] = []
                language_map[lang].append((sentence, confidence))
        except Exception as e:
            continue

    if language_map:
        print("\n📌 Foreign Language(s) Detected in Body:")
        for lang, entries in language_map.items():
            for sentence, conf in entries:
                print(f"- {lang.upper()} ({conf:.2f}): {sentence}")
    else:
        print("\n✅ Body appears to be entirely in English.")

    return language_map
