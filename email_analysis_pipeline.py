# email_analysis_pipeline.py

import boto3
import email
from email import policy
import re
from subject_analysis import run_subject_analysis
from language_detector_fasttext import detect_language_subject, detect_languages_body
from ioc_extractor import extract_iocs
from ioc_threat_intel import run_threat_intel

# AWS Configurations
AWS_REGION = "us-east-1"
S3_BUCKET_NAME = "email-sec-datasets-bronze"
S3_FILE_PATH = "email-sec-datasets-bronze/extracted/enron_mail_20150507/maildir/allen-p/inbox/71."

# Initialize S3 Client
s3 = boto3.client("s3", region_name=AWS_REGION)

def read_email_from_s3(file_path):
    try:
        response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=file_path)
        raw_email = response["Body"].read().decode("utf-8")
        return raw_email
    except Exception as e:
        print(f"\ Error reading {file_path}: {str(e)}")
        return None

def check_if_thread(email_content):
    from_matches = re.findall(r"(?i)^From:\s*(.*)", email_content, re.MULTILINE)
    to_matches = re.findall(r"(?i)^To:\s*(.*)", email_content, re.MULTILINE)
    subject_matches = re.findall(r"(?i)^Subject:\s*(.*)", email_content, re.MULTILINE)
    email_count = min(len(from_matches), len(to_matches), len(subject_matches))
    if email_count > 1:
        print(f"This email is part of a thread. (Total Emails in Thread: {email_count})")
    else:
        print(f"This is a single email. (Total Emails in Thread: {email_count})")

def extract_metadata_and_body(email_content):
    split_match = re.split(r"\n\s*\n", email_content, maxsplit=1)
    headers_text = split_match[0] if len(split_match) > 1 else ""
    body = split_match[1] if len(split_match) > 1 else ""

    metadata = {
        "Message-ID": re.search(r"(?i)^Message-ID:\s*(.*)", headers_text, re.MULTILINE),
        "From": re.search(r"(?i)^From:\s*(.*)", headers_text, re.MULTILINE),
        "To": re.search(r"(?i)^To:\s*(.*)", headers_text, re.MULTILINE),
        "Date": re.search(r"(?i)^Date:\s*(.*)", headers_text, re.MULTILINE),
        "Subject": re.search(r"(?i)^Subject:\s*(.*)", headers_text, re.MULTILINE),
        "In-Reply-To": re.search(r"(?i)^In-Reply-To:\s*(.*)", headers_text, re.MULTILINE),
        "References": re.search(r"(?i)^References:\s*(.*)", headers_text, re.MULTILINE),
        "Content-Type": re.search(r"(?i)^Content-Type:\s*(.*)", headers_text, re.MULTILINE),
    }

    extracted_metadata = {key: (match.group(1).strip() if match else None) for key, match in metadata.items()}
    return extracted_metadata, body.strip()

def main():
    raw_email_content = read_email_from_s3(S3_FILE_PATH)
    if not raw_email_content:
        return

    check_if_thread(raw_email_content)
    email_metadata, email_body = extract_metadata_and_body(raw_email_content)

    print("\n Extracted Metadata (Headers):")
    for key, value in email_metadata.items():
        print(f"{key}: {value}")

    print("\n Extracted Body (Without Metadata):")
    print(email_body)

    subject = email_metadata.get("Subject", "")
    body = email_body

    detect_language_subject(subject)
    detect_languages_body(body)

    iocs = extract_iocs(body)
    print("\n Extracted IOCs:")
    for key, values in iocs.items():
        print(f"{key.upper()}: {values}")

    results = run_threat_intel(iocs)
    print("Threat Intel Results:")
    for res in results:
        print(res)

    if email_metadata.get("In-Reply-To") is None and email_metadata.get("References") is None:
        print("\n Performing Subject Analysis on the email...")
        from_address = email_metadata.get("From", "")
        run_subject_analysis(subject, from_address)
    else:
        print("\n This is part of an email thread. Skipping subject analysis.")

if __name__ == "__main__":
    main()
