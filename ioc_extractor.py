import re

def extract_iocs(email_body):
    # IOC Patterns
    url_pattern = r"\b(?:https?://|www\.)[^\s\"\'<>]+\.[a-z]{2,}(?:/[^\s\"\'<>]*)?"
    email_pattern = r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"  # Capture domain
    full_email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ipv6_pattern = r"\b(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}\b"
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    # Extract matches
    emails = list(set(re.findall(full_email_pattern, email_body)))
    email_domains = list(set(re.findall(email_pattern, email_body)))
    urls = list(set(re.findall(url_pattern, email_body)))
    ipv4s = list(set(re.findall(ipv4_pattern, email_body)))
    ipv6s = list(set(re.findall(ipv6_pattern, email_body)))
    md5s = [h for h in re.findall(md5_pattern, email_body) if h not in email_body]
    sha1s = [h for h in re.findall(sha1_pattern, email_body) if h not in email_body]
    sha256s = list(set(re.findall(sha256_pattern, email_body)))

    return {
        "emails": emails,
        "email_domains": email_domains,
        "urls": urls,
        "ipv4": ipv4s,
        "ipv6": ipv6s,
        "md5": md5s,
        "sha1": sha1s,
        "sha256": sha256s
    }
