from vt_lookup import (
    lookup_url,
    lookup_domain,
    lookup_ip,
    lookup_hash
)
from concurrent.futures import ThreadPoolExecutor

def run_threat_intel(iocs):
    results = []

    with ThreadPoolExecutor() as executor:
        futures = []

        # 🔍 Submit URL lookups
        for url in iocs.get("urls", []):
            futures.append(executor.submit(lookup_url, url))

        # 🌐 Submit Domain lookups
        for domain in iocs.get("email_domains", []):
            futures.append(executor.submit(lookup_domain, domain))

        # 🌍 Submit IP lookups (both v4 and v6)
        for ip in iocs.get("ipv4", []) + iocs.get("ipv6", []):
            futures.append(executor.submit(lookup_ip, ip))

        # 🧬 Submit Hash lookups (MD5, SHA1, SHA256)
        for h in iocs.get("md5", []) + iocs.get("sha1", []) + iocs.get("sha256", []):
            futures.append(executor.submit(lookup_hash, h))

        # 📥 Collect Results
        for future in futures:
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"error": str(e)})

    return results
