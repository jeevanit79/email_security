import requests
import base64
import boto3
import json
from botocore.exceptions import ClientError

def get_virustotal_api_key():
    secret_name = "virus_total_api_credentials"
    region_name = "us-east-1"
    key_field = "virus_total_api_key"  # <-- Match the actual key name in your secret

    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret_string = response['SecretString']
        secret_json = json.loads(secret_string)
        return secret_json.get(key_field)
    except Exception as e:
        print(f"❌ Error retrieving VT API key: {e}")
        return None
# ✅ Initialize VT API key + headers at module level
API_KEY = get_virustotal_api_key()
HEADERS = {"x-apikey": API_KEY} if API_KEY else {}

# 🔍 Submit and lookup URL
def lookup_url(url):
    try:
        # Submit URL for analysis
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=HEADERS,
            data={"url": url}
        )
        submit_response.raise_for_status()
        url_id = submit_response.json()["data"]["id"]

        # Retrieve analysis report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        report_response = requests.get(report_url, headers=HEADERS)
        report_response.raise_for_status()

        stats = report_response.json()["data"]["attributes"]["stats"]
        return {
            "ioc_type": "url",
            "ioc_value": url,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"]
        }

    except Exception as e:
        return {"ioc_type": "url", "ioc_value": url, "error": str(e)}

# 🌐 Domain lookup
def lookup_domain(domain):
    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(vt_url, headers=HEADERS)
        response.raise_for_status()

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "ioc_type": "domain",
            "ioc_value": domain,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"]
        }

    except Exception as e:
        return {"ioc_type": "domain", "ioc_value": domain, "error": str(e)}

# 🌍 IP address lookup
def lookup_ip(ip):
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(vt_url, headers=HEADERS)
        response.raise_for_status()

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "ioc_type": "ip",
            "ioc_value": ip,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"]
        }

    except Exception as e:
        return {"ioc_type": "ip", "ioc_value": ip, "error": str(e)}

# 🧬 Hash lookup (MD5, SHA1, SHA256)
def lookup_hash(hash_value):
    try:
        vt_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        response = requests.get(vt_url, headers=HEADERS)
        response.raise_for_status()

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "ioc_type": "hash",
            "ioc_value": hash_value,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"]
        }

    except Exception as e:
        return {"ioc_type": "hash", "ioc_value": hash_value, "error": str(e)}
