import re
import boto3
import json

# Initialize Bedrock runtime client
bedrock_runtime = boto3.client('bedrock-runtime')

def run_subject_analysis(subject, from_address):
    print(f"Analyzing Subject: {subject}")
    print(f"Sender: {from_address}")
    
    # Check for malicious URLs
    malicious_url_pattern = r"https?://[^\s]+"
    urls_found = re.findall(malicious_url_pattern, subject)
    if urls_found:
        print(f"Malicious URL detected in subject: {urls_found}")
    else:
        print("No malicious URLs detected in subject.")
    
    # Prepare the prompt
    prompt = ("Straight give me without prolonging: "
              "What is the intent behind the following email subject without extra words? "
              "Categorize it (among 'malicious' / 'non-malicious'). "
              "Confident threat level on a scale of 1/10 and explanation in regards to phishing attempt.\n\n"
              f"Email Subject: {subject}")
    
    # Create the correct body format for Llama models
    body = {
        "prompt": prompt,
        "max_gen_len": 300,
        "temperature": 0.6,
        "top_p": 0.9
    }

    # Send request to Bedrock
    response = bedrock_runtime.invoke_model(
        modelId="us.meta.llama3-2-1b-instruct-v1:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps(body)
    )
    
    # Parse response
    result = json.loads(response['body'].read())
    generated_text = result.get('generation', '')
    
    print("LLaMA 3.2 Inference Result:")
    print(generated_text)