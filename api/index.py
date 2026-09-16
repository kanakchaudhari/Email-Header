from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import email
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    headers: str

def extract_ip(text: str) -> str:
    match = re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', text)
    return match.group(0) if match else 'Unknown'

@app.post("/api/analyze")
@app.post("/analyze")
@app.post("/")
async def analyze_headers(data: AnalyzeRequest):
    raw_headers = data.headers
    
    # Prepend a dummy body if it's missing to help parsing
    if "\r\n\r\n" not in raw_headers and "\n\n" not in raw_headers:
        raw_headers += "\n\nDummy body."

    msg = email.message_from_string(raw_headers)
    
    # Extract Authentication-Results
    auth_results_list = msg.get_all("Authentication-Results", [])
    auth_results_str = " ".join(auth_results_list).lower()
    
    # Extract Received Chain
    received_chain = msg.get_all("Received", [])
    
    # Helper to find statuses using regex in Authentication-Results
    def get_status(mechanism: str) -> str:
        match = re.search(rf'{mechanism}=([^;\s]+)', auth_results_str, re.IGNORECASE)
        return match.group(1).lower() if match else 'unknown'

    spf_status = get_status('spf')
    dkim_status = get_status('dkim')
    dmarc_status = get_status('dmarc')
    arc_status = get_status('arc')

    risk_score = 0
    findings = []

    if spf_status in ['fail', 'softfail']:
        risk_score += 30
        findings.append({"severity": "High", "finding": f"SPF check failed ({spf_status})", "recommendation": "Verify SPF records and authorized senders."})
    elif spf_status == 'pass':
        findings.append({"severity": "Low", "finding": "SPF check passed", "recommendation": ""})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "SPF record not found or inconclusive", "recommendation": "Ensure the sending domain has a valid SPF record."})

    if dkim_status == 'fail':
        risk_score += 30
        findings.append({"severity": "High", "finding": "DKIM signature invalid or failed", "recommendation": "Check DKIM signing configuration."})
    elif dkim_status == 'pass':
        findings.append({"severity": "Low", "finding": "DKIM check passed", "recommendation": ""})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "No valid DKIM signature", "recommendation": "Implement DKIM signing for outgoing emails."})

    if dmarc_status == 'fail':
        risk_score += 40
        findings.append({"severity": "Critical", "finding": "DMARC alignment failed", "recommendation": "Review DMARC policy and alignment of SPF/DKIM."})
    elif dmarc_status == 'pass':
        findings.append({"severity": "Low", "finding": "DMARC check passed", "recommendation": ""})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "DMARC record missing or not applied", "recommendation": "Publish a DMARC record to protect the domain."})

    from_email = msg.get("From", "")
    from_email_addr = ""
    if "<" in from_email and ">" in from_email:
        from_email_addr = from_email.split("<")[1].split(">")[0]
    else:
        from_email_addr = from_email

    return_path = msg.get("Return-Path", "")
    return_path_email = return_path.replace("<", "").replace(">", "")
    
    spoof_detected = False
    if from_email_addr and return_path_email:
        from_domain = from_email_addr.split('@')[-1] if '@' in from_email_addr else ""
        return_domain = return_path_email.split('@')[-1] if '@' in return_path_email else ""
        if from_domain and return_domain and from_domain not in return_domain and return_domain not in from_domain:
            risk_score += 50
            spoof_detected = True
            findings.append({"severity": "Critical", "finding": "Return-Path and From domain mismatch (Spoofing Indicator)", "recommendation": "Highly suspicious. Treat this email with caution."})

    overall_status = 'Safe'
    if risk_score >= 70:
        overall_status = 'Critical'
    elif risk_score >= 40:
        overall_status = 'High'
    elif risk_score >= 20:
        overall_status = 'Medium'
    elif risk_score > 0:
        overall_status = 'Low'

    originating_ip = "Unknown"
    if received_chain:
        originating_ip = extract_ip(received_chain[-1])

    parsed_headers = {}
    for key, val in msg.items():
        if key in parsed_headers:
            if isinstance(parsed_headers[key], list):
                parsed_headers[key].append(val)
            else:
                parsed_headers[key] = [parsed_headers[key], val]
        else:
            parsed_headers[key] = val

    return {
        "sender_email": from_email_addr,
        "return_path": return_path_email,
        "subject": msg.get("Subject", ""),
        "risk_score": min(risk_score, 100),
        "overall_status": overall_status,
        "spoof_detected": spoof_detected,
        "authentication_results": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "arc": arc_status
        },
        "routing_information": {
            "received_chain": received_chain,
            "originating_ip": originating_ip,
            "hop_count": len(received_chain)
        },
        "security_findings": findings,
        "parsed_headers": parsed_headers
    }
