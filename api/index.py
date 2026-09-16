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
    headers_for_msg = raw_headers
    if "\r\n\r\n" not in headers_for_msg and "\n\n" not in headers_for_msg:
        headers_for_msg += "\n\nDummy body."

    msg = email.message_from_string(headers_for_msg)
    
    # Extract Authentication-Results from MIME or raw text fallback
    auth_results_list = msg.get_all("Authentication-Results", [])
    auth_results_str = " ".join(auth_results_list).lower()
    if not auth_results_str:
        auth_matches = re.findall(r'Authentication-Results:[^\n\r]+', raw_headers, re.IGNORECASE)
        auth_results_str = " ".join(auth_matches).lower()
    
    # Helper to find statuses using regex in Authentication-Results
    def get_status(mechanism: str) -> str:
        match = re.search(rf'{mechanism}=([^;\s]+)', auth_results_str, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        # Fallback for printed Gmail header format (mailed-by / signed-by)
        if mechanism == 'spf':
            if re.search(r'mailed-by:\s*[^\n\r]+', raw_headers, re.IGNORECASE) or re.search(r'spf\s*=\s*pass', raw_headers, re.IGNORECASE):
                return 'pass'
            elif re.search(r'spf\s*=\s*fail', raw_headers, re.IGNORECASE):
                return 'fail'
        elif mechanism == 'dkim':
            if re.search(r'signed-by:\s*[^\n\r]+', raw_headers, re.IGNORECASE) or re.search(r'dkim\s*=\s*pass', raw_headers, re.IGNORECASE):
                return 'pass'
            elif re.search(r'dkim\s*=\s*fail', raw_headers, re.IGNORECASE):
                return 'fail'
        elif mechanism == 'dmarc':
            if re.search(r'dmarc\s*=\s*pass', raw_headers, re.IGNORECASE):
                return 'pass'
            elif re.search(r'dmarc\s*=\s*fail', raw_headers, re.IGNORECASE):
                return 'fail'
        return 'unknown'

    spf_status = get_status('spf')
    dkim_status = get_status('dkim')
    dmarc_status = get_status('dmarc')
    arc_status = get_status('arc')

    # Extract From header
    from_email = msg.get("From", "")
    if not from_email:
        from_match = re.search(r'(?:From|from):\s*([^\n\r]+)', raw_headers)
        if from_match:
            from_email = from_match.group(1).strip()

    from_email_addr = ""
    if "<" in from_email and ">" in from_email:
        from_email_addr = from_email.split("<")[1].split(">")[0]
    else:
        # Regex find email inside from_email or raw string fallback
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', from_email)
        from_email_addr = email_match.group(0) if email_match else from_email.strip()

    # Extract Subject
    subject = msg.get("Subject", "")
    if not subject:
        subject_match = re.search(r'(?:Subject|subject):\s*([^\n\r]+)', raw_headers)
        if subject_match:
            subject = subject_match.group(1).strip()

    # Extract Return-Path or mailed-by
    return_path = msg.get("Return-Path", "")
    if not return_path:
        return_match = re.search(r'(?:Return-Path|return-path|mailed-by):\s*<?([^>\s\n\r]+)>?', raw_headers, re.IGNORECASE)
        if return_match:
            return_path = return_match.group(1).strip()

    return_path_email = return_path.replace("<", "").replace(">", "").strip()
    
    # Extract Received Chain & IPs
    received_chain = msg.get_all("Received", [])
    if not received_chain:
        received_matches = re.findall(r'Received:[^\n\r]+(?:\n\s+[^\n\r]+)*', raw_headers, re.IGNORECASE)
        if received_matches:
            received_chain = [r.strip() for r in received_matches]

    originating_ip = "Unknown"
    if received_chain:
        originating_ip = extract_ip(received_chain[-1])
    else:
        # Look for any IP address in the raw header text
        ip_match = extract_ip(raw_headers)
        if ip_match != "Unknown":
            originating_ip = ip_match

    # Risk Score & Findings
    risk_score = 0
    findings = []

    if spf_status in ['fail', 'softfail']:
        risk_score += 30
        findings.append({"severity": "High", "finding": f"SPF check failed ({spf_status})", "recommendation": "Verify SPF records and authorized senders."})
    elif spf_status == 'pass':
        findings.append({"severity": "Low", "finding": "SPF check passed", "recommendation": "Sender domain is authorized."})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "SPF record not found or inconclusive", "recommendation": "Ensure the sending domain has a valid SPF record."})

    if dkim_status == 'fail':
        risk_score += 30
        findings.append({"severity": "High", "finding": "DKIM signature invalid or failed", "recommendation": "Check DKIM signing configuration."})
    elif dkim_status == 'pass':
        findings.append({"severity": "Low", "finding": "DKIM check passed", "recommendation": "Email signature is authentic."})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "No valid DKIM signature found", "recommendation": "Implement DKIM signing for outgoing emails."})

    if dmarc_status == 'fail':
        risk_score += 40
        findings.append({"severity": "Critical", "finding": "DMARC alignment failed", "recommendation": "Review DMARC policy and alignment of SPF/DKIM."})
    elif dmarc_status == 'pass':
        findings.append({"severity": "Low", "finding": "DMARC check passed", "recommendation": "Domain policy verified."})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "DMARC record missing or not applied", "recommendation": "Publish a DMARC record to protect the domain."})

    spoof_detected = False
    if from_email_addr and return_path_email:
        from_domain = from_email_addr.split('@')[-1] if '@' in from_email_addr else ""
        return_domain = return_path_email.split('@')[-1] if '@' in return_path_email else ""
        if from_domain and return_domain and from_domain not in return_domain and return_domain not in from_domain:
            risk_score += 50
            spoof_detected = True
            findings.append({"severity": "Critical", "finding": "Return-Path and From domain mismatch (Spoofing Indicator)", "recommendation": "Highly suspicious. Treat this email with caution."})

    # Additional Gmail / Printed PDF indicators
    if "mailed-by:" in raw_headers.lower() or "signed-by:" in raw_headers.lower():
        findings.append({"severity": "Info", "finding": "Detected Printed Email PDF layout (e.g. Gmail print headers).", "recommendation": "Headers parsed successfully from PDF print text."})

    overall_status = 'Safe'
    if risk_score >= 70:
        overall_status = 'Critical'
    elif risk_score >= 40:
        overall_status = 'High'
    elif risk_score >= 20:
        overall_status = 'Medium'
    elif risk_score > 0:
        overall_status = 'Low'

    parsed_headers = {}
    for key, val in msg.items():
        if key in parsed_headers:
            if isinstance(parsed_headers[key], list):
                parsed_headers[key].append(val)
            else:
                parsed_headers[key] = [parsed_headers[key], val]
        else:
            parsed_headers[key] = val

    # Include fallback parsed fields if msg didn't catch them
    if "From" not in parsed_headers and from_email_addr:
        parsed_headers["From"] = from_email_addr
    if "Subject" not in parsed_headers and subject:
        parsed_headers["Subject"] = subject
    if "Return-Path" not in parsed_headers and return_path_email:
        parsed_headers["Return-Path"] = return_path_email

    return {
        "sender_email": from_email_addr,
        "return_path": return_path_email,
        "subject": subject,
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

