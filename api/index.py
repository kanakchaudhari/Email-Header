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
    # Look for IPv4 addresses
    matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    for ip in matches:
        # Exclude local/loopback IPs if possible
        if not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip == "0.0.0.0"):
            return ip
    return matches[0] if matches else 'Unknown'

@app.post("/api/analyze")
@app.post("/analyze")
@app.post("/")
async def analyze_headers(data: AnalyzeRequest):
    raw_headers = data.headers.strip()
    
    # Prepend dummy body if needed for standard MIME parser
    headers_for_msg = raw_headers
    if "\r\n\r\n" not in headers_for_msg and "\n\n" not in headers_for_msg:
        headers_for_msg += "\n\nDummy body."

    msg = email.message_from_string(headers_for_msg)

    # -------------------------------------------------------------
    # 1. EXTRACT SUBJECT
    # -------------------------------------------------------------
    subject = msg.get("Subject", "").strip()
    if not subject:
        subject_match = re.search(r'(?:Subject|subject):\s*([^\n\r]+)', raw_headers)
        if subject_match:
            subject = subject_match.group(1).strip()
    if not subject:
        # Check for Gmail print title "Gmail - Subject Title"
        gmail_match = re.search(r'Gmail\s*-\s*([^\n\r]+)', raw_headers, re.IGNORECASE)
        if gmail_match:
            subject = gmail_match.group(1).strip()

    # -------------------------------------------------------------
    # 2. EXTRACT FROM (DECLARED SENDER)
    # -------------------------------------------------------------
    from_raw = msg.get("From", "").strip()
    if not from_raw:
        from_match = re.search(r'(?:From|from):\s*([^\n\r]+)', raw_headers)
        if from_match:
            from_raw = from_match.group(1).strip()

    # If still not found, search for any "Name <email@domain.com>" pattern in top 15 lines
    if not from_raw:
        lines = [line.strip() for line in raw_headers.split('\n') if line.strip()][:15]
        for line in lines:
            if "<" in line and ">" in line and "@" in line and not line.lower().startswith("to:"):
                from_raw = line
                break
        if not from_raw:
            # Fallback to any standalone email in top text
            all_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw_headers)
            if all_emails:
                from_raw = all_emails[0]

    from_email_addr = ""
    if "<" in from_raw and ">" in from_raw:
        match_addr = re.search(r'<([^>]+)>', from_raw)
        from_email_addr = match_addr.group(1).strip() if match_addr else from_raw
    else:
        match_addr = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', from_raw)
        from_email_addr = match_addr.group(0).strip() if match_addr else from_raw

    # -------------------------------------------------------------
    # 3. EXTRACT RETURN-PATH (ACTUAL SENDER)
    # -------------------------------------------------------------
    return_path_raw = msg.get("Return-Path", "").strip()
    if not return_path_raw:
        rp_match = re.search(r'(?:Return-Path|return-path):\s*<?([^>\s\n\r]+)>?', raw_headers, re.IGNORECASE)
        if rp_match:
            return_path_raw = rp_match.group(1).strip()

    if not return_path_raw:
        # Check Gmail printed "mailed-by:"
        mailed_match = re.search(r'mailed-by:\s*([^\s\n\r]+)', raw_headers, re.IGNORECASE)
        if mailed_match:
            mailed_domain = mailed_match.group(1).strip()
            # If from_email_addr belongs to same domain or parent domain, use from_email_addr
            if from_email_addr and mailed_domain in from_email_addr:
                return_path_raw = from_email_addr
            else:
                return_path_raw = f"no-reply@{mailed_domain}"

    if not return_path_raw:
        return_path_raw = from_email_addr

    return_path_email = return_path_raw.replace("<", "").replace(">", "").strip()

    # -------------------------------------------------------------
    # 4. EXTRACT AUTHENTICATION RESULTS (SPF, DKIM, DMARC, ARC)
    # -------------------------------------------------------------
    auth_results_list = msg.get_all("Authentication-Results", [])
    auth_results_str = " ".join(auth_results_list).lower()
    if not auth_results_str:
        auth_matches = re.findall(r'Authentication-Results:[^\n\r]+(?:\n\s+[^\n\r]+)*', raw_headers, re.IGNORECASE)
        auth_results_str = " ".join(auth_matches).lower()

    def get_mech_status(mechanism: str) -> str:
        match = re.search(rf'{mechanism}=([^;\s]+)', auth_results_str, re.IGNORECASE)
        if match:
            val = match.group(1).lower().strip()
            if val in ['pass', 'fail', 'softfail', 'neutral', 'none']:
                return val

        # Fallback inspection for Printed Gmail PDF format
        lower_headers = raw_headers.lower()
        if mechanism == 'spf':
            if 'mailed-by:' in lower_headers or 'spf=pass' in lower_headers or 'spf: pass' in lower_headers:
                return 'pass'
            elif 'spf=fail' in lower_headers or 'spf: fail' in lower_headers:
                return 'fail'
        elif mechanism == 'dkim':
            if 'signed-by:' in lower_headers or 'dkim=pass' in lower_headers or 'dkim: pass' in lower_headers:
                return 'pass'
            elif 'dkim=fail' in lower_headers or 'dkim: fail' in lower_headers:
                return 'fail'
        elif mechanism == 'dmarc':
            if 'dmarc=pass' in lower_headers or 'dmarc: pass' in lower_headers:
                return 'pass'
            elif ('mailed-by:' in lower_headers and 'signed-by:' in lower_headers):
                # Both SPF and DKIM verified in Gmail print
                return 'pass'
            elif 'dmarc=fail' in lower_headers or 'dmarc: fail' in lower_headers:
                return 'fail'
        elif mechanism == 'arc':
            if 'arc=pass' in lower_headers or 'security:' in lower_headers or 'tls' in lower_headers:
                return 'pass'

        return 'unknown'

    spf_status = get_mech_status('spf')
    dkim_status = get_mech_status('dkim')
    dmarc_status = get_mech_status('dmarc')
    arc_status = get_mech_status('arc')

    # -------------------------------------------------------------
    # 5. EXTRACT ROUTING & ORIGINATING IP
    # -------------------------------------------------------------
    received_chain = msg.get_all("Received", [])
    if not received_chain:
        received_matches = re.findall(r'Received:[^\n\r]+(?:\n\s+[^\n\r]+)*', raw_headers, re.IGNORECASE)
        if received_matches:
            received_chain = [r.strip() for r in received_matches]

    originating_ip = "Unknown"
    if received_chain:
        originating_ip = extract_ip(received_chain[-1])
    else:
        originating_ip = extract_ip(raw_headers)

    # -------------------------------------------------------------
    # 6. RISK CALCULATIONS & FINDINGS
    # -------------------------------------------------------------
    risk_score = 0
    findings = []

    # SPF Finding
    if spf_status in ['fail', 'softfail']:
        risk_score += 30
        findings.append({"severity": "High", "finding": f"SPF authentication failed ({spf_status})", "recommendation": "Verify sending server authorization."})
    elif spf_status == 'pass':
        findings.append({"severity": "Low", "finding": "SPF check passed cleanly.", "recommendation": "Sending domain server is authorized."})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "SPF record unverified or missing.", "recommendation": "Publish valid SPF records."})

    # DKIM Finding
    if dkim_status == 'fail':
        risk_score += 30
        findings.append({"severity": "High", "finding": "DKIM signature invalid or corrupted.", "recommendation": "Ensure DKIM key alignment."})
    elif dkim_status == 'pass':
        findings.append({"severity": "Low", "finding": "DKIM signature verified.", "recommendation": "Message contents are authentic."})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "No DKIM signature found.", "recommendation": "Enable DKIM signing for outgoing mail."})

    # DMARC Finding
    if dmarc_status == 'fail':
        risk_score += 40
        findings.append({"severity": "Critical", "finding": "DMARC policy check failed.", "recommendation": "Audit domain alignment and enforcement."})
    elif dmarc_status == 'pass':
        findings.append({"severity": "Low", "finding": "DMARC policy alignment verified.", "recommendation": "Sender domain protected against spoofing."})
    else:
        risk_score += 10
        findings.append({"severity": "Medium", "finding": "DMARC policy missing or unapplied.", "recommendation": "Enforce a DMARC policy (p=reject or quarantine)."})

    # Spoofing Detection
    spoof_detected = False
    if from_email_addr and return_path_email:
        from_domain = from_email_addr.split('@')[-1].lower() if '@' in from_email_addr else ""
        return_domain = return_path_email.split('@')[-1].lower() if '@' in return_path_email else ""
        if from_domain and return_domain and from_domain not in return_domain and return_domain not in from_domain:
            if spf_status != 'pass':
                risk_score += 50
                spoof_detected = True
                findings.append({"severity": "Critical", "finding": f"Domain Mismatch: From ({from_domain}) differs from Return-Path ({return_domain})", "recommendation": "High risk of email spoofing."})

    if "mailed-by:" in raw_headers.lower() or "signed-by:" in raw_headers.lower():
        findings.append({"severity": "Info", "finding": "Parsed layout from Printed Email PDF (Gmail/Webmail print format).", "recommendation": "Extracted verified fields from print headers."})

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

    if "From" not in parsed_headers and from_email_addr:
        parsed_headers["From"] = from_raw or from_email_addr
    if "Subject" not in parsed_headers and subject:
        parsed_headers["Subject"] = subject
    if "Return-Path" not in parsed_headers and return_path_email:
        parsed_headers["Return-Path"] = return_path_email

    return {
        "sender_email": from_email_addr or from_raw or "Unknown",
        "return_path": return_path_email or from_email_addr or "Unknown",
        "subject": subject or "No Subject",
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
