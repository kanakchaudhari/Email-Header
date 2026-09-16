export interface AnalysisResult {
  sender_email: string;
  return_path: string;
  subject: string;
  risk_score: number;
  overall_status: string;
  spoof_detected: boolean;
  authentication_results: {
    spf: string;
    dkim: string;
    dmarc: string;
    arc: string;
  };
  routing_information: {
    received_chain: string[];
    originating_ip: string;
    hop_count: number;
  };
  security_findings: Array<{
    severity: string;
    finding: string;
    recommendation: string;
  }>;
  parsed_headers: Record<string, any>;
}

export function parseEmailText(rawText: string): AnalysisResult {
  const text = rawText.trim();
  const lines = text.split(/\r?\n/).map(l => l.trim());

  // 1. EXTRACT SUBJECT
  let subject = "";
  const subjMatch = text.match(/(?:Subject|subject):\s*([^\n\r]+)/);
  if (subjMatch) {
    subject = subjMatch[1].trim();
  } else {
    const gmailSubjMatch = text.match(/Gmail\s*-\s*([^\n\r]+)/i);
    if (gmailSubjMatch) {
      subject = gmailSubjMatch[1].trim();
    }
  }
  if (!subject && lines.length > 0) {
    if (!lines[0].includes(":") && !lines[0].includes("@")) {
      subject = lines[0];
    }
  }

  // 2. EXTRACT FROM (DECLARED SENDER)
  let fromRaw = "";
  const fromMatch = text.match(/(?:From|from):\s*([^\n\r]+)/);
  if (fromMatch) {
    fromRaw = fromMatch[1].trim();
  } else {
    for (const line of lines.slice(0, 15)) {
      if (line.includes("<") && line.includes(">") && line.includes("@") && !line.toLowerCase().startsWith("to:")) {
        fromRaw = line;
        break;
      }
    }
    if (!fromRaw) {
      const allEmails = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
      if (allEmails && allEmails.length > 0) {
        fromRaw = allEmails[0];
      }
    }
  }

  let senderEmail = "";
  if (fromRaw.includes("<") && fromRaw.includes(">")) {
    const match = fromRaw.match(/<([^>]+)>/);
    senderEmail = match ? match[1].trim() : fromRaw;
  } else {
    const match = fromRaw.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    senderEmail = match ? match[0].trim() : fromRaw;
  }

  // 3. EXTRACT RETURN-PATH (ACTUAL SENDER)
  let returnPathRaw = "";
  const rpMatch = text.match(/(?:Return-Path|return-path):\s*<?([^>\s\n\r]+)>?/i);
  if (rpMatch) {
    returnPathRaw = rpMatch[1].trim();
  } else {
    const mailedMatch = text.match(/mailed-by:\s*([^\s\n\r]+)/i);
    if (mailedMatch) {
      const mailedDomain = mailedMatch[1].trim();
      if (senderEmail && senderEmail.toLowerCase().includes(mailedDomain.toLowerCase())) {
        returnPathRaw = senderEmail;
      } else {
        returnPathRaw = `no-reply@${mailedDomain}`;
      }
    }
  }
  if (!returnPathRaw) {
    returnPathRaw = senderEmail;
  }
  const returnPath = returnPathRaw.replace(/[<>]/g, "").trim();

  // 4. AUTHENTICATION RESULTS
  const lowerText = text.toLowerCase();
  
  let spf = 'unknown';
  const spfMatch = lowerText.match(/spf=([;\s]+)/) || lowerText.match(/spf:\s*(\w+)/);
  if (spfMatch && ['pass', 'fail', 'softfail', 'neutral', 'none'].includes(spfMatch[1])) {
    spf = spfMatch[1];
  } else if (lowerText.includes('mailed-by:') || lowerText.includes('spf=pass') || lowerText.includes('spf: pass')) {
    spf = 'pass';
  } else if (lowerText.includes('spf=fail') || lowerText.includes('spf: fail')) {
    spf = 'fail';
  }

  let dkim = 'unknown';
  const dkimMatch = lowerText.match(/dkim=([;\s]+)/) || lowerText.match(/dkim:\s*(\w+)/);
  if (dkimMatch && ['pass', 'fail', 'neutral', 'none'].includes(dkimMatch[1])) {
    dkim = dkimMatch[1];
  } else if (lowerText.includes('signed-by:') || lowerText.includes('dkim=pass') || lowerText.includes('dkim: pass')) {
    dkim = 'pass';
  } else if (lowerText.includes('dkim=fail') || lowerText.includes('dkim: fail')) {
    dkim = 'fail';
  }

  let dmarc = 'unknown';
  const dmarcMatch = lowerText.match(/dmarc=([;\s]+)/) || lowerText.match(/dmarc:\s*(\w+)/);
  if (dmarcMatch && ['pass', 'fail', 'none'].includes(dmarcMatch[1])) {
    dmarc = dmarcMatch[1];
  } else if (lowerText.includes('dmarc=pass') || lowerText.includes('dmarc: pass') || (lowerText.includes('mailed-by:') && lowerText.includes('signed-by:'))) {
    dmarc = 'pass';
  } else if (lowerText.includes('dmarc=fail') || lowerText.includes('dmarc: fail')) {
    dmarc = 'fail';
  }

  let arc = 'unknown';
  if (lowerText.includes('arc=pass') || lowerText.includes('security:') || lowerText.includes('tls')) {
    arc = 'pass';
  }

  // 5. ROUTING & IP
  const receivedChain: string[] = [];
  const recMatches = text.match(/Received:[^\n\r]+(?:\n\s+[^\n\r]+)*/gi);
  if (recMatches) {
    receivedChain.push(...recMatches.map(r => r.trim()));
  }

  const ipMatches = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [];
  let originatingIp = 'Unknown';
  for (const ip of ipMatches) {
    if (!ip.startsWith('127.') && !ip.startsWith('10.') && !ip.startsWith('192.168.') && ip !== '0.0.0.0') {
      originatingIp = ip;
      break;
    }
  }
  if (originatingIp === 'Unknown' && ipMatches.length > 0) {
    originatingIp = ipMatches[0] || 'Unknown';
  }

  // 6. RISK CALCULATIONS
  let riskScore = 0;
  const findings: Array<{ severity: string; finding: string; recommendation: string }> = [];

  if (spf === 'fail' || spf === 'softfail') {
    riskScore += 30;
    findings.push({ severity: 'High', finding: `SPF check failed (${spf})`, recommendation: 'Verify authorized sender servers.' });
  } else if (spf === 'pass') {
    findings.push({ severity: 'Low', finding: 'SPF authentication passed.', recommendation: 'Sender domain is authorized.' });
  } else {
    riskScore += 10;
    findings.push({ severity: 'Medium', finding: 'SPF status unverified.', recommendation: 'Ensure domain has SPF records.' });
  }

  if (dkim === 'fail') {
    riskScore += 30;
    findings.push({ severity: 'High', finding: 'DKIM signature invalid.', recommendation: 'Check DKIM key signing configuration.' });
  } else if (dkim === 'pass') {
    findings.push({ severity: 'Low', finding: 'DKIM signature verified.', recommendation: 'Email payload is authentic.' });
  } else {
    riskScore += 10;
    findings.push({ severity: 'Medium', finding: 'No DKIM signature found.', recommendation: 'Enable DKIM signing.' });
  }

  if (dmarc === 'fail') {
    riskScore += 40;
    findings.push({ severity: 'Critical', finding: 'DMARC policy alignment failed.', recommendation: 'Audit SPF and DKIM domain alignment.' });
  } else if (dmarc === 'pass') {
    findings.push({ severity: 'Low', finding: 'DMARC alignment verified.', recommendation: 'Domain is protected against spoofing.' });
  } else {
    riskScore += 10;
    findings.push({ severity: 'Medium', finding: 'DMARC policy unapplied.', recommendation: 'Enforce DMARC (p=reject or quarantine).' });
  }

  let spoofDetected = false;
  if (senderEmail && returnPath) {
    const fromDomain = senderEmail.split('@').pop()?.toLowerCase() || '';
    const returnDomain = returnPath.split('@').pop()?.toLowerCase() || '';
    if (fromDomain && returnDomain && !fromDomain.includes(returnDomain) && !returnDomain.includes(fromDomain)) {
      if (spf !== 'pass') {
        riskScore += 50;
        spoofDetected = true;
        findings.push({
          severity: 'Critical',
          finding: `Domain Mismatch: From (${fromDomain}) != Return-Path (${returnDomain})`,
          recommendation: 'High risk of email spoofing.'
        });
      }
    }
  }

  if (lowerText.includes('mailed-by:') || lowerText.includes('signed-by:')) {
    findings.push({
      severity: 'Info',
      finding: 'Parsed Printed Email PDF layout (Gmail/Webmail print headers).',
      recommendation: 'Successfully extracted email verification fields.'
    });
  }

  let overallStatus = 'Safe';
  if (riskScore >= 70) overallStatus = 'Critical';
  else if (riskScore >= 40) overallStatus = 'High';
  else if (riskScore >= 20) overallStatus = 'Medium';
  else if (riskScore > 0) overallStatus = 'Low';

  return {
    sender_email: senderEmail || 'Unknown',
    return_path: returnPath || senderEmail || 'Unknown',
    subject: subject || 'No Subject',
    risk_score: Math.min(riskScore, 100),
    overall_status: overallStatus,
    spoof_detected: spoofDetected,
    authentication_results: { spf, dkim, dmarc, arc },
    routing_information: {
      received_chain: receivedChain,
      originating_ip: originatingIp,
      hop_count: receivedChain.length
    },
    security_findings: findings,
    parsed_headers: {
      From: fromRaw || senderEmail,
      Subject: subject,
      'Return-Path': returnPath
    }
  };
}
