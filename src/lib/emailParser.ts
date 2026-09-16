export interface HopDetail {
  hop: number;
  from: string;
  by: string;
  withProtocol: string;
  date: string;
  ip: string;
  raw: string;
}

export interface AnalysisResult {
  sender_email: string;
  return_path: string;
  recipient?: string;
  date?: string;
  message_id?: string;
  reply_to?: string;
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
    parsed_hops?: HopDetail[];
  };
  security_findings: Array<{
    severity: string;
    finding: string;
    recommendation: string;
  }>;
  parsed_headers: Record<string, string>;
}

export function parseEmailText(rawText: string): AnalysisResult {
  const text = rawText.trim();
  const lowerText = text.toLowerCase();

  // 0. PARSE ALL KEY-VALUE HEADERS
  const unfoldedText = rawText.replace(/\r?\n[ \t]+/g, ' ');
  const headerLines = unfoldedText.split(/\r?\n/);
  const parsedHeaders: Record<string, string> = {};

  for (const line of headerLines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.substring(0, colonIdx).trim();
      const val = line.substring(colonIdx + 1).trim();
      if (key && !key.includes(' ') && !key.includes('\t')) {
        if (parsedHeaders[key]) {
          parsedHeaders[key] += '\n' + val;
        } else {
          parsedHeaders[key] = val;
        }
      }
    }
  }

  // 1. EXTRACT SUBJECT
  let subject = parsedHeaders['Subject'] || parsedHeaders['subject'] || "";
  if (!subject) {
    const subjMatch = text.match(/(?:Subject|subject):\s*([^\n\r]+)/i);
    if (subjMatch) {
      subject = subjMatch[1].trim();
    } else {
      const gmailSubjMatch = text.match(/Gmail\s*-\s*([^\n\r]+)/i);
      if (gmailSubjMatch) {
        subject = gmailSubjMatch[1].trim();
      }
    }
  }
  if (!subject && headerLines.length > 0) {
    if (!headerLines[0].includes(":") && !headerLines[0].includes("@")) {
      subject = headerLines[0];
    }
  }

  // 2. EXTRACT FROM (DECLARED SENDER)
  let fromRaw = parsedHeaders['From'] || parsedHeaders['from'] || "";
  if (!fromRaw) {
    const fromMatch = text.match(/(?:From|from):\s*([^\n\r]+)/);
    if (fromMatch) {
      fromRaw = fromMatch[1].trim();
    } else {
      for (const line of headerLines.slice(0, 15)) {
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
  let returnPathRaw = parsedHeaders['Return-Path'] || parsedHeaders['return-path'] || "";
  if (!returnPathRaw) {
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
  }
  if (!returnPathRaw) {
    returnPathRaw = senderEmail;
  }
  const returnPath = returnPathRaw.replace(/[<>]/g, "").trim();

  // EXTRACT RECIPIENT, DATE, MESSAGE-ID, REPLY-TO
  const recipient = parsedHeaders['To'] || parsedHeaders['to'] || parsedHeaders['Delivered-To'] || undefined;
  const date = parsedHeaders['Date'] || parsedHeaders['date'] || undefined;
  const messageId = parsedHeaders['Message-ID'] || parsedHeaders['message-id'] || undefined;
  const replyTo = parsedHeaders['Reply-To'] || parsedHeaders['reply-to'] || undefined;

  // 4. AUTHENTICATION RESULTS PARSING (SPF, DKIM, DMARC, ARC)
  let spf = 'unknown';
  // Check Received-SPF or Authentication-Results header or raw text
  const spfHeader = parsedHeaders['Received-SPF'] || parsedHeaders['received-spf'] || '';
  const authHeader = parsedHeaders['Authentication-Results'] || parsedHeaders['authentication-results'] || '';
  
  const spfValMatch = (spfHeader + ' ' + authHeader + ' ' + text).match(/spf=([^\s;()]+)/i) || 
                      (spfHeader + ' ' + text).match(/Received-SPF:\s*([a-z]+)/i) ||
                      lowerText.match(/spf:\s*([a-z]+)/i);
  if (spfValMatch) {
    const val = spfValMatch[1].toLowerCase();
    if (['pass', 'fail', 'softfail', 'neutral', 'none'].includes(val)) {
      spf = val;
    }
  }
  if (spf === 'unknown') {
    if (lowerText.includes('mailed-by:') || lowerText.includes('spf=pass') || lowerText.includes('spf: pass') || lowerText.includes('received-spf: pass')) {
      spf = 'pass';
    } else if (lowerText.includes('spf=fail') || lowerText.includes('spf: fail') || lowerText.includes('received-spf: fail')) {
      spf = 'fail';
    } else if (lowerText.includes('spf=softfail') || lowerText.includes('spf: softfail')) {
      spf = 'softfail';
    }
  }

  let dkim = 'unknown';
  const dkimValMatch = (authHeader + ' ' + text).match(/dkim=([^\s;()]+)/i) || lowerText.match(/dkim:\s*([a-z]+)/i);
  if (dkimValMatch) {
    const val = dkimValMatch[1].toLowerCase();
    if (['pass', 'fail', 'neutral', 'none'].includes(val)) {
      dkim = val;
    }
  }
  if (dkim === 'unknown') {
    if (parsedHeaders['DKIM-Signature'] || parsedHeaders['dkim-signature'] || lowerText.includes('signed-by:') || lowerText.includes('dkim=pass') || lowerText.includes('dkim: pass')) {
      dkim = 'pass';
    } else if (lowerText.includes('dkim=fail') || lowerText.includes('dkim: fail')) {
      dkim = 'fail';
    }
  }

  let dmarc = 'unknown';
  const dmarcValMatch = (authHeader + ' ' + text).match(/dmarc=([^\s;()]+)/i) || lowerText.match(/dmarc:\s*([a-z]+)/i);
  if (dmarcValMatch) {
    const val = dmarcValMatch[1].toLowerCase();
    if (['pass', 'fail', 'none'].includes(val)) {
      dmarc = val;
    }
  }
  if (dmarc === 'unknown') {
    if (lowerText.includes('dmarc=pass') || lowerText.includes('dmarc: pass') || (lowerText.includes('mailed-by:') && lowerText.includes('signed-by:'))) {
      dmarc = 'pass';
    } else if (lowerText.includes('dmarc=fail') || lowerText.includes('dmarc: fail')) {
      dmarc = 'fail';
    }
  }

  let arc = 'unknown';
  const arcValMatch = (authHeader + ' ' + text).match(/arc=([^\s;()]+)/i);
  if (arcValMatch) {
    const val = arcValMatch[1].toLowerCase();
    if (['pass', 'fail', 'none'].includes(val)) {
      arc = val;
    }
  }
  if (arc === 'unknown') {
    if (parsedHeaders['ARC-Seal'] || parsedHeaders['ARC-Message-Signature'] || lowerText.includes('arc=pass') || lowerText.includes('security:') || lowerText.includes('tls')) {
      arc = 'pass';
    }
  }

  // 5. ROUTING & IP PARSING
  const receivedChain: string[] = [];
  const recMatches = text.match(/Received:[^\n\r]+(?:\n\s+[^\n\r]+)*/gi);
  if (recMatches) {
    receivedChain.push(...recMatches.map(r => r.replace(/\s+/g, ' ').trim()));
  }

  // Parse structured hops
  const parsedHops: HopDetail[] = receivedChain.map((rawHop, idx) => {
    const fromMatch = rawHop.match(/from\s+([^\s;]+(?:\s+\([^)]+\))?)/i);
    const byMatch = rawHop.match(/by\s+([^\s;]+)/i);
    const withMatch = rawHop.match(/with\s+([^\s;]+)/i);
    const dateMatch = rawHop.match(/;\s*([^\n\r]+)$/);
    const ipMatch = rawHop.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);

    return {
      hop: idx + 1,
      from: fromMatch ? fromMatch[1].trim() : 'Unknown Host',
      by: byMatch ? byMatch[1].trim() : 'Unknown Receiver',
      withProtocol: withMatch ? withMatch[1].trim() : 'Standard SMTP',
      date: dateMatch ? dateMatch[1].trim() : 'N/A',
      ip: ipMatch ? ipMatch[0] : 'N/A',
      raw: rawHop
    };
  });

  const allIps = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [];
  let originatingIp = 'Unknown';
  for (const ip of allIps) {
    if (!ip.startsWith('127.') && !ip.startsWith('10.') && !ip.startsWith('192.168.') && ip !== '0.0.0.0') {
      originatingIp = ip;
      break;
    }
  }
  if (originatingIp === 'Unknown' && allIps.length > 0) {
    originatingIp = allIps[0] || 'Unknown';
  }

  // 6. RISK CALCULATIONS & FINDINGS
  let riskScore = 0;
  const findings: Array<{ severity: string; finding: string; recommendation: string }> = [];

  if (spf === 'fail' || spf === 'softfail') {
    riskScore += 30;
    findings.push({ severity: 'High', finding: `SPF check failed (${spf})`, recommendation: 'Verify authorized sender servers in DNS SPF records.' });
  } else if (spf === 'pass') {
    findings.push({ severity: 'Low', finding: 'SPF authentication passed cleanly.', recommendation: 'Sender domain is authorized to send emails.' });
  } else {
    riskScore += 10;
    findings.push({ severity: 'Medium', finding: 'SPF status unverified or missing.', recommendation: 'Ensure the sender domain has valid SPF records.' });
  }

  if (dkim === 'fail') {
    riskScore += 30;
    findings.push({ severity: 'High', finding: 'DKIM signature invalid or mismatched.', recommendation: 'Check DKIM public key signing configuration.' });
  } else if (dkim === 'pass') {
    findings.push({ severity: 'Low', finding: 'DKIM signature verified.', recommendation: 'Email payload integrity is intact.' });
  } else {
    riskScore += 10;
    findings.push({ severity: 'Medium', finding: 'No DKIM signature detected.', recommendation: 'Enable DKIM signing for outgoing domain email.' });
  }

  if (dmarc === 'fail') {
    riskScore += 40;
    findings.push({ severity: 'Critical', finding: 'DMARC policy alignment failed.', recommendation: 'Audit SPF and DKIM domain alignment.' });
  } else if (dmarc === 'pass') {
    findings.push({ severity: 'Low', finding: 'DMARC alignment verified.', recommendation: 'Domain is actively protected against spoofing.' });
  } else {
    riskScore += 10;
    findings.push({ severity: 'Medium', finding: 'DMARC policy missing or unapplied.', recommendation: 'Enforce DMARC policy (p=reject or p=quarantine).' });
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
          finding: `Domain Mismatch: From (${fromDomain}) differs from Return-Path (${returnDomain})`,
          recommendation: 'High risk of email spoofing. Treat sender with caution.'
        });
      }
    }
  }

  if (lowerText.includes('mailed-by:') || lowerText.includes('signed-by:')) {
    findings.push({
      severity: 'Info',
      finding: 'Parsed layout from Printed Email PDF (Gmail/Webmail print headers).',
      recommendation: 'Successfully extracted email verification fields from document text.'
    });
  }

  let overallStatus = 'Safe';
  if (riskScore >= 70) overallStatus = 'Critical';
  else if (riskScore >= 40) overallStatus = 'High';
  else if (riskScore >= 20) overallStatus = 'Medium';
  else if (riskScore > 0) overallStatus = 'Low';

  // Ensure From, Subject, Return-Path are populated in parsedHeaders
  if (!parsedHeaders['From'] && senderEmail) parsedHeaders['From'] = fromRaw || senderEmail;
  if (!parsedHeaders['Subject'] && subject) parsedHeaders['Subject'] = subject;
  if (!parsedHeaders['Return-Path'] && returnPath) parsedHeaders['Return-Path'] = returnPath;

  return {
    sender_email: senderEmail || 'Unknown',
    return_path: returnPath || senderEmail || 'Unknown',
    recipient: recipient,
    date: date,
    message_id: messageId,
    reply_to: replyTo,
    subject: subject || 'No Subject',
    risk_score: Math.min(riskScore, 100),
    overall_status: overallStatus,
    spoof_detected: spoofDetected,
    authentication_results: { spf, dkim, dmarc, arc },
    routing_information: {
      received_chain: receivedChain,
      originating_ip: originatingIp,
      hop_count: receivedChain.length,
      parsed_hops: parsedHops
    },
    security_findings: findings,
    parsed_headers: parsedHeaders
  };
}

