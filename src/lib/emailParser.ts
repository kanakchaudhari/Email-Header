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

export function decodeMimeHeader(headerStr: string): string {
  if (!headerStr) return '';
  return headerStr.replace(/=\?([^?]+)\?([QBqb])\?([^?]+)\?=/gi, (match, charset, encoding, text) => {
    try {
      const enc = encoding.toUpperCase();
      if (enc === 'Q') {
        const str = text.replace(/_/g, ' ');
        const bytes: number[] = [];
        for (let i = 0; i < str.length; i++) {
          if (str[i] === '=' && i + 2 < str.length) {
            const hex = str.substring(i + 1, i + 3);
            const byte = parseInt(hex, 16);
            if (!isNaN(byte)) {
              bytes.push(byte);
              i += 2;
              continue;
            }
          }
          bytes.push(str.charCodeAt(i));
        }
        return new TextDecoder(charset || 'utf-8').decode(new Uint8Array(bytes));
      } else if (enc === 'B') {
        const binary = atob(text);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        return new TextDecoder(charset || 'utf-8').decode(bytes);
      }
    } catch {
      return match;
    }
    return match;
  });
}

function getRootDomain(domain: string): string {
  if (!domain) return '';
  const parts = domain.toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return domain.toLowerCase();
  return parts.slice(-2).join('.');
}

export function parseEmailText(rawText: string): AnalysisResult {
  const text = rawText.trim();
  
  // Extract Header Section if double newline is present (e.g. .eml format with body)
  const doubleNewlineIdx = text.search(/\r?\n\r?\n/);
  const headerText = doubleNewlineIdx !== -1 ? text.substring(0, doubleNewlineIdx) : text;
  const lowerHeaderText = headerText.toLowerCase();

  // 0. PARSE ALL KEY-VALUE HEADERS
  const unfoldedText = headerText.replace(/\r?\n[ \t]+/g, ' ');
  const headerLines = unfoldedText.split(/\r?\n/);
  const parsedHeaders: Record<string, string> = {};

  for (const line of headerLines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.substring(0, colonIdx).trim();
      const val = decodeMimeHeader(line.substring(colonIdx + 1).trim());
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
    const subjMatch = headerText.match(/(?:Subject|subject):\s*([^\n\r]+)/i);
    if (subjMatch) {
      subject = decodeMimeHeader(subjMatch[1].trim());
    } else {
      const gmailSubjMatch = headerText.match(/Gmail\s*-\s*([^\n\r]+)/i);
      if (gmailSubjMatch) {
        subject = decodeMimeHeader(gmailSubjMatch[1].trim());
      }
    }
  }
  if (!subject && headerLines.length > 0) {
    if (!headerLines[0].includes(":") && !headerLines[0].includes("@")) {
      subject = decodeMimeHeader(headerLines[0]);
    }
  }

  // 2. EXTRACT FROM (DECLARED SENDER)
  let fromRaw = parsedHeaders['From'] || parsedHeaders['from'] || "";
  if (!fromRaw) {
    const fromMatch = headerText.match(/(?:From|from):\s*([^\n\r]+)/);
    if (fromMatch) {
      fromRaw = decodeMimeHeader(fromMatch[1].trim());
    } else {
      for (const line of headerLines.slice(0, 15)) {
        if (line.includes("<") && line.includes(">") && line.includes("@") && !line.toLowerCase().startsWith("to:")) {
          fromRaw = decodeMimeHeader(line);
          break;
        }
      }
      if (!fromRaw) {
        const allEmails = headerText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
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
    const rpMatch = headerText.match(/(?:Return-Path|return-path):\s*<?([^>\s\n\r]+)>?/i);
    if (rpMatch) {
      returnPathRaw = rpMatch[1].trim();
    } else {
      const mailedMatch = headerText.match(/mailed-by:\s*([^\s\n\r]+)/i);
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
  const spfHeader = parsedHeaders['Received-SPF'] || parsedHeaders['received-spf'] || '';
  const authHeader = parsedHeaders['Authentication-Results'] || parsedHeaders['authentication-results'] || parsedHeaders['ARC-Authentication-Results'] || '';
  
  const spfValMatch = (spfHeader + ' ' + authHeader + ' ' + headerText).match(/spf=([^\s;()]+)/i) || 
                      (spfHeader + ' ' + headerText).match(/Received-SPF:\s*([a-z]+)/i) ||
                      lowerHeaderText.match(/spf:\s*([a-z]+)/i);
  if (spfValMatch) {
    const val = spfValMatch[1].toLowerCase();
    if (['pass', 'fail', 'softfail', 'neutral', 'none'].includes(val)) {
      spf = val;
    }
  }
  if (spf === 'unknown') {
    if (lowerHeaderText.includes('mailed-by:') || lowerHeaderText.includes('spf=pass') || lowerHeaderText.includes('spf: pass') || lowerHeaderText.includes('received-spf: pass')) {
      spf = 'pass';
    } else if (lowerHeaderText.includes('spf=fail') || lowerHeaderText.includes('spf: fail') || lowerHeaderText.includes('received-spf: fail')) {
      spf = 'fail';
    } else if (lowerHeaderText.includes('spf=softfail') || lowerHeaderText.includes('spf: softfail')) {
      spf = 'softfail';
    }
  }

  let dkim = 'unknown';
  const dkimValMatch = (authHeader + ' ' + headerText).match(/dkim=([^\s;()]+)/i) || lowerHeaderText.match(/dkim:\s*([a-z]+)/i);
  if (dkimValMatch) {
    const val = dkimValMatch[1].toLowerCase();
    if (['pass', 'fail', 'neutral', 'none'].includes(val)) {
      dkim = val;
    }
  }
  if (dkim === 'unknown') {
    if (parsedHeaders['DKIM-Signature'] || parsedHeaders['dkim-signature'] || lowerHeaderText.includes('signed-by:') || lowerHeaderText.includes('dkim=pass') || lowerHeaderText.includes('dkim: pass')) {
      dkim = 'pass';
    } else if (lowerHeaderText.includes('dkim=fail') || lowerHeaderText.includes('dkim: fail')) {
      dkim = 'fail';
    }
  }

  let dmarc = 'unknown';
  const dmarcValMatch = (authHeader + ' ' + headerText).match(/dmarc=([^\s;()]+)/i) || lowerHeaderText.match(/dmarc:\s*([a-z]+)/i);
  if (dmarcValMatch) {
    const val = dmarcValMatch[1].toLowerCase();
    if (['pass', 'fail', 'none'].includes(val)) {
      dmarc = val;
    }
  }
  if (dmarc === 'unknown') {
    if (lowerHeaderText.includes('dmarc=pass') || lowerHeaderText.includes('dmarc: pass') || (lowerHeaderText.includes('mailed-by:') && lowerHeaderText.includes('signed-by:'))) {
      dmarc = 'pass';
    } else if (lowerHeaderText.includes('dmarc=fail') || lowerHeaderText.includes('dmarc: fail')) {
      dmarc = 'fail';
    }
  }

  let arc = 'unknown';
  const arcValMatch = (authHeader + ' ' + headerText).match(/arc=([^\s;()]+)/i);
  if (arcValMatch) {
    const val = arcValMatch[1].toLowerCase();
    if (['pass', 'fail', 'none'].includes(val)) {
      arc = val;
    }
  }
  if (arc === 'unknown') {
    if (parsedHeaders['ARC-Seal'] || parsedHeaders['ARC-Message-Signature'] || lowerHeaderText.includes('arc=pass') || lowerHeaderText.includes('security:') || lowerHeaderText.includes('tls')) {
      arc = 'pass';
    }
  }

  // 5. ROUTING & IP PARSING
  const receivedChain: string[] = [];
  const recMatches = headerText.match(/Received:[^\n\r]+(?:\n\s+[^\n\r]+)*/gi);
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

  const allIps = headerText.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [];
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
    const rootFrom = getRootDomain(fromDomain);
    const rootReturn = getRootDomain(returnDomain);

    if (rootFrom && rootReturn && rootFrom !== rootReturn && !fromDomain.includes(returnDomain) && !returnDomain.includes(fromDomain)) {
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

  if (lowerHeaderText.includes('mailed-by:') || lowerHeaderText.includes('signed-by:')) {
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


