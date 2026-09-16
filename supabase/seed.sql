-- Supabase Seed Data for Email Header Analyzer

-- 1. Insert sample analysis 1 (High Risk / Phishing)
INSERT INTO email_analysis (
    id, created_at, sender_email, return_path, subject, risk_score, overall_status, spoof_detected, raw_header
) VALUES (
    '11111111-1111-4111-a111-111111111111',
    NOW() - INTERVAL '2 hours',
    'support@secure-paypal-verify.com',
    'bounce@fake-mailer.net',
    'URGENT: Security Alert - Verify Your Account Now',
    85,
    'High Risk',
    true,
    'Received: from mail.fake-mailer.net (mail.fake-mailer.net [192.0.2.45]) by mx.google.com...'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO authentication_results (id, analysis_id, spf_status, dkim_status, dmarc_status, arc_status)
VALUES (
    '11111111-1111-4111-a111-111111111112',
    '11111111-1111-4111-a111-111111111111',
    'fail', 'fail', 'fail', 'none'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO routing_information (id, analysis_id, received_chain, originating_ip, hop_count)
VALUES (
    '11111111-1111-4111-a111-111111111113',
    '11111111-1111-4111-a111-111111111111',
    '[{"from": "mail.fake-mailer.net", "by": "mx.google.com", "delay": "2s", "ip": "192.0.2.45"}]'::jsonb,
    '192.0.2.45',
    3
) ON CONFLICT (id) DO NOTHING;

INSERT INTO security_findings (id, analysis_id, severity, finding, recommendation)
VALUES 
('11111111-1111-4111-a111-111111111114', '11111111-1111-4111-a111-111111111111', 'Critical', 'SPF alignment failed. From header domain does not match Return-Path.', 'Do not click links in this email. Block sender domain.'),
('11111111-1111-4111-a111-111111111115', '11111111-1111-4111-a111-111111111111', 'High', 'DKIM signature verification failed.', 'Treat email content as untrusted.'),
('11111111-1111-4111-a111-111111111116', '11111111-1111-4111-a111-111111111111', 'Medium', 'DMARC policy failed for domain secure-paypal-verify.com.', 'Quarantine or reject messages from unauthenticated senders.')
ON CONFLICT (id) DO NOTHING;

-- 2. Insert sample analysis 2 (Low Risk / Legitimate)
INSERT INTO email_analysis (
    id, created_at, sender_email, return_path, subject, risk_score, overall_status, spoof_detected, raw_header
) VALUES (
    '22222222-2222-4222-a222-222222222222',
    NOW() - INTERVAL '1 day',
    'notifications@github.com',
    'noreply@github.com',
    '[GitHub] Security advisory published for package express',
    10,
    'Safe',
    false,
    'Received: from out-21.smtp.github.com (out-21.smtp.github.com [192.30.252.21]) by mx.google.com...'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO authentication_results (id, analysis_id, spf_status, dkim_status, dmarc_status, arc_status)
VALUES (
    '22222222-2222-4222-a222-222222222223',
    '22222222-2222-4222-a222-222222222222',
    'pass', 'pass', 'pass', 'pass'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO routing_information (id, analysis_id, received_chain, originating_ip, hop_count)
VALUES (
    '22222222-2222-4222-a222-222222222224',
    '22222222-2222-4222-a222-222222222222',
    '[{"from": "out-21.smtp.github.com", "by": "mx.google.com", "delay": "0s", "ip": "192.30.252.21"}]'::jsonb,
    '192.30.252.21',
    2
) ON CONFLICT (id) DO NOTHING;

INSERT INTO security_findings (id, analysis_id, severity, finding, recommendation)
VALUES 
('22222222-2222-4222-a222-222222222225', '22222222-2222-4222-a222-222222222222', 'Info', 'All authentication checks (SPF, DKIM, DMARC) passed cleanly.', 'No suspicious activity detected.')
ON CONFLICT DO NOTHING;
