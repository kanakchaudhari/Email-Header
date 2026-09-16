-- Supabase Migration: Initial Schema for Email Header Analyzer

-- 1. Create email_analysis table
CREATE TABLE IF NOT EXISTS email_analysis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    sender_email TEXT,
    return_path TEXT,
    subject TEXT,
    risk_score INTEGER,
    overall_status TEXT,
    spoof_detected BOOLEAN,
    raw_header TEXT
);

-- 2. Create authentication_results table
CREATE TABLE IF NOT EXISTS authentication_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES email_analysis(id) ON DELETE CASCADE,
    spf_status TEXT,
    dkim_status TEXT,
    dmarc_status TEXT,
    arc_status TEXT
);

-- 3. Create routing_information table
CREATE TABLE IF NOT EXISTS routing_information (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES email_analysis(id) ON DELETE CASCADE,
    received_chain JSONB,
    originating_ip TEXT,
    hop_count INTEGER
);

-- 4. Create security_findings table
CREATE TABLE IF NOT EXISTS security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES email_analysis(id) ON DELETE CASCADE,
    severity TEXT,
    finding TEXT,
    recommendation TEXT
);

-- Enable Row Level Security (RLS)
ALTER TABLE email_analysis ENABLE ROW LEVEL SECURITY;
ALTER TABLE authentication_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_information ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_findings ENABLE ROW LEVEL SECURITY;

-- Allow anonymous read and insert for the sake of the demo
-- (In a real scenario with full auth, this would be restricted to authenticated users)
CREATE POLICY "Enable read access for all users" ON email_analysis FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON email_analysis FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable delete access for all users" ON email_analysis FOR DELETE USING (true);

CREATE POLICY "Enable read access for all users" ON authentication_results FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON authentication_results FOR INSERT WITH CHECK (true);

CREATE POLICY "Enable read access for all users" ON routing_information FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON routing_information FOR INSERT WITH CHECK (true);

CREATE POLICY "Enable read access for all users" ON security_findings FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON security_findings FOR INSERT WITH CHECK (true);
