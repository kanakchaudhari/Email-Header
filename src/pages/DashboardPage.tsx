import React, { useEffect, useState, useMemo } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
    ShieldAlert, ShieldCheck, Shield, AlertTriangle, ArrowLeft, Mail, 
    AlertOctagon, Network, FileText, Copy, Check, Search, Server, 
    Clock, ChevronDown, ChevronUp, RefreshCw, UserCheck, Send
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { supabase } from '../lib/supabase';
import { toast } from 'sonner';
import { parseEmailText } from '../lib/emailParser';

const getRiskColor = (status: string) => {
    switch(status) {
        case 'Safe': return 'text-green-600 bg-green-50 border-green-200';
        case 'Low': return 'text-blue-600 bg-blue-50 border-blue-200';
        case 'Medium': return 'text-amber-500 bg-amber-50 border-amber-200';
        case 'High': return 'text-orange-600 bg-orange-50 border-orange-200';
        case 'Critical': return 'text-red-600 bg-red-50 border-red-200';
        default: return 'text-slate-600 bg-slate-50 border-slate-200';
    }
};

const getStatusIcon = (status: string) => {
    switch(status?.toLowerCase()) {
        case 'pass': return <ShieldCheck className="text-green-600 h-6 w-6" />;
        case 'fail': return <ShieldAlert className="text-red-600 h-6 w-6" />;
        case 'softfail': return <AlertTriangle className="text-orange-500 h-6 w-6" />;
        case 'neutral': return <Shield className="text-amber-500 h-6 w-6" />;
        default: return <Shield className="text-slate-400 h-6 w-6" />;
    }
};

const getAuthExplanation = (mech: string, status: string) => {
    const s = status?.toLowerCase() || 'unknown';
    switch(mech) {
        case 'spf':
            if (s === 'pass') return 'Sender IP is explicitly authorized in the domain SPF DNS record.';
            if (s === 'fail') return 'Sender IP is NOT authorized in the domain SPF DNS record.';
            if (s === 'softfail') return 'Sender IP is not explicitly authorized (transitioning policy).';
            return 'SPF record status could not be definitively verified from headers.';
        case 'dkim':
            if (s === 'pass') return 'Digital signature is valid and email body/headers were not tampered with.';
            if (s === 'fail') return 'DKIM cryptographic signature verification failed or signature was modified.';
            return 'No valid DKIM signature header was detected in the email.';
        case 'dmarc':
            if (s === 'pass') return 'DMARC alignment passed (Header From matches SPF/DKIM domains).';
            if (s === 'fail') return 'DMARC alignment failed. Email domain does not match SPF/DKIM.';
            return 'No strict DMARC policy evaluation found in header results.';
        case 'arc':
            if (s === 'pass') return 'Authenticated Received Chain verified for multi-hop mail forwarding.';
            if (s === 'fail') return 'ARC validation failed across intermediary mail servers.';
            return 'No ARC headers present or intermediary forwarding not detected.';
        default:
            return '';
    }
};

export default function DashboardPage() {
    const location = useLocation();
    const navigate = useNavigate();
    const { result: stateResult, rawHeaders } = location.state || {};
    
    const [saved, setSaved] = useState(false);
    const [activeTab, setActiveTab] = useState<'parsed' | 'raw'>('parsed');
    const [searchHeader, setSearchHeader] = useState('');
    const [copied, setCopied] = useState(false);
    const [expandedHops, setExpandedHops] = useState<Record<number, boolean>>({});

    // Compute full comprehensive analysis result (restores missing hop/header details if loaded from history)
    const result = useMemo(() => {
        if (!stateResult && !rawHeaders) return null;
        
        let res = stateResult;
        
        // If loaded from database history or missing detailed hops/headers, re-parse from rawHeaders if available
        if (rawHeaders && rawHeaders.trim()) {
            const reParsed = parseEmailText(rawHeaders);
            if (!res) {
                res = reParsed;
            } else {
                res = {
                    ...reParsed,
                    ...res,
                    parsed_headers: Object.keys(res.parsed_headers || {}).length > 0 ? res.parsed_headers : reParsed.parsed_headers,
                    routing_information: {
                        ...reParsed.routing_information,
                        ...(res.routing_information || {})
                    }
                };
            }
        }
        return res;
    }, [stateResult, rawHeaders]);

    useEffect(() => {
        if (!result) {
            navigate('/');
        } else if (!saved && stateResult) {
            saveAnalysis();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [result, saved]);

    const saveAnalysis = async () => {
        if (!result) return;
        try {
            const { data, error } = await supabase.from('email_analysis').insert({
                sender_email: result.sender_email || 'Unknown',
                return_path: result.return_path || result.sender_email || 'Unknown',
                subject: result.subject || 'No Subject',
                risk_score: typeof result.risk_score === 'number' ? result.risk_score : 0,
                overall_status: result.overall_status || 'Safe',
                spoof_detected: !!result.spoof_detected,
                raw_header: rawHeaders || ''
            }).select('id').single();

            if (error) throw error;
            
            const analysisId = data.id;

            await supabase.from('authentication_results').insert({
                analysis_id: analysisId,
                spf_status: result.authentication_results?.spf || 'unknown',
                dkim_status: result.authentication_results?.dkim || 'unknown',
                dmarc_status: result.authentication_results?.dmarc || 'unknown',
                arc_status: result.authentication_results?.arc || 'unknown'
            });

            await supabase.from('routing_information').insert({
                analysis_id: analysisId,
                received_chain: result.routing_information?.received_chain || [],
                originating_ip: result.routing_information?.originating_ip || 'Unknown',
                hop_count: result.routing_information?.hop_count || 0
            });

            if (result.security_findings && Array.isArray(result.security_findings) && result.security_findings.length > 0) {
                const findingsToInsert = result.security_findings.map((f: any) => ({
                    analysis_id: analysisId,
                    severity: f.severity || 'Info',
                    finding: f.finding || '',
                    recommendation: f.recommendation || ''
                }));
                await supabase.from('security_findings').insert(findingsToInsert);
            }

            setSaved(true);
            toast.success('Analysis saved to history');
        } catch (err: any) {
            console.error('Failed to save analysis', err);
            // Non-blocking toast if DB is optional or offline
        }
    };

    const copyRawHeaders = () => {
        if (!rawHeaders) return;
        navigator.clipboard.writeText(rawHeaders);
        setCopied(true);
        toast.success('Raw email headers copied to clipboard');
        setTimeout(() => setCopied(false), 2000);
    };

    const toggleHopExpand = (hopIndex: number) => {
        setExpandedHops(prev => ({ ...prev, [hopIndex]: !prev[hopIndex] }));
    };

    if (!result) return null;

    const riskData = [
        { name: 'Risk', value: result.risk_score },
        { name: 'Safe', value: Math.max(0, 100 - result.risk_score) }
    ];
    
    const COLORS = [result.risk_score >= 70 ? '#EF4444' : result.risk_score >= 40 ? '#F59E0B' : '#22C55E', '#E2E8F0'];

    // Header key-value filtering
    const headersList = Object.entries(result.parsed_headers || {}).map(([key, val]) => ({
        key,
        value: typeof val === 'string' ? val : Array.isArray(val) ? val.join('\n') : JSON.stringify(val)
    }));

    const filteredHeaders = headersList.filter(h => 
        h.key.toLowerCase().includes(searchHeader.toLowerCase()) || 
        h.value.toLowerCase().includes(searchHeader.toLowerCase())
    );

    const hops = result.routing_information?.parsed_hops || [];
    const receivedChain = result.routing_information?.received_chain || [];

    return (
        <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex flex-col space-y-6 pb-12"
        >
            {/* Top Navigation & Quick Actions */}
            <div className="flex flex-wrap items-center justify-between gap-4 border-b pb-4">
                <div className="flex items-center space-x-4">
                    <Link to="/" className="p-2 border rounded-lg bg-white hover:bg-slate-100 transition-colors shadow-xs">
                        <ArrowLeft size={18} className="text-slate-700" />
                    </Link>
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight text-slate-900">Analysis Dashboard</h1>
                        <p className="text-slate-500 text-sm">Comprehensive security overview, authentication breakdown, routing chain & raw headers.</p>
                    </div>
                </div>

                <div className="flex items-center space-x-2">
                    {rawHeaders && (
                        <button
                            onClick={copyRawHeaders}
                            className="flex items-center space-x-1.5 px-3 py-2 text-sm bg-white border border-slate-300 rounded-lg hover:bg-slate-50 transition-all text-slate-700 font-medium shadow-xs"
                        >
                            {copied ? <Check size={16} className="text-green-600" /> : <Copy size={16} className="text-slate-600" />}
                            <span>{copied ? 'Copied' : 'Copy Headers'}</span>
                        </button>
                    )}
                    <button
                        onClick={() => navigate('/')}
                        className="flex items-center space-x-1.5 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-all shadow-xs"
                    >
                        <RefreshCw size={16} />
                        <span>Analyze New Header</span>
                    </button>
                </div>
            </div>

            {/* Row 1: Overview Cards */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Risk Score Card */}
                <div className="lg:col-span-1 bg-white rounded-xl border shadow-sm p-6 flex flex-col items-center justify-between relative overflow-hidden">
                    <div className="w-full flex items-center justify-between border-b pb-3">
                        <h3 className="text-lg font-bold text-slate-900">Overall Risk Score</h3>
                        <span className={`px-3 py-1 rounded-full border text-xs font-bold ${getRiskColor(result.overall_status)}`}>
                            {result.overall_status} Risk
                        </span>
                    </div>

                    <div className="w-48 h-48 relative my-4">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={riskData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={65}
                                    outerRadius={85}
                                    startAngle={180}
                                    endAngle={0}
                                    dataKey="value"
                                >
                                    {riskData.map((_, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                    ))}
                                </Pie>
                            </PieChart>
                        </ResponsiveContainer>
                        <div className="absolute inset-0 flex flex-col items-center justify-center pb-6">
                            <span className="text-4xl font-extrabold text-slate-900">{result.risk_score}</span>
                            <span className="text-xs text-slate-500 font-medium">/ 100 Risk Score</span>
                        </div>
                    </div>

                    {/* Spoofing Warning Badge */}
                    {result.spoof_detected ? (
                        <div className="w-full bg-red-50 border border-red-200 rounded-lg p-3 text-red-800 text-xs flex items-start space-x-2">
                            <AlertTriangle className="text-red-600 shrink-0 mt-0.5" size={16} />
                            <div>
                                <span className="font-bold block">Spoofing Warning Detected</span>
                                Declared sender domain differs from actual return-path domain without valid SPF pass.
                            </div>
                        </div>
                    ) : (
                        <div className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-center text-xs text-slate-600 font-medium">
                            {result.risk_score === 0 ? 'No security anomalies detected.' : 'Calculated based on SPF, DKIM, DMARC & domain alignment.'}
                        </div>
                    )}
                </div>

                {/* Sender & Recipient Metadata Card */}
                <div className="lg:col-span-2 bg-white rounded-xl border shadow-sm p-6 flex flex-col justify-between">
                    <h3 className="text-lg font-bold flex items-center border-b pb-3 text-slate-900">
                        <Mail className="mr-2 h-5 w-5 text-blue-600" /> Header Overview & Sender Information
                    </h3>
                    
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4">
                        <div className="space-y-1">
                            <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider flex items-center">
                                <Send size={13} className="mr-1 text-slate-400" /> Declared Sender (From)
                            </p>
                            <p className="font-mono text-xs break-all bg-slate-50 p-2.5 rounded-lg border text-slate-800 font-medium">
                                {result.sender_email || 'None'}
                            </p>
                        </div>

                        <div className="space-y-1">
                            <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider flex items-center">
                                <UserCheck size={13} className="mr-1 text-slate-400" /> Actual Sender (Return-Path)
                            </p>
                            <p className="font-mono text-xs break-all bg-slate-50 p-2.5 rounded-lg border text-slate-800 font-medium">
                                {result.return_path || 'None'}
                            </p>
                        </div>

                        {result.recipient && (
                            <div className="space-y-1">
                                <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider">Recipient (To)</p>
                                <p className="font-mono text-xs break-all bg-slate-50 p-2 rounded-lg border text-slate-800">
                                    {result.recipient}
                                </p>
                            </div>
                        )}

                        <div className="space-y-1">
                            <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider">Subject</p>
                            <p className="text-xs font-semibold bg-slate-50 p-2.5 rounded-lg border text-slate-900 truncate">
                                {result.subject || 'No Subject'}
                            </p>
                        </div>

                        <div className="space-y-1">
                            <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider flex items-center">
                                <Server size={13} className="mr-1 text-slate-400" /> Originating IP
                            </p>
                            <p className="font-mono text-xs bg-slate-50 p-2 rounded-lg border text-slate-800 inline-block font-semibold">
                                {result.routing_information?.originating_ip || 'Unknown'}
                            </p>
                        </div>

                        <div className="space-y-1">
                            <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider flex items-center">
                                <Network size={13} className="mr-1 text-slate-400" /> Routing Hops Traversed
                            </p>
                            <div className="flex items-center space-x-2 pt-0.5">
                                <span className="px-3 py-1 bg-blue-50 text-blue-700 border border-blue-200 rounded-md font-bold text-xs">
                                    {result.routing_information?.hop_count || hops.length || 0} Hops Recorded
                                </span>
                            </div>
                        </div>

                        {result.date && (
                            <div className="sm:col-span-2 space-y-1">
                                <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider flex items-center">
                                    <Clock size={13} className="mr-1 text-slate-400" /> Timestamp (Date)
                                </p>
                                <p className="font-mono text-xs bg-slate-50 p-2 rounded-lg border text-slate-700">
                                    {result.date}
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Row 2: Authentication Mechanisms */}
            <div>
                <h3 className="text-xl font-bold text-slate-900 mb-3 flex items-center">
                    <ShieldCheck className="mr-2 text-blue-600" size={22} /> Authentication Mechanisms Breakdown
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {['spf', 'dkim', 'dmarc', 'arc'].map((mech) => {
                        const status = (result.authentication_results as any)?.[mech] || 'unknown';
                        const upperStatus = status.toUpperCase();
                        const isPass = status === 'pass';
                        const isFail = status === 'fail' || status === 'softfail';

                        return (
                            <div key={mech} className="bg-white rounded-xl border shadow-sm p-4 flex flex-col justify-between space-y-3 hover:border-slate-300 transition-all">
                                <div className="flex items-center justify-between border-b pb-2">
                                    <div className="flex items-center space-x-2">
                                        {getStatusIcon(status)}
                                        <h4 className="uppercase font-bold tracking-wider text-sm text-slate-800">{mech}</h4>
                                    </div>
                                    <span className={`px-2.5 py-1 text-xs rounded-md font-bold border uppercase ${
                                        isPass ? 'bg-green-50 text-green-700 border-green-200' : 
                                        isFail ? 'bg-red-50 text-red-700 border-red-200' : 
                                        'bg-slate-50 text-slate-600 border-slate-200'
                                    }`}>
                                        {upperStatus}
                                    </span>
                                </div>
                                <p className="text-xs text-slate-600 leading-relaxed font-normal">
                                    {getAuthExplanation(mech, status)}
                                </p>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Row 3: Security Findings Table */}
            {result.security_findings && result.security_findings.length > 0 && (
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                    <div className="bg-slate-50 p-4 border-b flex items-center space-x-2">
                        <AlertOctagon className="text-amber-600" size={20} />
                        <h3 className="text-lg font-bold text-slate-900">Security Findings & Recommendations</h3>
                        <span className="ml-auto text-xs bg-slate-200 text-slate-700 px-2 py-0.5 rounded-full font-semibold">
                            {result.security_findings.length} findings
                        </span>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm text-left">
                            <thead className="bg-slate-100/70 text-slate-700 border-b text-xs uppercase font-semibold">
                                <tr>
                                    <th className="px-4 py-3 w-28">Severity</th>
                                    <th className="px-4 py-3">Security Finding</th>
                                    <th className="px-4 py-3">Recommended Action</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {result.security_findings.map((finding: any, i: number) => (
                                    <tr key={i} className="hover:bg-slate-50/70 transition-colors">
                                        <td className="px-4 py-3 align-top">
                                            <span className={`px-2.5 py-1 text-xs rounded-md font-bold inline-block ${
                                                finding.severity === 'Critical' ? 'bg-red-100 text-red-800 border border-red-200' :
                                                finding.severity === 'High' ? 'bg-orange-100 text-orange-800 border border-orange-200' :
                                                finding.severity === 'Medium' ? 'bg-amber-100 text-amber-800 border border-amber-200' :
                                                finding.severity === 'Low' ? 'bg-blue-100 text-blue-800 border border-blue-200' :
                                                'bg-slate-100 text-slate-700'
                                            }`}>
                                                {finding.severity}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 font-semibold text-slate-900 align-top">{finding.finding}</td>
                                        <td className="px-4 py-3 text-slate-600 align-top text-xs leading-relaxed">{finding.recommendation}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Row 4: Email Routing & Network Hops Section */}
            <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-3">
                    <h3 className="text-xl font-bold text-slate-900 flex items-center">
                        <Network className="mr-2 text-blue-600" size={22} /> Network Hop Traversal & Routing Chain
                    </h3>
                    <span className="text-xs text-slate-500 font-mono bg-slate-100 px-2.5 py-1 rounded-md border font-semibold">
                        {hops.length || receivedChain.length} Hops Detected
                    </span>
                </div>

                {hops.length > 0 ? (
                    <div className="space-y-3 mt-2">
                        {hops.map((hop: any) => {
                            const isExpanded = !!expandedHops[hop.hop];
                            return (
                                <div key={hop.hop} className="border rounded-lg p-3.5 bg-slate-50/50 hover:bg-slate-50 transition-all text-xs space-y-2">
                                    <div className="flex flex-wrap items-center justify-between gap-2">
                                        <div className="flex items-center space-x-2">
                                            <span className="px-2 py-0.5 rounded bg-blue-600 text-white font-bold font-mono text-[11px]">
                                                Hop #{hop.hop}
                                            </span>
                                            <span className="font-semibold text-slate-900 font-mono text-xs">
                                                {hop.from}
                                            </span>
                                        </div>

                                        <div className="flex items-center space-x-2 text-slate-500">
                                            {hop.ip !== 'N/A' && (
                                                <span className="font-mono bg-white px-2 py-0.5 rounded border text-slate-700 font-semibold">
                                                    IP: {hop.ip}
                                                </span>
                                            )}
                                            <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-semibold">
                                                {hop.withProtocol}
                                            </span>
                                            <button 
                                                onClick={() => toggleHopExpand(hop.hop)}
                                                className="text-slate-500 hover:text-slate-800 p-1 rounded hover:bg-slate-200 transition-colors"
                                                title="Toggle Raw Received Header"
                                            >
                                                {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                                            </button>
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-slate-600 border-t border-slate-200/60">
                                        <div>
                                            <span className="text-slate-400 font-medium">Received By: </span>
                                            <span className="font-mono text-slate-800 font-semibold">{hop.by}</span>
                                        </div>
                                        <div>
                                            <span className="text-slate-400 font-medium">Timestamp: </span>
                                            <span className="font-mono text-slate-800">{hop.date}</span>
                                        </div>
                                    </div>

                                    {isExpanded && (
                                        <motion.div 
                                            initial={{ opacity: 0, height: 0 }}
                                            animate={{ opacity: 1, height: 'auto' }}
                                            className="mt-2 p-2.5 bg-slate-900 text-slate-200 rounded font-mono text-[11px] break-all"
                                        >
                                            <span className="text-blue-400 font-bold">Received: </span>
                                            {hop.raw}
                                        </motion.div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                ) : receivedChain.length > 0 ? (
                    <div className="space-y-2">
                        {receivedChain.map((rawRec: string, idx: number) => (
                            <div key={idx} className="p-3 border rounded-lg bg-slate-50 font-mono text-xs text-slate-800 break-all">
                                <span className="font-bold text-blue-600 mr-2">Hop #{idx + 1}:</span>
                                {rawRec}
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="p-4 bg-slate-50 rounded-lg border text-center text-xs text-slate-500">
                        No intermediate Received hop headers detected. (Common for direct webmail inputs or printed PDF email exports).
                    </div>
                )}
            </div>

            {/* Row 5: Parsed Headers & Raw Header Details Explorer */}
            <div className="bg-white rounded-xl border shadow-sm overflow-hidden">
                <div className="bg-slate-50 border-b p-4 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center space-x-2">
                        <FileText className="text-blue-600" size={20} />
                        <h3 className="text-lg font-bold text-slate-900">Header Inspection & Explorer</h3>
                    </div>

                    <div className="flex items-center space-x-2 bg-slate-200/80 p-1 rounded-lg">
                        <button
                            onClick={() => setActiveTab('parsed')}
                            className={`px-3 py-1.5 text-xs font-bold rounded-md transition-all ${
                                activeTab === 'parsed' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                            }`}
                        >
                            Parsed Key-Value Headers ({headersList.length})
                        </button>
                        <button
                            onClick={() => setActiveTab('raw')}
                            className={`px-3 py-1.5 text-xs font-bold rounded-md transition-all ${
                                activeTab === 'raw' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                            }`}
                        >
                            Raw Email Headers
                        </button>
                    </div>
                </div>

                {activeTab === 'parsed' ? (
                    <div className="p-4 space-y-4">
                        <div className="relative">
                            <Search className="absolute left-3 top-2.5 text-slate-400" size={16} />
                            <input 
                                type="text" 
                                value={searchHeader} 
                                onChange={(e) => setSearchHeader(e.target.value)}
                                placeholder="Search headers by field name or value (e.g. DKIM, Return-Path, Date)..." 
                                className="w-full pl-9 pr-4 py-2 border text-xs rounded-lg bg-slate-50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                        </div>

                        <div className="border rounded-lg overflow-x-auto max-h-96">
                            <table className="w-full text-xs text-left">
                                <thead className="bg-slate-100 text-slate-700 font-semibold border-b uppercase sticky top-0">
                                    <tr>
                                        <th className="px-4 py-2.5 w-1/4">Header Field</th>
                                        <th className="px-4 py-2.5">Header Value</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100 font-mono">
                                    {filteredHeaders.length === 0 ? (
                                        <tr>
                                            <td colSpan={2} className="px-4 py-6 text-center text-slate-500 font-sans">
                                                No header fields matching "{searchHeader}"
                                            </td>
                                        </tr>
                                    ) : (
                                        filteredHeaders.map((h, i) => (
                                            <tr key={i} className="hover:bg-slate-50/80 transition-colors">
                                                <td className="px-4 py-2.5 font-bold text-blue-900 align-top break-all bg-slate-50/50">
                                                    {h.key}
                                                </td>
                                                <td className="px-4 py-2.5 text-slate-800 break-all whitespace-pre-wrap leading-relaxed">
                                                    {h.value}
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ) : (
                    <div className="p-4 space-y-3">
                        <div className="flex items-center justify-between text-xs text-slate-500">
                            <span>Raw Header Payload ({rawHeaders?.length || 0} characters)</span>
                            {rawHeaders && (
                                <button
                                    onClick={copyRawHeaders}
                                    className="flex items-center space-x-1 text-blue-600 hover:underline font-semibold"
                                >
                                    <Copy size={14} />
                                    <span>Copy Raw Text</span>
                                </button>
                            )}
                        </div>
                        <pre className="p-4 bg-slate-900 text-slate-100 rounded-lg font-mono text-xs overflow-x-auto max-h-96 whitespace-pre-wrap leading-relaxed">
                            {rawHeaders || 'No raw header text provided.'}
                        </pre>
                    </div>
                )}
            </div>
        </motion.div>
    );
}

