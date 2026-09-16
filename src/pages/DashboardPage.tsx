import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Shield, AlertTriangle, ArrowLeft, Mail, Network, Search, AlertOctagon } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { supabase } from '../lib/supabase';
import { toast } from 'sonner';

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
    switch(status) {
        case 'pass': return <ShieldCheck className="text-green-600" />;
        case 'fail': return <ShieldAlert className="text-red-600" />;
        case 'softfail': return <AlertTriangle className="text-orange-500" />;
        default: return <Shield className="text-slate-400" />;
    }
};

export default function DashboardPage() {
    const location = useLocation();
    const navigate = useNavigate();
    const { result, rawHeaders } = location.state || {};
    
    const [saved, setSaved] = useState(false);

    useEffect(() => {
        if (!result) {
            navigate('/');
        } else if (!saved) {
            saveAnalysis();
        }
    }, [result]);

    const saveAnalysis = async () => {
        try {
            const { data, error } = await supabase.from('email_analysis').insert({
                sender_email: result.sender_email,
                return_path: result.return_path,
                subject: result.subject,
                risk_score: result.risk_score,
                overall_status: result.overall_status,
                spoof_detected: result.spoof_detected,
                raw_header: rawHeaders
            }).select('id').single();

            if (error) throw error;
            
            const analysisId = data.id;

            await supabase.from('authentication_results').insert({
                analysis_id: analysisId,
                spf_status: result.authentication_results.spf,
                dkim_status: result.authentication_results.dkim,
                dmarc_status: result.authentication_results.dmarc,
                arc_status: result.authentication_results.arc
            });

            await supabase.from('routing_information').insert({
                analysis_id: analysisId,
                received_chain: result.routing_information.received_chain,
                originating_ip: result.routing_information.originating_ip,
                hop_count: result.routing_information.hop_count
            });

            if (result.security_findings && result.security_findings.length > 0) {
                const findingsToInsert = result.security_findings.map((f: any) => ({
                    analysis_id: analysisId,
                    severity: f.severity,
                    finding: f.finding,
                    recommendation: f.recommendation
                }));
                await supabase.from('security_findings').insert(findingsToInsert);
            }

            setSaved(true);
            toast.success('Analysis saved to history');
        } catch (err: any) {
            console.error('Failed to save analysis', err);
            toast.error('Database save error: ' + (err.message || 'Check Supabase configuration and Anon Key'));
        }
    };

    if (!result) return null;

    const riskData = [
        { name: 'Risk', value: result.risk_score },
        { name: 'Safe', value: 100 - result.risk_score }
    ];
    
    const COLORS = [result.risk_score >= 70 ? '#EF4444' : result.risk_score >= 40 ? '#F59E0B' : '#22C55E', '#E2E8F0'];

    return (
        <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex flex-col space-y-6"
        >
            <div className="flex items-center space-x-4">
                <Link to="/" className="p-2 border rounded-md hover:bg-slate-100 transition-colors">
                    <ArrowLeft size={18} />
                </Link>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Analysis Dashboard</h1>
                    <p className="text-slate-500">Security overview and detailed breakdown of email headers.</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Risk Score Card */}
                <div className="md:col-span-1 bg-white rounded-xl border shadow-sm p-6 flex flex-col items-center justify-center relative overflow-hidden">
                    <h3 className="text-lg font-semibold w-full text-left mb-4">Overall Risk Score</h3>
                    <div className="w-48 h-48 relative">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={riskData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    startAngle={180}
                                    endAngle={0}
                                    dataKey="value"
                                >
                                    {riskData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                    ))}
                                </Pie>
                            </PieChart>
                        </ResponsiveContainer>
                        <div className="absolute inset-0 flex flex-col items-center justify-center pb-8">
                            <span className="text-4xl font-bold">{result.risk_score}</span>
                            <span className="text-sm text-slate-500">/ 100</span>
                        </div>
                    </div>
                    
                    <div className={`mt-2 px-4 py-1.5 rounded-full border font-medium ${getRiskColor(result.overall_status)}`}>
                        {result.overall_status} Risk
                    </div>
                </div>

                {/* Sender Info Card */}
                <div className="md:col-span-2 bg-white rounded-xl border shadow-sm p-6">
                    <h3 className="text-lg font-semibold flex items-center mb-4 border-b pb-2">
                        <Mail className="mr-2 h-5 w-5 text-blue-600" /> Sender Information
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="space-y-1">
                            <p className="text-sm text-slate-500 font-medium">Declared Sender (From)</p>
                            <p className="font-mono text-sm break-all bg-slate-50 p-2 rounded border">{result.sender_email || 'None'}</p>
                        </div>
                        <div className="space-y-1">
                            <p className="text-sm text-slate-500 font-medium">Actual Sender (Return-Path)</p>
                            <p className="font-mono text-sm break-all bg-slate-50 p-2 rounded border">{result.return_path || 'None'}</p>
                        </div>
                        <div className="sm:col-span-2 space-y-1">
                            <p className="text-sm text-slate-500 font-medium">Subject</p>
                            <p className="text-sm bg-slate-50 p-2 rounded border">{result.subject || 'No Subject'}</p>
                        </div>
                        <div className="sm:col-span-2 space-y-1">
                            <p className="text-sm text-slate-500 font-medium">Originating IP</p>
                            <p className="font-mono text-sm bg-slate-50 p-2 rounded border inline-block">{result.routing_information.originating_ip}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Authentication Cards */}
            <h3 className="text-xl font-bold mt-4">Authentication Mechanisms</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                {['spf', 'dkim', 'dmarc', 'arc'].map((mech) => {
                    const status = result.authentication_results[mech];
                    return (
                        <div key={mech} className="bg-white rounded-xl border shadow-sm p-4 flex flex-col items-center justify-center text-center space-y-2">
                            {getStatusIcon(status)}
                            <h4 className="uppercase font-bold tracking-wider text-sm text-slate-700">{mech}</h4>
                            <span className={`px-2 py-1 text-xs rounded font-medium border ${status === 'pass' ? 'bg-green-50 text-green-700 border-green-200' : status === 'fail' ? 'bg-red-50 text-red-700 border-red-200' : 'bg-slate-50 text-slate-600 border-slate-200'}`}>
                                {status.toUpperCase()}
                            </span>
                        </div>
                    )
                })}
            </div>

            {/* Findings */}
            {result.security_findings.length > 0 && (
                <div className="bg-white rounded-xl border border-red-200 shadow-sm overflow-hidden">
                    <div className="bg-red-50 p-4 border-b border-red-200 flex items-center space-x-2">
                        <AlertOctagon className="text-red-600" />
                        <h3 className="text-lg font-semibold text-red-900">Security Findings</h3>
                    </div>
                    <div className="p-0 overflow-x-auto">
                        <table className="w-full text-sm text-left">
                            <thead className="bg-slate-50 text-slate-600 border-b">
                                <tr>
                                    <th className="px-4 py-3 font-medium">Severity</th>
                                    <th className="px-4 py-3 font-medium">Finding</th>
                                    <th className="px-4 py-3 font-medium">Recommendation</th>
                                </tr>
                            </thead>
                            <tbody>
                                {result.security_findings.map((finding: any, i: number) => (
                                    <tr key={i} className="border-b last:border-0 hover:bg-slate-50/50">
                                        <td className="px-4 py-3">
                                            <span className={`px-2 py-1 text-xs rounded font-medium ${
                                                finding.severity === 'Critical' ? 'bg-red-100 text-red-700' :
                                                finding.severity === 'High' ? 'bg-orange-100 text-orange-700' :
                                                finding.severity === 'Medium' ? 'bg-amber-100 text-amber-700' :
                                                'bg-blue-100 text-blue-700'
                                            }`}>
                                                {finding.severity}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 font-medium text-slate-900">{finding.finding}</td>
                                        <td className="px-4 py-3 text-slate-600">{finding.recommendation}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </motion.div>
    );
}
