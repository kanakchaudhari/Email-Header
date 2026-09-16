import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { Trash2, ExternalLink, Calendar, Mail, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';

export default function HistoryPage() {
    const [history, setHistory] = useState<any[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        fetchHistory();
    }, []);

    const fetchHistory = async () => {
        setIsLoading(true);
        try {
            const { data, error } = await supabase
                .from('email_analysis')
                .select('*')
                .order('created_at', { ascending: false })
                .limit(50);
            
            if (error) throw error;
            setHistory(data || []);
        } catch (error: any) {
            console.error(error);
            toast.error('Failed to load history');
        } finally {
            setIsLoading(false);
        }
    };

    const handleDelete = async (id: string) => {
        try {
            const { error } = await supabase.from('email_analysis').delete().eq('id', id);
            if (error) throw error;
            setHistory(prev => prev.filter(item => item.id !== id));
            toast.success('Record deleted');
        } catch (error: any) {
            toast.error('Failed to delete record');
        }
    };

    const viewDetails = async (item: any) => {
        try {
            const { data: authData } = await supabase
                .from('authentication_results')
                .select('*')
                .eq('analysis_id', item.id)
                .maybeSingle();

            const { data: routeData } = await supabase
                .from('routing_information')
                .select('*')
                .eq('analysis_id', item.id)
                .maybeSingle();

            const { data: findingsData } = await supabase
                .from('security_findings')
                .select('*')
                .eq('analysis_id', item.id);

            const resultObj = {
                sender_email: item.sender_email,
                return_path: item.return_path,
                subject: item.subject,
                risk_score: item.risk_score,
                overall_status: item.overall_status,
                spoof_detected: item.spoof_detected,
                authentication_results: {
                    spf: authData?.spf_status || 'unknown',
                    dkim: authData?.dkim_status || 'unknown',
                    dmarc: authData?.dmarc_status || 'unknown',
                    arc: authData?.arc_status || 'unknown'
                },
                routing_information: {
                    received_chain: routeData?.received_chain || [],
                    originating_ip: routeData?.originating_ip || 'Unknown',
                    hop_count: routeData?.hop_count || 0
                },
                security_findings: findingsData || []
            };

            navigate('/dashboard', { state: { result: resultObj, rawHeaders: item.raw_header } });
        } catch (err: any) {
            toast.error('Failed to load analysis details');
        }
    };

    return (
        <div className="flex flex-col space-y-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Analysis History</h1>
                <p className="text-slate-500">View and manage previous email header analyses.</p>
            </div>

            <div className="bg-white border rounded-xl shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-sm text-left text-slate-600">
                        <thead className="text-xs text-slate-700 uppercase bg-slate-50 border-b">
                            <tr>
                                <th className="px-6 py-3">Date</th>
                                <th className="px-6 py-3">Subject</th>
                                <th className="px-6 py-3">Sender</th>
                                <th className="px-6 py-3 text-center">Risk Score</th>
                                <th className="px-6 py-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {isLoading ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-8 text-center text-slate-500">Loading history...</td>
                                </tr>
                            ) : history.length === 0 ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-8 text-center text-slate-500">No previous analyses found.</td>
                                </tr>
                            ) : (
                                history.map((item) => (
                                    <tr key={item.id} className="bg-white border-b hover:bg-slate-50">
                                        <td className="px-6 py-4 flex items-center space-x-2 whitespace-nowrap">
                                            <Calendar size={14} className="text-slate-400" />
                                            <span>{new Date(item.created_at).toLocaleString()}</span>
                                        </td>
                                        <td className="px-6 py-4 font-medium text-slate-900 truncate max-w-xs">
                                            {item.subject || 'No Subject'}
                                        </td>
                                        <td className="px-6 py-4">
                                            {item.sender_email || item.return_path || 'Unknown'}
                                        </td>
                                        <td className="px-6 py-4 text-center">
                                            <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                                                item.risk_score >= 70 ? 'bg-red-100 text-red-700' :
                                                item.risk_score >= 40 ? 'bg-orange-100 text-orange-700' :
                                                item.risk_score >= 20 ? 'bg-amber-100 text-amber-700' :
                                                'bg-green-100 text-green-700'
                                            }`}>
                                                {item.risk_score}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right space-x-3">
                                            <button onClick={() => viewDetails(item)} className="font-medium text-blue-600 hover:underline inline-flex items-center space-x-1">
                                                <span>View</span>
                                                <ExternalLink size={14} />
                                            </button>
                                            <button onClick={() => handleDelete(item.id)} className="font-medium text-red-600 hover:underline inline-flex items-center space-x-1">
                                                <span>Delete</span>
                                                <Trash2 size={14} />
                                            </button>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
