import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileCode2, Play, CheckCircle2, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';

export default function AnalyzerPage() {
  const [headers, setHeaders] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleAnalyze = async () => {
    if (!headers.trim()) {
      toast.error('Please enter email headers to analyze');
      return;
    }
    
    setIsLoading(true);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headers })
      });
      
      const contentType = res.headers.get('content-type') || '';
      let data: any = {};
      
      if (contentType.includes('application/json')) {
        data = await res.json();
      } else {
        const text = await res.text();
        if (res.status === 401 || text.includes('Protected deployment') || text.includes('vercel_auth')) {
          throw new Error('Vercel Deployment Protection is active. Please disable Vercel Authentication in project settings.');
        }
        throw new Error(`Server returned non-JSON response (${res.status})`);
      }

      if (!res.ok) {
        throw new Error(data.error?.message || data.error || data.message || 'Failed to analyze email headers');
      }
      
      // Navigate to dashboard and pass data in state
      navigate('/dashboard', { state: { result: data, rawHeaders: headers } });
    } catch (error: any) {
      toast.error(error.message || 'An error occurred during header analysis');
    } finally {
      setIsLoading(false);
    }
  };

  const loadSample = () => {
    const sample = `Return-Path: <sender@example.com>
Received: from mail.example.com (mail.example.com [192.168.1.1])
    by mx.google.com with ESMTPS id abcdefg
    for <recipient@test.com>;
    Thu, 01 Aug 2026 10:00:00 -0700 (PDT)
Authentication-Results: mx.google.com;
    dkim=pass header.i=@example.com;
    spf=pass (google.com: domain of sender@example.com designates 192.168.1.1 as permitted sender);
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
From: Sender Name <sender@example.com>
To: Recipient <recipient@test.com>
Subject: Security Alert
Date: Thu, 01 Aug 2026 10:00:00 -0700
Message-ID: <123456789@example.com>`;
    setHeaders(sample);
    toast.success('Sample headers loaded');
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (event) => {
      setHeaders(event.target?.result as string);
      toast.success('File loaded successfully');
    };
    reader.readAsText(file);
  };

  return (
    <div className="flex flex-col space-y-6">
      <div className="flex flex-col space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Header Analyzer</h1>
        <p className="text-slate-500">Paste raw email headers below to detect spoofing and verify authenticity.</p>
      </div>

      <div className="bg-white border rounded-xl shadow-sm overflow-hidden flex flex-col">
        <div className="bg-slate-50 border-b p-3 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <button onClick={loadSample} className="flex items-center space-x-1 px-3 py-1.5 text-sm bg-white border rounded-md hover:bg-slate-100 transition-colors">
              <FileCode2 size={16} className="text-blue-600" />
              <span>Load Sample</span>
            </button>
            
            <label className="flex items-center space-x-1 px-3 py-1.5 text-sm bg-white border rounded-md hover:bg-slate-100 transition-colors cursor-pointer">
              <Upload size={16} className="text-blue-600" />
              <span>Upload TXT</span>
              <input type="file" accept=".txt,.eml" className="hidden" onChange={handleFileUpload} />
            </label>
          </div>
          <div className="text-xs text-slate-500 font-mono">
            {headers.length} characters
          </div>
        </div>
        
        <textarea
          value={headers}
          onChange={(e) => setHeaders(e.target.value)}
          placeholder="Return-Path: <sender@example.com>&#10;Received: from ..."
          className="w-full h-96 p-4 font-mono text-sm bg-slate-900 text-slate-100 focus:outline-none resize-none"
          spellCheck="false"
        />
        
        <div className="p-4 bg-slate-50 border-t flex justify-end">
          <button 
            onClick={handleAnalyze} 
            disabled={isLoading || !headers.trim()}
            className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg font-medium transition-all shadow-sm"
          >
            {isLoading ? <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent" /> : <Play size={18} />}
            <span>{isLoading ? 'Analyzing...' : 'Analyze Headers'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
