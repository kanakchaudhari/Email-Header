import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileCode2, Play, FileText } from 'lucide-react';
import { toast } from 'sonner';
import * as pdfjsLib from 'pdfjs-dist';

// Configure PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = `https://unpkg.com/pdfjs-dist@${pdfjsLib.version}/build/pdf.worker.min.mjs`;

export default function AnalyzerPage() {
  const [headers, setHeaders] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isExtractingPdf, setIsExtractingPdf] = useState(false);
  const [sourceFormat, setSourceFormat] = useState<'text' | 'pdf' | 'eml' | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const navigate = useNavigate();

  const handleAnalyze = async (headersToAnalyze?: string) => {
    const textToAnalyze = headersToAnalyze || headers;
    if (!textToAnalyze.trim()) {
      toast.error('Please enter email headers to analyze');
      return;
    }
    
    setIsLoading(true);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headers: textToAnalyze })
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
      navigate('/dashboard', { state: { result: data, rawHeaders: textToAnalyze } });
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
    setSourceFormat('text');
    toast.success('Sample headers loaded');
  };

  const processFile = async (file: File) => {
    if (file.type === 'application/pdf' || file.name.endsWith('.pdf')) {
      setIsExtractingPdf(true);
      setSourceFormat('pdf');
      const toastId = toast.loading('Extracting text from email PDF...');
      try {
        const arrayBuffer = await file.arrayBuffer();
        const loadingTask = pdfjsLib.getDocument({ data: arrayBuffer });
        const pdf = await loadingTask.promise;
        let extractedText = '';
        
        for (let i = 1; i <= pdf.numPages; i++) {
          const page = await pdf.getPage(i);
          const textContent = await page.getTextContent();
          const pageText = textContent.items.map((item: any) => item.str).join(' ');
          extractedText += pageText + '\n';
        }
        
        if (!extractedText.trim()) {
          throw new Error('No readable text found in PDF file.');
        }

        setHeaders(extractedText);
        toast.dismiss(toastId);
        toast.success(`PDF Loaded (${pdf.numPages} ${pdf.numPages === 1 ? 'page' : 'pages'}). Extracted headers ready!`);
      } catch (err: any) {
        toast.dismiss(toastId);
        toast.error(err.message || 'Failed to extract text from PDF');
      } finally {
        setIsExtractingPdf(false);
      }
    } else {
      if (file.name.endsWith('.eml')) {
        setSourceFormat('eml');
      } else {
        setSourceFormat('text');
      }
      const reader = new FileReader();
      reader.onload = (event) => {
        setHeaders(event.target?.result as string);
        toast.success('File loaded successfully');
      };
      reader.readAsText(file);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  return (
    <div className="flex flex-col space-y-6">
      <div className="flex flex-col space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Header Analyzer</h1>
        <p className="text-slate-500">
          Upload a printed Gmail email <strong>PDF</strong>, paste raw email headers, or upload <strong>.txt / .eml</strong> files to detect spoofing and verify authenticity.
        </p>
      </div>

      <div 
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`bg-white border rounded-xl shadow-sm overflow-hidden flex flex-col transition-all ${
          isDragging ? 'border-blue-500 ring-2 ring-blue-100 bg-blue-50/20' : ''
        }`}
      >
        <div className="bg-slate-50 border-b p-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <button 
              type="button"
              onClick={loadSample} 
              className="flex items-center space-x-1 px-3 py-1.5 text-sm bg-white border rounded-md hover:bg-slate-100 transition-colors shadow-xs"
            >
              <FileCode2 size={16} className="text-blue-600" />
              <span>Load Sample</span>
            </button>
            
            <label className="flex items-center space-x-1 px-3 py-1.5 text-sm bg-white border rounded-md hover:bg-slate-100 transition-colors cursor-pointer shadow-xs">
              <Upload size={16} className="text-blue-600" />
              <span>Upload TXT / EML</span>
              <input type="file" accept=".txt,.eml" className="hidden" onChange={handleFileUpload} />
            </label>

            <label className="flex items-center space-x-1.5 px-3 py-1.5 text-sm bg-blue-50 text-blue-700 border border-blue-200 rounded-md hover:bg-blue-100 transition-colors cursor-pointer font-medium shadow-xs">
              <FileText size={16} className="text-blue-600" />
              <span>Upload Email PDF</span>
              <input type="file" accept=".pdf" className="hidden" onChange={handleFileUpload} />
            </label>
          </div>

          <div className="flex items-center space-x-3 text-xs text-slate-500 font-mono">
            {sourceFormat && (
              <span className={`px-2 py-0.5 rounded font-semibold text-[11px] uppercase ${
                sourceFormat === 'pdf' ? 'bg-red-100 text-red-700' :
                sourceFormat === 'eml' ? 'bg-purple-100 text-purple-700' :
                'bg-slate-200 text-slate-700'
              }`}>
                {sourceFormat}
              </span>
            )}
            <span>{headers.length} characters</span>
          </div>
        </div>

        {isDragging && (
          <div className="p-4 bg-blue-50 border-b text-center text-blue-600 text-sm font-medium animate-pulse">
            Drop your PDF, TXT, or EML file here to parse automatically...
          </div>
        )}

        {isExtractingPdf && (
          <div className="p-4 bg-amber-50 border-b flex items-center justify-center space-x-2 text-amber-800 text-sm">
            <div className="animate-spin rounded-full h-4 w-4 border-2 border-amber-600 border-t-transparent" />
            <span>Reading PDF content and extracting email headers...</span>
          </div>
        )}
        
        <textarea
          value={headers}
          onChange={(e) => {
            setHeaders(e.target.value);
            if (sourceFormat) setSourceFormat(null);
          }}
          placeholder="Paste raw email headers here or click 'Upload Email PDF' to select a printed Gmail PDF..."
          className="w-full h-96 p-4 font-mono text-sm bg-slate-900 text-slate-100 focus:outline-none resize-none"
          spellCheck="false"
        />
        
        <div className="p-4 bg-slate-50 border-t flex items-center justify-between">
          <p className="text-xs text-slate-500 hidden sm:block">
            Supports Gmail printed PDF emails, Outlook exports, and raw RFC 822 MIME headers.
          </p>

          <button 
            type="button"
            onClick={() => handleAnalyze()} 
            disabled={isLoading || isExtractingPdf || !headers.trim()}
            className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg font-medium transition-all shadow-sm ml-auto"
          >
            {isLoading ? <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent" /> : <Play size={18} />}
            <span>{isLoading ? 'Analyzing...' : 'Analyze Headers'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}

