import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Link, useNavigate } from 'react-router-dom';
import { ShieldCheck, History, Activity, FileText } from 'lucide-react';
import { Toaster } from 'sonner';

import AnalyzerPage from './pages/AnalyzerPage';
import DashboardPage from './pages/DashboardPage';
import HistoryPage from './pages/HistoryPage';

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-slate-50 font-sans text-slate-900 selection:bg-blue-100">
        {/* Navigation */}
        <header className="sticky top-0 z-50 w-full border-b bg-white/80 backdrop-blur-md shadow-sm">
          <div className="container mx-auto px-4 h-16 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="bg-blue-600 p-2 rounded-lg text-white">
                <ShieldCheck size={24} />
              </div>
              <span className="text-xl font-bold tracking-tight text-slate-900">
                Email Header Analyzer
              </span>
            </div>
            
            <nav className="flex items-center space-x-6">
              <Link to="/" className="text-sm font-medium text-slate-600 hover:text-blue-600 transition-colors flex items-center space-x-1">
                <FileText size={16} />
                <span>Analyze</span>
              </Link>
              <Link to="/history" className="text-sm font-medium text-slate-600 hover:text-blue-600 transition-colors flex items-center space-x-1">
                <History size={16} />
                <span>History</span>
              </Link>
            </nav>
          </div>
        </header>

        {/* Main Content */}
        <main className="container mx-auto px-4 py-8 max-w-6xl">
          <Routes>
            <Route path="/" element={<AnalyzerPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/history" element={<HistoryPage />} />
          </Routes>
        </main>
        
        <Toaster position="top-right" />
      </div>
    </BrowserRouter>
  );
}
