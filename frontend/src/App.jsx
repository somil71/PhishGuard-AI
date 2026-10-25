import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import UrlScanner from './components/UrlScanner';
import BatchScanner from './components/BatchScanner';
import ModelDashboard from './components/ModelDashboard';
import ArchitectureExplorer from './components/ArchitectureExplorer';
import Footer from './components/Footer';
import { getHealthStatus } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [healthStatus, setHealthStatus] = useState(null);
  const [isHealthChecking, setIsHealthChecking] = useState(false);

  const checkHealth = useCallback(async () => {
    try {
      setIsHealthChecking(true);
      const data = await getHealthStatus();
      setHealthStatus(data);
    } catch (err) {
      setHealthStatus({ status: 'offline', error: err.message });
    } finally {
      setIsHealthChecking(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
    // Periodically poll backend status every 30 seconds
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-900">
      {/* Background ambient cybersecurity mesh gradients */}
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div className="absolute top-[-10%] left-[-10%] w-[45vw] h-[45vw] rounded-full bg-cyan-600/5 blur-[120px]" />
        <div className="absolute bottom-[10%] right-[-10%] w-[45vw] h-[45vw] rounded-full bg-blue-700/5 blur-[140px]" />
      </div>

      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        healthStatus={healthStatus}
        onRefreshHealth={checkHealth}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
        {activeTab === 'scanner' && <UrlScanner />}
        {activeTab === 'batch' && <BatchScanner />}
        {activeTab === 'metrics' && <ModelDashboard />}
        {activeTab === 'architecture' && <ArchitectureExplorer />}
      </main>

      {/* Footer */}
      <Footer healthStatus={healthStatus} />
    </div>
  );
}
