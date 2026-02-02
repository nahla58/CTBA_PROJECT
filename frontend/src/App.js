// src/App.js
import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Link, useLocation } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Login from './components/Login';
import CVEList from './components/CVElist';
import TechnologyManager from './components/TechnologyManager';
import ActionHistory from './components/ActionHistory';
import BlacklistManagement from './components/BlacklistManagement';
import AcceptedCVEs from './components/AcceptedCVEs';
import RejectedCVEs from './components/RejectedCVEs';
import AnalystKPIDashboard from './components/AnalystKPIDashboard';
import NLPImprovement from './components/NLPImprovement';
import MultiSourceIngestion from './components/MultiSourceIngestion';
import BulletinManagement from './components/BulletinManagement';
import DeliveryAuditTrail from './components/DeliveryAuditTrail';
import MailingListManager from './components/MailingListManager';
import DeliveryQueueMonitor from './components/DeliveryQueueMonitor';
import BulletinPreview from './components/BulletinPreview';
import './App.css';

// Composant Statistics
function StatsComponent() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('http://localhost:8000/stats')
      .then(response => response.json())
      .then(data => {
        setStats(data);
        setLoading(false);
      })
      .catch(error => {
        console.error('Error fetching stats:', error);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="stats-container">
        <h1>📊 Statistics</h1>
        <div className="loading-spinner">⏳</div>
        <p>Chargement des statistiques...</p>
      </div>
    );
  }

  return (
    <div className="stats-container">
      <h1>📊 Statistics Dashboard</h1>
      
      {stats && (
        <>
          {/* Summary Cards */}
          <div className="stats-cards">
            <div className="stat-card">
              <div className="stat-icon">🛡️</div>
              <div className="stat-value">{stats.summary.total_cves}</div>
              <div className="stat-label">Total CVEs</div>
            </div>
            
            <div className="stat-card">
              <div className="stat-icon">⏳</div>
              <div className="stat-value">{stats.summary.pending_cves}</div>
              <div className="stat-label">En attente</div>
            </div>
            
            <div className="stat-card">
              <div className="stat-icon">📦</div>
              <div className="stat-value">{stats.summary.total_products}</div>
              <div className="stat-label">Produits</div>
            </div>
            
            <div className="stat-card">
              <div className="stat-icon">🔧</div>
              <div className="stat-value">{stats.summary.total_technologies}</div>
              <div className="stat-label">Technologies</div>
            </div>
          </div>

          {/* Distribution par sévérité */}
          <div className="stats-section">
            <h3>📈 Distribution par sévérité</h3>
            <div className="severity-stats">
              {stats.distribution.by_severity && Object.entries(stats.distribution.by_severity).map(([severity, count]) => {
                const getSeverityColor = (severity) => {
                  const colors = {
                    CRITICAL: '#dc3545',
                    HIGH: '#fd7e14',
                    MEDIUM: '#ffc107',
                    LOW: '#28a745'
                  };
                  return colors[severity] || '#6c757d';
                };
                
                return (
                  <div key={severity} className="severity-item">
                    <span 
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(severity) }}
                    >
                      {severity}
                    </span>
                    <span className="severity-count">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Distribution par statut */}
          <div className="stats-section">
            <h3>📋 Distribution par statut</h3>
            <div className="status-stats">
              {stats.distribution.by_status && Object.entries(stats.distribution.by_status).map(([status, count]) => {
                const getStatusConfig = (status) => {
                  const configs = {
                    PENDING: { text: '⏳ En attente', color: '#ffc107' },
                    VALIDATED: { text: '✅ Validées', color: '#28a745' },
                    REJECTED: { text: '❌ Rejetées', color: '#dc3545' }
                  };
                  return configs[status] || { text: status, color: '#6c757d' };
                };
                
                const config = getStatusConfig(status);
                
                return (
                  <div key={status} className="status-item">
                    <span 
                      className="status-badge"
                      style={{ backgroundColor: config.color }}
                    >
                      {config.text}
                    </span>
                    <span className="status-count">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Technologies par statut */}
          {stats.distribution.tech_by_status && (
            <div className="stats-section">
              <h3>🔧 Technologies par statut</h3>
              <div className="tech-stats">
                {Object.entries(stats.distribution.tech_by_status).map(([status, count]) => {
                  let statusText = '';
                  let statusColor = '';
                  
                  switch(status) {
                    case 'OUT_OF_SCOPE':
                      statusText = '🚫 Out of Scope';
                      statusColor = '#dc3545';
                      break;
                    case 'PRIORITY':
                      statusText = '⚡ Priority';
                      statusColor = '#ffc107';
                      break;
                    case 'NORMAL':
                      statusText = '✅ Normal';
                      statusColor = '#28a745';
                      break;
                    default:
                      statusText = status;
                      statusColor = '#6c757d';
                  }
                  
                  return (
                    <div key={status} className="tech-item">
                      <span 
                        className="tech-badge"
                        style={{ backgroundColor: statusColor }}
                      >
                        {statusText}
                      </span>
                      <span className="tech-count">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Dernières importations */}
          {stats.automation.recent_imports && stats.automation.recent_imports.length > 0 && (
            <div className="stats-section">
              <h3>🔄 Dernières importations</h3>
              <div className="imports-list">
                {stats.automation.recent_imports.map((imp, index) => (
                  <div key={index} className="import-item">
                    <div className="import-date">
                      {new Date(imp.import_date).toLocaleDateString('fr-FR', {
                        day: '2-digit',
                        month: '2-digit',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                      })}
                    </div>
                    <div className="import-details">
                      <span className="import-detail">📦 {imp.cves_found} trouvées</span>
                      <span className="import-detail">✅ {imp.cves_added} ajoutées</span>
                      <span className="import-detail">⏱️ {imp.duration_seconds}s</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// Navigation active
function NavLink({ to, children }) {
  const location = useLocation();
  const isActive = location.pathname === to;
  
  return (
    <Link 
      to={to} 
      className={`nav-link ${isActive ? 'active' : ''}`}
    >
      {children}
    </Link>
  );
}

// Composant principal
function AppContent() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already logged in
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (e) {
        localStorage.removeItem('user');
        localStorage.removeItem('token');
      }
    }
    setLoading(false);
  }, []);

  const handleLoginSuccess = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    setUser(null);
  };

  if (loading) {
    return <div style={{textAlign: 'center', paddingTop: '50px'}}>⏳ Loading...</div>;
  }

  if (!user) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <Routes>
      <Route path="/" element={<Dashboard user={user} onLogout={handleLogout} />} />
      <Route path="/cves" element={<CVEList user={user} onLogout={handleLogout} />} />
      <Route path="/technologies" element={<TechnologyManager user={user} onLogout={handleLogout} />} />
      <Route path="/stats" element={<StatsComponent user={user} onLogout={handleLogout} />} />
      <Route path="/history" element={<ActionHistory user={user} onLogout={handleLogout} />} />
      <Route path="/blacklist" element={<BlacklistManagement user={user} onLogout={handleLogout} />} />
      <Route path="/accepted" element={<AcceptedCVEs user={user} onLogout={handleLogout} />} />
      <Route path="/rejected" element={<RejectedCVEs user={user} onLogout={handleLogout} />} />
      <Route path="/kpi" element={<AnalystKPIDashboard user={user} onLogout={handleLogout} />} />
      <Route path="/ingestion" element={<MultiSourceIngestion user={user} onLogout={handleLogout} />} />
      <Route path="/nlp-improvement" element={<NLPImprovement user={user} onLogout={handleLogout} />} />
      <Route path="/bulletins" element={<BulletinManagement user={user} onLogout={handleLogout} />} />
      <Route path="/delivery-audit" element={<DeliveryAuditTrail user={user} onLogout={handleLogout} />} />
      <Route path="/mailing-lists" element={<MailingListManager user={user} onLogout={handleLogout} />} />
      <Route path="/delivery-queue" element={<DeliveryQueueMonitor user={user} onLogout={handleLogout} />} />
    </Routes>
  );
}

// Composant racine avec Router
function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;