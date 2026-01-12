// src/App.js
import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Link, useLocation } from 'react-router-dom';
import CVEList from './components/CVElist';
import TechnologyManager from './components/TechnologyManager';
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
  return (
    <div className="App">
      <nav className="navbar">
        <div className="nav-brand">
          <h1>🛡️ CTBA Dashboard</h1>
        </div>
        <div className="nav-links">
          <NavLink to="/">📋 CVEs</NavLink>
          <NavLink to="/technologies">🔧 Technologies</NavLink>
          <NavLink to="/stats">📊 Statistics</NavLink>
        </div>
      </nav>

      <div className="main-content">
        <Routes>
          <Route path="/" element={<CVEList />} />
          <Route path="/technologies" element={<TechnologyManager />} />
          <Route path="/stats" element={<StatsComponent />} />
        </Routes>
      </div>
    </div>
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