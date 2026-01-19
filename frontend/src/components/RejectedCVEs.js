import React, { useState, useEffect } from 'react';
import './RejectedCVEs.css';

function RejectedCVEs({ user, onLogout }) {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCve, setSelectedCve] = useState(null);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    fetchRejectedCVEs();
  }, []);

  const fetchRejectedCVEs = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/cves?status=REJECTED&limit=100', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setCves(data.cves || []);
      }
      setLoading(false);
    } catch (error) {
      console.error('Error fetching rejected CVEs:', error);
      setLoading(false);
    }
  };

  const getSeverityBadgeClass = (severity) => {
    switch(severity) {
      case 'CRITICAL': return 'severity-critical';
      case 'HIGH': return 'severity-high';
      case 'MEDIUM': return 'severity-medium';
      case 'LOW': return 'severity-low';
      default: return 'severity-unknown';
    }
  };

  const openCveModal = (cve) => {
    setSelectedCve(cve);
    setShowModal(true);
  };

  const tableStyle = {
    width: '100%',
    borderCollapse: 'collapse',
    backgroundColor: '#ffffff'
  };

  const thStyle = {
    padding: '12px',
    textAlign: 'left',
    borderBottom: '2px solid #e2e8f0',
    fontWeight: '600',
    backgroundColor: '#f1f5f9',
    color: '#1e293b'
  };

  const tdStyle = {
    padding: '12px',
    borderBottom: '1px solid #e2e8f0'
  };

  const modalOverlayStyle = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0,0,0,0.5)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000
  };

  const modalStyle = {
    backgroundColor: 'white',
    borderRadius: '8px',
    maxWidth: '700px',
    width: '90%',
    maxHeight: '90vh',
    overflow: 'auto',
    boxShadow: '0 4px 20px rgba(0,0,0,0.2)'
  };

  const modalHeaderStyle = {
    padding: '20px',
    borderBottom: '1px solid #e2e8f0',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center'
  };

  const modalBodyStyle = {
    padding: '20px'
  };

  const closeButtonStyle = {
    background: 'none',
    border: 'none',
    fontSize: '24px',
    cursor: 'pointer'
  };

  return (
    <div className="dashboard-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <div className="logo-icon">🔐</div>
            <div>CTBA</div>
          </div>
        </div>

        <div className="nav-menu">
          <a href="/" className="nav-item">
            📊 Dashboard
          </a>
          <a href="/accepted" className="nav-item">
            ✅ CVEs Acceptés
          </a>
          <a href="/rejected" className="nav-item active">
            ❌ CVEs Rejetés
          </a>
          <a href="/blacklist" className="nav-item">
            🚫 Produits Blacklistés
          </a>
          <a href="/history" className="nav-item">
            📜 Historique des Actions
          </a>
        </div>

        <div className="sidebar-footer">
          <p>CTBA Platform v7.0.0</p>
          <p>© 2026 Tds by Nomios. All rights reserved.</p>
        </div>
      </div>

      {/* Main Content */}
      <div className="main-content">
        {/* Top Bar */}
        <div className="top-bar">
          <div className="page-title">
            <h1>❌ CVEs Rejetés</h1>
            <p>Liste des CVEs rejetés par les analystes</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* CVEs Table */}
        <div className="cves-container">
          {loading ? (
            <div style={{padding: '40px', textAlign: 'center'}}>⏳ Chargement...</div>
          ) : cves.length === 0 ? (
            <div style={{padding: '40px', textAlign: 'center', color: '#666'}}>
              Aucun CVE rejeté trouvé
            </div>
          ) : (
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={thStyle}>CVE ID</th>
                  <th style={thStyle}>Sévérité</th>
                  <th style={thStyle}>Score CVSS</th>
                  <th style={thStyle}>Produits Affectés</th>
                  <th style={thStyle}>Date de Décision</th>
                  <th style={thStyle}>Analyste</th>
                  <th style={thStyle}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {cves.map((cve) => (
                  <tr key={cve.cve_id} style={{borderBottom: '1px solid #e2e8f0'}}>
                    <td style={tdStyle}>
                      <strong style={{color: '#2563eb'}}>{cve.cve_id}</strong>
                    </td>
                    <td style={tdStyle}>
                      <span className={`severity-badge ${getSeverityBadgeClass(cve.severity)}`}>
                        {cve.severity}
                      </span>
                    </td>
                    <td style={tdStyle}>{cve.cvss_score || 'N/A'}</td>
                    <td style={tdStyle}>
                      {cve.affected_products && Array.isArray(cve.affected_products)
                        ? cve.affected_products.map(p => `${p.vendor}/${p.product}`).join(', ')
                        : '-'
                      }
                    </td>
                    <td style={tdStyle}>{cve.decision_date ? new Date(cve.decision_date).toLocaleDateString('fr-FR') : '-'}</td>
                    <td style={tdStyle}>{cve.analyst || '-'}</td>
                    <td style={tdStyle}>
                      <button 
                        onClick={() => openCveModal(cve)}
                        style={{
                          background: '#2563eb',
                          color: 'white',
                          border: 'none',
                          padding: '6px 12px',
                          borderRadius: '4px',
                          cursor: 'pointer'
                        }}
                      >
                        👁️ Détails
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* CVE Detail Modal */}
        {showModal && selectedCve && (
          <div style={modalOverlayStyle}>
            <div style={modalStyle}>
              <div style={modalHeaderStyle}>
                <h2>{selectedCve.cve_id}</h2>
                <button onClick={() => setShowModal(false)} style={closeButtonStyle}>✕</button>
              </div>
              
              <div style={modalBodyStyle}>
                <div style={{marginBottom: '20px'}}>
                  <h3>Description</h3>
                  <p>{selectedCve.description}</p>
                </div>

                <div style={{marginBottom: '20px'}}>
                  <h3>Sévérité et Score</h3>
                  <p>
                    <span className={`severity-badge ${getSeverityBadgeClass(selectedCve.severity)}`}>
                      {selectedCve.severity}
                    </span>
                    <span style={{marginLeft: '10px'}}>CVSS {selectedCve.cvss_score} ({selectedCve.cvss_version})</span>
                  </p>
                </div>

                <div style={{marginBottom: '20px'}}>
                  <h3>Produits Affectés</h3>
                  {selectedCve.affected_products && Array.isArray(selectedCve.affected_products) ? (
                    <ul>
                      {selectedCve.affected_products.map((p, i) => (
                        <li key={i}>{p.vendor}: {p.product}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>-</p>
                  )}
                </div>

                <div style={{marginBottom: '20px'}}>
                  <h3>Informations de Décision</h3>
                  <p><strong>Analyste:</strong> {selectedCve.analyst || '-'}</p>
                  <p><strong>Raison du Rejet:</strong> {selectedCve.decision_comments || '-'}</p>
                  <p><strong>Date:</strong> {selectedCve.decision_date ? new Date(selectedCve.decision_date).toLocaleString('fr-FR') : '-'}</p>
                </div>

                <div style={{marginBottom: '20px'}}>
                  <h3>Référence</h3>
                  <p>
                    <strong>Publié:</strong> {selectedCve.published_date_formatted || selectedCve.published_date}
                    <br/>
                    <small style={{color: '#64748b'}}>
                      Timezone: {selectedCve.timezone || 'Europe/Paris (UTC+1)'}
                    </small>
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default RejectedCVEs;
