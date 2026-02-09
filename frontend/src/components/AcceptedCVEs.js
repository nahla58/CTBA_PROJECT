import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './AcceptedCVEs.css';

function AcceptedCVEs({ user, onLogout }) {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCve, setSelectedCve] = useState(null);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    fetchAcceptedCVEs();
  }, []);

  const fetchAcceptedCVEs = async () => {
    try {
      // Fetch ACCEPTED CVEs only (reviewed and approved by analysts)
      const response = await fetch('http://localhost:8000/api/cves?status=ACCEPTED&limit=100', {
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
      console.error('Error fetching accepted CVEs:', error);
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
            <img src="/logo_nomios.svg" alt="Nomios Logo" style={{height: '40px'}} />
            <div>CTBA</div>
          </div>
        </div>

        <div className="nav-menu">
          <Link to="/" className="nav-item">
            📊 Dashboard
          </Link>
          <Link to="/accepted" className="nav-item active">
            ✅ Accepted CVEs
          </Link>
          <Link to="/rejected" className="nav-item">
            ❌ Rejected CVEs
          </Link>
          <Link to="/ingestion" className="nav-item">
            📡 Source Ingestion
          </Link>
          <Link to="/blacklist" className="nav-item">
            🚫 Blacklisted Products
          </Link>
          <Link to="/bulletins" className="nav-item">
            📧 Bulletins
          </Link>
          <Link to="/history" className="nav-item">
            📜 Action History
          </Link>
          <Link to="/kpi" className="nav-item">
            📈 Reports & KPIs
          </Link>
        </div>

        <div className="sidebar-footer">
          <p>CTBA Platform </p>
          <p>© 2026 TDS by Nomios. All rights reserved.</p>
        </div>
      </div>

      {/* Main Content */}
      <div className="main-content">
        {/* Top Bar */}
        <div className="top-bar">
          <div className="page-title">
            <h1>✅ Accepted CVEs</h1>
            <p>List of CVEs approved by analysts</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* CVEs Table */}
        <div className="cves-container">
          {loading ? (
            <div style={{padding: '40px', textAlign: 'center'}}>⏳ Loading...</div>
          ) : cves.length === 0 ? (
            <div style={{padding: '40px', textAlign: 'center', color: '#666'}}>
              No accepted CVEs found. Go to Dashboard to accept CVEs.
            </div>
          ) : (
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={thStyle}>CVE ID</th>
                  <th style={thStyle}>Severity</th>
                  <th style={thStyle}>CVSS Score</th>
                  <th style={thStyle}>Affected Products</th>
                  <th style={thStyle}>Source</th>
                  <th style={thStyle}>Decision Date</th>
                  <th style={thStyle}>Analyst</th>
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
                    <td style={tdStyle}>
                      {cve.cvss_score !== undefined && cve.cvss_score !== null ? cve.cvss_score : 'N/A'}
                    </td>
                    <td style={tdStyle}>
                      {cve.affected_products && Array.isArray(cve.affected_products)
                        ? cve.affected_products.map(p => `${p.vendor}/${p.product}`).join(', ')
                        : '-'
                      }
                    </td>
                    <td style={tdStyle}>
                      <div style={{display: 'flex', gap: '4px', flexWrap: 'wrap'}}>
                        <span style={{
                          background: '#3b82f6',
                          color: 'white',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          fontWeight: 'bold'
                        }}>
                          {cve.source_primary || cve.source || 'NVD'}
                        </span>
                        {cve.sources_secondary && cve.sources_secondary.length > 0 && (
                          <span style={{
                            background: '#10b981',
                            color: 'white',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            fontSize: '0.75rem'
                          }}>
                            +{cve.sources_secondary.length}
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={tdStyle}>{cve.decision_date ? new Date(cve.decision_date).toLocaleDateString('en-US') : '-'}</td>
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
                        👁️ Details
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
                  <h3>Severity and Score</h3>
                  <p>
                    <span className={`severity-badge ${getSeverityBadgeClass(selectedCve.severity)}`}>
                      {selectedCve.severity}
                    </span>
                    <span style={{marginLeft: '10px'}}>CVSS {selectedCve.cvss_score} ({selectedCve.cvss_version})</span>
                  </p>
                </div>

                <div style={{marginBottom: '20px'}}>
                  <h3>📡 Sources</h3>
                  <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
                    <div style={{
                      background: '#e0f2fe',
                      border: '1px solid #0284c7',
                      padding: '10px',
                      borderRadius: '6px',
                      flex: '1',
                      minWidth: '200px'
                    }}>
                      <p style={{margin: '0 0 8px 0', fontWeight: 'bold', color: '#0c4a6e'}}>Primary Source</p>
                      <span style={{
                        background: '#0284c7',
                        color: 'white',
                        padding: '4px 12px',
                        borderRadius: '4px',
                        fontSize: '0.9rem',
                        fontWeight: 'bold'
                      }}>
                        {selectedCve.source_primary || selectedCve.source || 'NVD'}
                      </span>
                    </div>
                    
                    {selectedCve.sources_secondary && selectedCve.sources_secondary.length > 0 && (
                      <div style={{
                        background: '#f0fdf4',
                        border: '1px solid #16a34a',
                        padding: '10px',
                        borderRadius: '6px',
                        flex: '1',
                        minWidth: '200px'
                      }}>
                        <p style={{margin: '0 0 8px 0', fontWeight: 'bold', color: '#166534'}}>Secondary Sources (Enrichments)</p>
                        <div style={{display: 'flex', gap: '4px', flexWrap: 'wrap'}}>
                          {selectedCve.sources_secondary.map((source, i) => (
                            <div key={i} style={{fontSize: '0.85rem'}}>
                              <span style={{
                                background: '#16a34a',
                                color: 'white',
                                padding: '2px 8px',
                                borderRadius: '3px',
                                marginRight: '4px'
                              }}>
                                {source.name}
                              </span>
                              <span style={{fontSize: '0.75rem', color: '#666'}}>
                                ({source.data_enrichment || 'data'})
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div style={{marginBottom: '20px'}}>
                  <h3>Affected Products</h3>
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
                  <h3>Decision Information</h3>
                  <p><strong>Analyst:</strong> {selectedCve.analyst || '-'}</p>
                  <p><strong>Comments:</strong> {selectedCve.decision_comments || '-'}</p>
                  <p><strong>Date:</strong> {selectedCve.decision_date ? new Date(selectedCve.decision_date).toLocaleString('en-US') : '-'}</p>
                </div>

                <div style={{marginBottom: '20px'}}>
                  <h3>Reference</h3>
                  <p>
                    <strong>Published:</strong> {selectedCve.published_date_formatted || selectedCve.published_date}
                    <br/>
                    <small style={{color: '#64748b'}}>
                      Timezone: {selectedCve.timezone || 'Africa/Tunis (UTC+1)'}
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

export default AcceptedCVEs;
