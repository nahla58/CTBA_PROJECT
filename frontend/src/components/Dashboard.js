import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Dashboard.css';
import BulletinManagement from './BulletinManagement';
import SourceBadges from './SourceBadges';
import AIRemediationPanelSimple from './AIRemediationPanelSimple';

// Load Font Awesome
const loadFontAwesome = () => {
  if (!document.querySelector('link[href*="font-awesome"]')) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css';
    document.head.appendChild(link);
  }
};

// Call it once when component loads
loadFontAwesome();

const modalOverlayStyle = {
  position: 'fixed',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  backgroundColor: 'rgba(0, 0, 0, 0.5)',
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'center',
  zIndex: 1000
};

const modalStyle = {
  backgroundColor: '#fff',
  borderRadius: '8px',
  maxWidth: '600px',
  width: '90%',
  maxHeight: '80vh',
  overflow: 'auto',
  boxShadow: '0 10px 40px rgba(0, 0, 0, 0.3)'
};

const modalHeaderStyle = {
  padding: '20px',
  borderBottom: '1px solid #e2e8f0',
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center'
};

const closeButtonStyle = {
  background: 'none',
  border: 'none',
  fontSize: '24px',
  cursor: 'pointer',
  color: '#64748b'
};

const modalBodyStyle = {
  padding: '20px'
};

const modalSectionStyle = {
  marginBottom: '20px'
};

const modalFooterStyle = {
  padding: '20px',
  borderTop: '1px solid #e2e8f0',
  display: 'flex',
  justifyContent: 'flex-end',
  gap: '10px'
};

function Dashboard({ user, onLogout }) {
  const navigate = useNavigate();
  const [cves, setCves] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    pending: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [activePage, setActivePage] = useState('dashboard');
  const [selectedCve, setSelectedCve] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8000/api/cves?limit=200');
      const data = await response.json();
      
      if (data.cves) {
        setCves(data.cves);
        
        // Calculate stats
        const statsData = {
          total: data.cves.length,
          pending: data.cves.filter(c => c.status === 'PENDING').length,
          critical: data.cves.filter(c => c.severity === 'CRITICAL').length,
          high: data.cves.filter(c => c.severity === 'HIGH').length,
          medium: data.cves.filter(c => c.severity === 'MEDIUM').length,
          low: data.cves.filter(c => c.severity === 'LOW').length
        };
        setStats(statsData);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefreshCves = async () => {
    setRefreshing(true);
    try {
      console.log('🔄 Import rapide depuis NVD (source principale)...');
      
      // ✅ OPTIMISÉ: Import rapide depuis NVD uniquement (~2 secondes)
      const importResponse = await fetch('http://localhost:8000/api/cves/import-from-all-sources?days=7&limit=200', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      });
      
      if (!importResponse.ok) {
        throw new Error(`HTTP Error: ${importResponse.status} ${importResponse.statusText}`);
      }
      
      const importData = await importResponse.json();
      console.log('✅ Import NVD terminé:', importData);
      
      // Recharger les CVEs depuis la base de données
      const response = await fetch('http://localhost:8000/api/cves?limit=200');
      const data = await response.json();
      
      if (data.cves && Array.isArray(data.cves)) {
        setCves(data.cves);
        
        // Recalculer les stats
        const statsData = {
          total: data.cves.length,
          pending: data.cves.filter(c => c.status === 'PENDING').length,
          critical: data.cves.filter(c => c.severity === 'CRITICAL').length,
          high: data.cves.filter(c => c.severity === 'HIGH').length,
          medium: data.cves.filter(c => c.severity === 'MEDIUM').length,
          low: data.cves.filter(c => c.severity === 'LOW').length
        };
        setStats(statsData);
        
        // Message de succès détaillé
        alert(`✅ Synchronisation NVD réussie! (rapide)\n\n` +
              `📥 Importés: ${importData.imported || 0}\n` +
              `🔄 Mis à jour: ${importData.updated || 0}\n` +
              `⏭️ Ignorés: ${importData.skipped || 0} (sans score CVSS)\n\n` +
              `📊 CVEs MEDIUM/HIGH affichés: ${data.cves.length}`);
      } else {
        throw new Error('No CVEs data in response');
      }
    } catch (error) {
      console.error('❌ Error refreshing CVEs:', error);
      alert(`❌ Erreur lors de la synchronisation:\n${error.message}`);
    } finally {
      setRefreshing(false);
    }
  };

  const getSeverityBadgeClass = (severity) => {
    switch(severity) {
      case 'CRITICAL': return 'severity-critical';
      case 'HIGH': return 'severity-high';
      case 'MEDIUM': return 'severity-medium';
      case 'LOW': return 'severity-low';
      default: return '';
    }
  };

  const getStatusBadgeClass = (status) => {
    switch(status) {
      case 'PENDING': return 'status-pending';
      case 'ACCEPTED': return 'status-accepted';
      case 'REJECTED': return 'status-rejected';
      case 'DEFERRED': return 'status-deferred';
      default: return '';
    }
  };

  const handleAcceptCve = async (cveId) => {
    try {
      const response = await fetch(`http://localhost:8000/api/cves/test/${cveId}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'ACCEPTED',
          analyst: user.username,
          comments: 'Approved by analyst'
        })
      });
      if (response.ok) {
        fetchData();
        setShowModal(false);
      } else {
        alert('Error accepting CVE');
      }
    } catch (error) {
      console.error('Error accepting CVE:', error);
    }
  };

  const handleRejectCve = async (cveId) => {
    try {
      const response = await fetch(`http://localhost:8000/api/cves/test/${cveId}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'REJECTED',
          analyst: user.username,
          comments: 'Rejected by analyst'
        })
      });
      if (response.ok) {
        fetchData();
        setShowModal(false);
      } else {
        alert('Error rejecting CVE');
      }
    } catch (error) {
      console.error('Error rejecting CVE:', error);
    }
  };

  const handleAddToBlacklist = async (cveId) => {
    if (!selectedCve || !selectedCve.affected_products) return;
    
    const product = selectedCve.affected_products[0];
    if (!product) return;
    
    try {
      // Add to blacklist (technologies table)
      const response = await fetch('http://localhost:8000/api/technologies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vendor: product.vendor,
          product: product.product,
          status: 'OUT_OF_SCOPE',
          reason: `Blacklisted from CVE ${cveId}`,
          added_by: user.username
        })
      });
      
      if (response.ok) {
        // Also record action in CVE action history
        await fetch(`http://localhost:8000/api/cves/test/${cveId}/action`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'DEFERRED',
            analyst: user.username,
            comments: `Added ${product.vendor}/${product.product} to blacklist`
          })
        });
        
        alert(`Added ${product.vendor}/${product.product} to blacklist`);
        fetchData();
        setShowModal(false);
      } else {
        alert('Error adding to blacklist');
      }
    } catch (error) {
      console.error('Error adding to blacklist:', error);
    }
  };

  const openCveModal = (cve) => {
    setSelectedCve(cve);
    setShowModal(true);
  };

  return (
    <>
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <img src="/logo_nomios.svg" alt="Nomios Logo" style={{height: '40px'}} />
            <div>CTBA</div>
          </div>
        </div>

        <div className="nav-menu">
          <a onClick={() => {setActivePage('dashboard');}} className={`nav-item ${activePage === 'dashboard' ? 'active' : ''}`} style={{cursor: 'pointer'}}>
            📊 Dashboard
          </a>
          <a onClick={() => navigate('/accepted')} className={`nav-item ${activePage === 'accepted' ? 'active' : ''}`} style={{cursor: 'pointer'}}>
            ✅ Accepted CVEs
          </a>
          <a onClick={() => navigate('/rejected')} className={`nav-item ${activePage === 'rejected' ? 'active' : ''}`} style={{cursor: 'pointer'}}>
            ❌ Rejected CVEs
          </a>
          <a onClick={() => navigate('/ingestion')} className={`nav-item ${activePage === 'ingestion' ? 'active' : ''}`} style={{cursor: 'pointer'}}>
            📡 Source Ingestion
          </a>
          <a onClick={() => navigate('/blacklist')} className={`nav-item ${activePage === 'blacklist' ? 'active' : ''}`} style={{cursor: 'pointer'}}>
            🚫 Blocked Products
          </a>
          <a onClick={() => navigate('/bulletins')} className={`nav-item ${activePage === 'bulletins' ? 'active' : ''}`} style={{cursor: 'pointer'}}>
            📧 Bulletins
          </a>
          <a onClick={() => navigate('/history')} className={`nav-item ${activePage === 'history' ? 'active' : ''}`} style={{cursor: 'pointer'}}>
            📜 Action History
          </a>
          <a onClick={() => navigate('/kpi')} className={`nav-item ${activePage === 'kpi' ? 'active' : ''}`} style={{cursor: 'pointer'}}>
            📈 Reports & KPI
          </a>
        </div>

        <div className="sidebar-footer">
          <p>CTBA Platform v7.0.0</p>
          <p>© 2026 TDS by Nomios. All rights reserved.</p>
        </div>
      </div>

      {/* Main Content */}
      <div className="main-content">
        {/* Top Bar */}
        <div className="top-bar">
          <div className="page-title">
            <h1>{activePage === 'bulletins' ? 'Bulletins' : 'Dashboard'}</h1>
            <p>{activePage === 'bulletins' ? 'Manage and send security bulletins to customers' : 'Welcome to CTBA Platform - CVE Management System'}</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* Show BulletinManagement if bulletins page is selected */}
        {activePage === 'bulletins' ? (
          <BulletinManagement />
        ) : (
          <>
            <div className="user-actions">
              <div className="search-box">
                <i className="fas fa-search"></i>
                <input 
                  type="text" 
                  placeholder="Search CVE ID..." 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              <button 
                onClick={handleRefreshCves}
                disabled={refreshing}
                className="btn btn-primary"
                title="Import rapide depuis NVD (2-3 secondes)"
              >
                <i className={`fas ${refreshing ? 'fa-spinner fa-spin' : 'fa-download'}`}></i>
                {refreshing ? '⏳ Import en cours...' : '⚡ UPDATE'}
              </button>
            </div>

            <div className="stats-container">
              <div className="stat-card">
                <div className="stat-header">
                  <div>
                    <div className="stat-value">{stats.total}</div>
                    <div className="stat-label">Total CVE</div>
                  </div>
                  <div className="stat-icon">📊</div>
                </div>
                <div className="stat-change">
                  <i className="fas fa-arrow-up"></i>
                  <span>12% par rapport à la semaine dernière</span>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-header">
                  <div>
                    <div className="stat-value">{stats.pending}</div>
                    <div className="stat-label">PENDING</div>
                  </div>
                  <div className="stat-icon pending">⏳</div>
                </div>
                <div className="stat-change">
                  <span>Attente d'action analyste</span>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-header">
                  <div>
                    <div className="stat-value">{stats.critical}</div>
                    <div className="stat-label">Critical</div>
                  </div>
                  <div className="stat-icon critical">🔴</div>
                </div>
                <div className="stat-change negative">
                  <i className="fas fa-arrow-up"></i>
                  <span>Nécessite une action immédiate</span>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-header">
                  <div>
                    <div className="stat-value">{stats.high}</div>
                    <div className="stat-label">high</div>
                  </div>
                  <div className="stat-icon high">🟠</div>
                </div>
              </div>
            </div>

            {/* CVE Table */}
            <div className="card">
          <div className="card-header">
            <div className="card-title">RECENT CVES</div>
            <div className="card-actions">
              <button className="btn btn-secondary btn-icon">
                <i className="fas fa-download"></i>
              </button>
              <button className="btn btn-secondary btn-icon">
                <i className="fas fa-filter"></i>
              </button>
            </div>
          </div>

          {loading ? (
            <p>loading Cves</p>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>ID CVE</th>
                    <th>SOURCE</th>
                    <th>SEVERITY</th>
                    <th>SCORE</th>
                    <th>AFFECTED PRODUCTS</th>
                    <th>STATUS</th>
                    <th>PUBLISHED</th>
                    <th>UPDATED</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {cves
                    .filter(cve => 
                      searchTerm === '' || 
                      cve.cve_id.toLowerCase().includes(searchTerm.toLowerCase())
                    )
                    .slice(0, 100)
                    .map((cve) => (
                    <tr key={cve.cve_id}>
                      <td><a href="#" style={{color: 'var(--primary-color)'}}>{cve.cve_id}</a></td>
                      <td>
                        <SourceBadges 
                          sourcePrimary={cve.source_primary} 
                          sourcesSecondary={cve.sources_secondary}
                        />
                      </td>
                      <td>
                        <span className={`severity-badge ${getSeverityBadgeClass(cve.severity)}`}>
                          {cve.severity}
                        </span>
                      </td>
                      <td>{cve.cvss_score !== null && cve.cvss_score !== undefined ? cve.cvss_score : 'N/A'}</td>
                      <td>
                        {cve.affected_products && Array.isArray(cve.affected_products) 
                          ? cve.affected_products.map(p => `${p.vendor}: ${p.product}`).join(', ')
                          : '-'
                        }
                      </td>
                      <td>
                        <span className={`status-badge ${getStatusBadgeClass(cve.status)}`}>
                          {cve.status}
                        </span>
                      </td>
                      <td>
                        <span title={`${cve.published_date_utc} | ${cve.timezone || 'UTC+1'}`}>
                          {cve.published_date_formatted || cve.published_date || 'N/A'}
                          <small style={{fontSize: '0.8em', color: '#64748b'}}> (UTC+1)</small>
                        </span>
                      </td>
                      <td>
                        <span title={`Dernière mise à jour: ${cve.last_updated}`}>
                          {cve.last_updated_formatted || cve.last_updated || 'N/A'}
                          <small style={{fontSize: '0.8em', color: '#64748b'}}> (UTC+1)</small>
                        </span>
                      </td>
                      <td>
                        <div className="action-buttons">
                          <button className="btn btn-small btn-secondary" onClick={() => openCveModal(cve)} title="View Details">
                            👁️
                          </button>
                          <button className="btn btn-small btn-primary" onClick={() => handleAcceptCve(cve.cve_id)} title="Accept">
                            ✅
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
          </>
        )}

        {/* CVE Detail Modal - only show when not on bulletins page */}
        {activePage !== 'bulletins' && showModal && selectedCve && (
          <div style={modalOverlayStyle}>
            <div style={modalStyle}>
              <div style={modalHeaderStyle}>
                <h2>{selectedCve.cve_id}</h2>
                <button onClick={() => setShowModal(false)} style={closeButtonStyle}>✕</button>
              </div>
              
              <div style={modalBodyStyle}>
                <div style={modalSectionStyle}>
                  <h3>Description</h3>
                  <p>{selectedCve.description}</p>
                </div>

                <div style={modalSectionStyle}>
                  <h3>Severity and Score</h3>
                  <p>
                    <span className={`severity-badge ${getSeverityBadgeClass(selectedCve.severity)}`}>
                      {selectedCve.severity}
                    </span>
                    <span style={{marginLeft: '10px'}}>CVSS {selectedCve.cvss_score} ({selectedCve.cvss_version})</span>
                  </p>
                </div>

                <div style={modalSectionStyle}>
                  <h3>Affected Products</h3>
                  {selectedCve.affected_products && Array.isArray(selectedCve.affected_products) ? (
                    <ul>
                      {selectedCve.affected_products.map((p, i) => (
                        <li key={i}>{p.vendor}: {p.product}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>Unknown</p>
                  )}
                </div>

                <div style={modalSectionStyle}>
                  <h3>Published</h3>
                  <p>
                    <strong>{selectedCve.published_date_formatted || selectedCve.published_date}</strong>
                    <br/>
                    <small style={{color: '#64748b'}}>
                      UTC: {selectedCve.published_date_utc}<br/>
                      Timezone: {selectedCve.timezone || 'Africa/Tunis (UTC+1)'}
                    </small>
                  </p>
                </div>

                {/* AI Remediation Panel */}
                <div style={{...modalSectionStyle, padding: 0}}>
                  <AIRemediationPanelSimple
                    cveId={selectedCve.cve_id}
                    cveSeverity={selectedCve.severity}
                    cveScore={selectedCve.cvss_score}
                  />
                </div>
              </div>

              <div style={modalFooterStyle}>
                {(user.role === 'VOC_L1' || user.role === 'ADMINISTRATOR') ? (
                  <>
                    <button 
                      className="btn btn-primary"
                      onClick={() => handleAcceptCve(selectedCve.cve_id)}
                    >
                      ✅ Accept
                    </button>
                    <button 
                      className="btn btn-secondary"
                      onClick={() => handleRejectCve(selectedCve.cve_id)}
                      style={{marginLeft: '10px'}}
                    >
                      ❌ Reject
                    </button>
                    <button 
                      className="btn btn-secondary"
                      onClick={() => handleAddToBlacklist(selectedCve.cve_id)}
                      style={{marginLeft: '10px'}}
                    >
                      🚫 Blacklist
                    </button>
                  </>
                ) : (
                  <p style={{color: '#666', fontStyle: 'italic'}}>
                    ⚠️ Your role ({user.role}) does not have permission to modify CVE status. Read-only access.
                  </p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

export default Dashboard;
