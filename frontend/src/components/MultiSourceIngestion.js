import React, { useState, useEffect } from 'react';
import '../components/MultiSourceIngestion.css';

const MultiSourceIngestion = () => {
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('sources');
  const [manualCVE, setManualCVE] = useState({
    cve_id: '',
    description: '',
    cvss_score: '',
    affected_products: '',
    references: ''
  });
  const [manualCVEs, setManualCVEs] = useState([]);
  const [submitLoading, setSubmitLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');

  useEffect(() => {
    fetchSources();
    fetchManualCVEs();
  }, []);

  const fetchSources = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8000/api/ingestion-sources');
      if (!response.ok) throw new Error('Failed to fetch sources');
      const data = await response.json();
      setSources(data.sources);
    } catch (error) {
      console.error('Error fetching sources:', error);
      setMessage('Failed to load ingestion sources');
      setMessageType('error');
    } finally {
      setLoading(false);
    }
  };

  const fetchManualCVEs = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/manual-cves');
      if (!response.ok) throw new Error('Failed to fetch manual CVEs');
      const data = await response.json();
      setManualCVEs(data.cves);
    } catch (error) {
      console.error('Error fetching manual CVEs:', error);
    }
  };



  const handleManualCVEChange = (e) => {
    const { name, value } = e.target;
    setManualCVE(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmitManualCVE = async (e) => {
    e.preventDefault();
    
    if (!manualCVE.cve_id || !manualCVE.description) {
      setMessage('CVE ID and Description are required');
      setMessageType('error');
      return;
    }

    // Validate CVE ID format
    const cveRegex = /^CVE-\d{4}-\d{4,}$/;
    if (!cveRegex.test(manualCVE.cve_id)) {
      setMessage('Invalid CVE ID format. Use CVE-YYYY-XXXXX');
      setMessageType('error');
      return;
    }

    // Validate CVSS if provided
    if (manualCVE.cvss_score && (isNaN(manualCVE.cvss_score) || manualCVE.cvss_score < 0 || manualCVE.cvss_score > 10)) {
      setMessage('CVSS score must be between 0 and 10');
      setMessageType('error');
      return;
    }

    try {
      setSubmitLoading(true);
      const formData = new FormData();
      formData.append('cve_id', manualCVE.cve_id);
      formData.append('description', manualCVE.description);
      if (manualCVE.cvss_score) formData.append('cvss_score', parseFloat(manualCVE.cvss_score));
      if (manualCVE.affected_products) formData.append('affected_products', manualCVE.affected_products);
      if (manualCVE.references) formData.append('references', manualCVE.references);

      const response = await fetch('http://localhost:8000/api/manual-cve', {
        method: 'POST',
        body: formData,
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to add CVE');
      }

      const data = await response.json();
      setMessage(`✅ ${data.message}`);
      setMessageType('success');
      
      // Reset form
      setManualCVE({
        cve_id: '',
        description: '',
        cvss_score: '',
        affected_products: '',
        references: ''
      });

      // Refresh manual CVEs
      fetchManualCVEs();

      // Clear message after 5 seconds
      setTimeout(() => setMessage(''), 5000);
    } catch (error) {
      setMessage(error.message || 'Failed to add manual CVE');
      setMessageType('error');
    } finally {
      setSubmitLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return '#d32f2f';
      case 'HIGH':
        return '#f57c00';
      case 'MEDIUM':
        return '#fbc02d';
      case 'LOW':
        return '#388e3c';
      default:
        return '#757575';
    }
  };

  return (
    <div className="multi-source-ingestion">
      <div className="ingestion-header">
        <h2>CVE Ingestion Management</h2>
        <p>Manage CVE data from multiple sources</p>
      </div>

      {message && (
        <div className={`message message-${messageType}`}>
          {message}
        </div>
      )}

      <div className="ingestion-tabs">
        <button 
          className={`tab-button ${activeTab === 'sources' ? 'active' : ''}`}
          onClick={() => setActiveTab('sources')}
        >
          📡 Ingestion Sources
        </button>
        <button 
          className={`tab-button ${activeTab === 'manual' ? 'active' : ''}`}
          onClick={() => setActiveTab('manual')}
        >
          ✏️ Manual Entry
        </button>
      </div>

      {/* Sources Tab */}
      {activeTab === 'sources' && (
        <div className="tab-content">
          {loading ? (
            <div className="loading">Loading ingestion sources...</div>
          ) : (
            <div className="sources-grid">
              {sources.map((source) => (
                <div key={source.id} className="source-card">
                  <div className="source-header">
                    <h3>{source.name}</h3>
                    <span className={`status-badge ${source.enabled ? 'enabled' : 'disabled'}`}>
                      {source.enabled ? '✅ Enabled' : '⚪ Disabled'}
                    </span>
                  </div>
                  <p className="source-description">{source.description}</p>
                  
                  <div className="source-details">
                    <div className="detail-row">
                      <span className="label">Frequency:</span>
                      <span className="value">{source.frequency}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">CVEs Imported:</span>
                      <span className="value"><strong>{source.cve_count}</strong></span>
                    </div>
                    {source.requires_auth && (
                      <div className="detail-row auth-required">
                        <span className="label">⚠️ Requires API Key</span>
                      </div>
                    )}
                  </div>

                  <div className="source-status">
                    {source.id === 'nvd' && (
                      <p className="status-info">🔄 Primary source - Always enabled</p>
                    )}
                    {source.id === 'manual' && (
                      <p className="status-info">✏️ Add CVEs manually via the form</p>
                    )}
                    {source.enabled && !source.requires_auth && source.id !== 'nvd' && source.id !== 'manual' && (
                      <p className="status-info">✅ Ingesting CVEs automatically</p>
                    )}
                    {!source.enabled && source.requires_auth && (
                      <p className="status-info">🔐 Configure API credentials to enable</p>
                    )}
                    {!source.enabled && !source.requires_auth && source.id !== 'nvd' && (
                      <p className="status-info">⏸️ Not currently enabled</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Manual Entry Tab */}
      {activeTab === 'manual' && (
        <div className="tab-content">
          <div className="manual-entry-container">
            <div className="entry-form-section">
              <h3>Add New CVE Manually</h3>
              <form onSubmit={handleSubmitManualCVE} className="manual-cve-form">
                <div className="form-group">
                  <label htmlFor="cve_id">CVE ID * <span className="required">(required)</span></label>
                  <input
                    type="text"
                    id="cve_id"
                    name="cve_id"
                    placeholder="CVE-YYYY-XXXXX (e.g., CVE-2026-12345)"
                    value={manualCVE.cve_id}
                    onChange={handleManualCVEChange}
                    className="form-input"
                  />
                  <small>Format: CVE-YYYY-XXXXX where XXXXX is at least 4 digits</small>
                </div>

                <div className="form-group">
                  <label htmlFor="description">Description * <span className="required">(required)</span></label>
                  <textarea
                    id="description"
                    name="description"
                    placeholder="Enter CVE description..."
                    value={manualCVE.description}
                    onChange={handleManualCVEChange}
                    rows={4}
                    className="form-textarea"
                  />
                  <small>Products will be automatically extracted using NLP</small>
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="cvss_score">CVSS Score (0-10)</label>
                    <input
                      type="number"
                      id="cvss_score"
                      name="cvss_score"
                      placeholder="5.0"
                      value={manualCVE.cvss_score}
                      onChange={handleManualCVEChange}
                      min="0"
                      max="10"
                      step="0.1"
                      className="form-input"
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label htmlFor="affected_products">Affected Products (JSON)</label>
                  <textarea
                    id="affected_products"
                    name="affected_products"
                    placeholder='[{"vendor":"Microsoft","product":"Windows 10"}]'
                    value={manualCVE.affected_products}
                    onChange={handleManualCVEChange}
                    rows={2}
                    className="form-textarea"
                  />
                  <small>Optional. Leave empty to auto-extract from description</small>
                </div>

                <div className="form-group">
                  <label htmlFor="references">References (JSON)</label>
                  <textarea
                    id="references"
                    name="references"
                    placeholder='["https://example.com/advisory"]'
                    value={manualCVE.references}
                    onChange={handleManualCVEChange}
                    rows={2}
                    className="form-textarea"
                  />
                </div>

                <button
                  type="submit"
                  disabled={submitLoading}
                  className="btn-submit"
                >
                  {submitLoading ? 'Adding CVE...' : '➕ Add CVE'}
                </button>
              </form>
            </div>

            <div className="recent-manual-cves">
              <h3>Recently Added Manual CVEs ({manualCVEs.length})</h3>
              {manualCVEs.length === 0 ? (
                <p className="no-data">No manual CVEs yet</p>
              ) : (
                <div className="cves-list">
                  {manualCVEs.slice(0, 10).map((cve) => (
                    <div key={cve.cve_id} className="manual-cve-item">
                      <div className="cve-header">
                        <span className="cve-id">{cve.cve_id}</span>
                        <span 
                          className="severity-badge"
                          style={{ backgroundColor: getSeverityColor(cve.severity) }}
                        >
                          {cve.severity}
                        </span>
                        <span className="cvss-score">CVSS: {cve.cvss_score}</span>
                      </div>
                      <p className="cve-desc">{cve.description.substring(0, 200)}...</p>
                      <div className="cve-meta">
                        <small>Added by: {cve.created_by} on {new Date(cve.created_at).toLocaleDateString()}</small>
                        <span className="status">{cve.status}</span>
                      </div>
                      {cve.affected_products && cve.affected_products.length > 0 && (
                        <div className="products-preview">
                          {cve.affected_products.map((prod, idx) => (
                            <span key={idx} className="product-badge">
                              {prod.vendor}: {prod.product}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MultiSourceIngestion;
