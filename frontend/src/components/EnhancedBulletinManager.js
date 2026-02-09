"""
Enhanced Bulletin Management Component - Frontend React
Features:
- Automatic CVE grouping by technology/product
- Region selection and management
- Attachment support
- Multiple status management (Draft, Send, Not Processed)
- Bulletin storage and retrieval
"""
import React, { useState, useEffect } from 'react';
import './EnhancedBulletinManager.css';

function EnhancedBulletinManager({ user }) {
  const [bulletins, setBulletins] = useState([]);
  const [regions, setRegions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('list');
  
  // Form states
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [cveInput, setCveInput] = useState('');
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [attachments, setAttachments] = useState([]);
  
  // Selected bulletin details
  const [selectedBulletin, setSelectedBulletin] = useState(null);
  const [bulletinDetails, setBulletinDetails] = useState(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);

  // Load data on mount
  useEffect(() => {
    fetchRegions();
    fetchBulletins();
  }, []);

  // ========== FETCH FUNCTIONS ==========

  const fetchRegions = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/regions');
      const data = await response.json();
      if (response.ok) {
        setRegions(Array.isArray(data) ? data : data.regions || []);
      }
    } catch (error) {
      console.error('Error fetching regions:', error);
    }
  };

  const fetchBulletins = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8000/api/bulletins');
      const data = await response.json();
      if (data.success) {
        setBulletins(data.bulletins || []);
      }
    } catch (error) {
      console.error('Error fetching bulletins:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchBulletinDetails = async (bulletinId) => {
    try {
      const response = await fetch(`http://localhost:8000/api/bulletins/bulletins/${bulletinId}`);
      const data = await response.json();
      if (data.success) {
        setBulletinDetails(data.bulletin);
        setShowDetailsModal(true);
      }
    } catch (error) {
      console.error('Error fetching bulletin details:', error);
    }
  };

  // ========== CREATE BULLETIN WITH GROUPING ==========

  const handleCreateBulletin = async (e) => {
    e.preventDefault();
    
    try {
      setLoading(true);
      
      const formData = new FormData();
      formData.append('title', title);
      formData.append('body', body);
      formData.append('regions', JSON.stringify(selectedRegions));
      formData.append('cve_ids', cveInput);
      formData.append('created_by', user.username);

      const response = await fetch(
        'http://localhost:8000/api/bulletins/create-with-grouping',
        {
          method: 'POST',
          body: formData
        }
      );

      const data = await response.json();

      if (data.success) {
        alert(`✅ Bulletin created with ${data.bulletin.groupings.length} technology groups!`);
        
        // Reset form
        setTitle('');
        setBody('');
        setCveInput('');
        setSelectedRegions([]);
        setAttachments([]);
        setActiveTab('list');
        
        // Refresh bulletins list
        fetchBulletins();
      } else {
        alert('❌ Error creating bulletin');
      }
    } catch (error) {
      console.error('Error creating bulletin:', error);
      alert('❌ Server error');
    } finally {
      setLoading(false);
    }
  };

  // ========== UPLOAD ATTACHMENTS ==========

  const handleFileUpload = async (bulletinId, file, attachmentType, description) => {
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('attachment_type', attachmentType);
      formData.append('description', description);
      formData.append('uploaded_by', user.username);

      const response = await fetch(
        `http://localhost:8000/api/bulletins/bulletins/${bulletinId}/attachments`,
        {
          method: 'POST',
          body: formData
        }
      );

      const data = await response.json();

      if (data.success) {
        alert(`✅ Attachment '${file.name}' added successfully!`);
        // Refresh details
        fetchBulletinDetails(bulletinId);
      } else {
        alert('❌ Error adding attachment');
      }
    } catch (error) {
      console.error('Error uploading attachment:', error);
      alert('❌ Erreur serveur');
    }
  };

  // ========== UPDATE BULLETIN STATUS ==========

  const handleStatusChange = async (bulletinId, newStatus) => {
    try {
      const formData = new FormData();
      formData.append('status', newStatus);
      formData.append('updated_by', user.username);
      formData.append('reason', `Changed by ${user.username}`);

      const response = await fetch(
        `http://localhost:8000/api/bulletins/bulletins/${bulletinId}/status`,
        {
          method: 'PUT',
          body: formData
        }
      );

      const data = await response.json();

      if (data.success) {
        alert(`✅ Bulletin status updated: ${newStatus}`);
        fetchBulletins();
        fetchBulletinDetails(bulletinId);
      }
    } catch (error) {
      console.error('Error updating status:', error);
    }
  };

  // ========== SEND BULLETIN ==========

  const handleSendBulletin = async (bulletinId, bulletin) => {
    try {
      const formData = new FormData();
      formData.append('regions', JSON.stringify(bulletin.regions));
      formData.append('delivery_method', 'EMAIL');
      formData.append('sent_by', user.username);

      const response = await fetch(
        `http://localhost:8000/api/bulletins/bulletins/${bulletinId}/send`,
        {
          method: 'POST',
          body: formData
        }
      );

      const data = await response.json();

      if (data.success) {
        alert(`✅ Bulletin sent to ${data.regions_sent.length} regions!`);
        fetchBulletins();
        fetchBulletinDetails(bulletinId);
      }
    } catch (error) {
      console.error('Error sending bulletin:', error);
      alert('❌ Error sending');
    }
  };

  // ========== REGION SELECTION ==========

  const toggleRegion = (regionName) => {
    setSelectedRegions(prev =>
      prev.includes(regionName)
        ? prev.filter(r => r !== regionName)
        : [...prev, regionName]
    );
  };

  // ========== RENDER FUNCTIONS ==========

  const getStatusBadgeColor = (status) => {
    const colors = {
      DRAFT: '#9ca3af',
      SENT: '#10b981',
      NOT_PROCESSED: '#f59e0b',
      ARCHIVED: '#6b7280'
    };
    return colors[status] || '#6b7280';
  };

  return (
    <div className="enhanced-bulletin-container">
      {/* Header */}
      <div className="bulletin-header">
        <h1>📧 Security Bulletin Management</h1>
        <p>Create and manage bulletins with automatic CVE grouping</p>
      </div>

      {/* Tabs */}
      <div className="bulletin-tabs">
        <button
          className={`tab ${activeTab === 'list' ? 'active' : ''}`}
          onClick={() => setActiveTab('list')}
        >
          📋 Bulletin List
        </button>
        <button
          className={`tab ${activeTab === 'create' ? 'active' : ''}`}
          onClick={() => setActiveTab('create')}
        >
          ✏️ Create Bulletin
        </button>
        <button
          className={`tab ${activeTab === 'regions' ? 'active' : ''}`}
          onClick={() => setActiveTab('regions')}
        >
          🌍 Manage Regions
        </button>
      </div>

      {/* ========== LIST TAB ========== */}
      {activeTab === 'list' && (
        <div className="bulletin-list-section">
          <h2>Created Bulletins</h2>

          {loading ? (
            <p className="loader">⏳ Loading...</p>
          ) : bulletins.length === 0 ? (
            <p className="empty-state">No bulletins created. Start by creating one!</p>
          ) : (
            <div className="bulletin-cards">
              {bulletins.map((bulletin) => (
                <div key={bulletin.id} className="bulletin-card">
                  <div className="card-header">
                    <h3>{bulletin.title}</h3>
                    <span
                      className="status-badge"
                      style={{ backgroundColor: getStatusBadgeColor(bulletin.status) }}
                    >
                      {bulletin.status}
                    </span>
                  </div>

                  <div className="card-details">
                    <p>📅 Created on: {new Date(bulletin.created_at).toLocaleDateString('en-US')}</p>
                    <p>👤 By: {bulletin.created_by}</p>
                    <p>🔍 CVE included: {bulletin.cve_count}</p>
                    <p>🌍 Regions: {bulletin.regions.join(', ')}</p>
                  </div>

                  <div className="card-actions">
                    <button
                      className="btn btn-info"
                      onClick={() => fetchBulletinDetails(bulletin.id)}
                    >
                      👁️ Details
                    </button>
                    {bulletin.status === 'DRAFT' && (
                      <>
                        <button
                          className="btn btn-primary"
                          onClick={() => handleSendBulletin(bulletin.id, bulletin)}
                        >
                          ✉️ Send
                        </button>
                        <button
                          className="btn btn-secondary"
                          onClick={() => handleStatusChange(bulletin.id, 'NOT_PROCESSED')}
                        >
                          ⏸️ Postpone
                        </button>
                      </>
                    )}
                    {bulletin.status === 'SENT' && (
                      <button
                        className="btn btn-secondary"
                        onClick={() => handleStatusChange(bulletin.id, 'ARCHIVED')}
                      >
                        📦 Archive
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ========== CREATE TAB ========== */}
      {activeTab === 'create' && (
        <div className="bulletin-create-section">
          <h2>Create a New Bulletin</h2>

          <form onSubmit={handleCreateBulletin} className="bulletin-form">
            {/* Title */}
            <div className="form-group">
              <label htmlFor="title">📝 Bulletin Title *</label>
              <input
                id="title"
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Ex: Security Bulletin - January 2024"
                required
                minLength="5"
              />
            </div>

            {/* Body */}
            <div className="form-group">
              <label htmlFor="body">📄 Bulletin Content</label>
              <textarea
                id="body"
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="Main bulletin content..."
                rows="6"
              />
            </div>

            {/* CVE IDs */}
            <div className="form-group">
              <label htmlFor="cve">🔍 CVEs to Include (comma separated)</label>
              <input
                id="cve"
                type="text"
                value={cveInput}
                onChange={(e) => setCveInput(e.target.value)}
                placeholder="CVE-2024-1234, CVE-2024-5678, CVE-2024-9012"
              />
              <small>CVEs will be automatically grouped by technology</small>
            </div>

            {/* Regions Selection */}
            <div className="form-group">
              <label>🌍 Distribution Regions *</label>
              <div className="region-selector">
                {regions.map((region) => (
                  <label key={region.id} className="region-checkbox">
                    <input
                      type="checkbox"
                      checked={selectedRegions.includes(region.name)}
                      onChange={() => toggleRegion(region.name)}
                    />
                    <span>{region.name}</span>
                    <small>{region.description}</small>
                  </label>
                ))}
              </div>
              {selectedRegions.length === 0 && (
                <p className="error">Select at least one region</p>
              )}
            </div>

            {/* File Attachments */}
            <div className="form-group">
              <label>📎 Attachments (optional)</label>
              <div className="attachment-uploader">
                <input
                  type="file"
                  multiple
                  onChange={(e) => setAttachments(Array.from(e.target.files))}
                  className="file-input"
                />
                <p>Files selected: {attachments.length}</p>
              </div>
            </div>

            {/* Submit Button */}
            <div className="form-actions">
              <button type="submit" className="btn btn-primary btn-large" disabled={loading}>
                {loading ? '⏳ Creating...' : '✅ Create Bulletin'}
              </button>
              <button
                type="reset"
                className="btn btn-secondary btn-large"
                onClick={() => {
                  setTitle('');
                  setBody('');
                  setCveInput('');
                  setSelectedRegions([]);
                  setAttachments([]);
                }}
              >
                🔄 Reset
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ========== REGIONS TAB ========== */}
      {activeTab === 'regions' && (
        <div className="bulletin-regions-section">
          <h2>Region Management</h2>
          <p>Regions can be added or archived without impacting historical data</p>

          <div className="regions-grid">
            {regions.map((region) => (
              <div key={region.id} className="region-card">
                <h3>{region.name}</h3>
                <p>{region.description}</p>
                <p className="recipient-count">
                  📧 {region.recipients.length} recipients
                </p>
                <button className="btn btn-secondary">Archive</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========== DETAILS MODAL ========== */}
      {showDetailsModal && bulletinDetails && (
        <div className="modal-overlay" onClick={() => setShowDetailsModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{bulletinDetails.title}</h2>
              <button className="close-btn" onClick={() => setShowDetailsModal(false)}>✕</button>
            </div>

            <div className="modal-body">
              {/* General Info */}
              <section className="modal-section">
                <h3>📋 General Information</h3>
                <div className="info-grid">
                  <div><strong>Status:</strong> {bulletinDetails.status}</div>
                  <div><strong>Created by:</strong> {bulletinDetails.created_by}</div>
                  <div><strong>Date:</strong> {new Date(bulletinDetails.created_at).toLocaleDateString('en-US')}</div>
                  <div><strong>Regions:</strong> {bulletinDetails.regions.join(', ')}</div>
                </div>
              </section>

              {/* CVE Groupings */}
              {bulletinDetails.groupings && bulletinDetails.groupings.length > 0 && (
                <section className="modal-section">
                  <h3>🔍 CVE Grouping by Technology</h3>
                  <div className="groupings-container">
                    {bulletinDetails.groupings.map((grouping, idx) => (
                      <div key={idx} className="grouping-card">
                        <h4>{grouping.vendor} / {grouping.product}</h4>
                        <p className="cve-count">📊 {grouping.cve_count} CVE(s)</p>
                        <details>
                          <summary>Included CVEs</summary>
                          <ul>
                            {JSON.parse(grouping.cve_ids).map(cve => (
                              <li key={cve}>{cve}</li>
                            ))}
                          </ul>
                        </details>
                        {grouping.remediation_guidance && (
                          <div className="remediation">
                            <strong>Recommendations:</strong>
                            <p>{grouping.remediation_guidance}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Attachments */}
              {bulletinDetails.attachments && bulletinDetails.attachments.length > 0 && (
                <section className="modal-section">
                  <h3>📎 Attachments</h3>
                  <div className="attachments-list">
                    {bulletinDetails.attachments.map((attachment) => (
                      <div key={attachment.id} className="attachment-item">
                        <span>{attachment.filename}</span>
                        <small>Type: {attachment.attachment_type}</small>
                        <button className="btn btn-small">⬇️ Download</button>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Delivery Status */}
              {bulletinDetails.delivery_status && (
                <section className="modal-section">
                  <h3>📤 Delivery Status</h3>
                  <div className="delivery-stats">
                    <div>Total: {bulletinDetails.delivery_status.total}</div>
                    <div>Sent: {bulletinDetails.delivery_status.sent}</div>
                    <div>Failed: {bulletinDetails.delivery_status.failed}</div>
                  </div>
                </section>
              )}
            </div>

            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setShowDetailsModal(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default EnhancedBulletinManager;
