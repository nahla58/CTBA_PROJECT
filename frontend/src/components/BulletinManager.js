import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './BulletinManager.css';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

/**
 * BulletinManager Component
 * 
 * Features:
 * - View all bulletins with filtering
 * - View detailed CVE grouping by technology
 * - Manage bulletin status (Draft, Send, Archive)
 * - Download attachments
 * - View delivery status and metrics
 */
const BulletinManager = () => {
  const [bulletins, setBulletins] = useState([]);
  const [selectedBulletin, setSelectedBulletin] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all'); // all, draft, sent, archived
  const [currentUser] = useState(localStorage.getItem('username') || 'user');

  useEffect(() => {
    // In a real app, would load bulletins from API
    // For now, load sample data
    loadBulletins();
  }, []);

  const loadBulletins = async () => {
    try {
      setLoading(true);
      // This would be: GET /api/bulletins/?status={filter}
      // For demo, we'll show placeholder
      console.log('Loading bulletins...');
    } catch (err) {
      setError('Failed to load bulletins');
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async (bulletinId, newStatus) => {
    try {
      await axios.patch(`${API_BASE}/bulletins/${bulletinId}/status`, {
        status: newStatus,
        updated_by: currentUser
      });

      // Update local state
      if (selectedBulletin && selectedBulletin.id === bulletinId) {
        setSelectedBulletin(prev => ({
          ...prev,
          status: newStatus
        }));
      }

      loadBulletins();
    } catch (err) {
      setError('Failed to update bulletin status');
      console.error(err);
    }
  };

  const handleDownloadAttachment = async (attachmentId, filename) => {
    try {
      const response = await axios.get(
        `${API_BASE}/bulletins/attachments/${attachmentId}/download`,
        { responseType: 'blob' }
      );
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.parentElement.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError('Failed to download attachment');
      console.error(err);
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      'DRAFT': '#95a5a6',
      'SENT': '#27ae60',
      'NOT_PROCESSED': '#f39c12',
      'ARCHIVED': '#7f8c8d'
    };
    return colors[status] || '#95a5a6';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'CRITICAL': '#e74c3c',
      'HIGH': '#e67e22',
      'MEDIUM': '#f39c12',
      'LOW': '#27ae60'
    };
    return colors[severity] || '#95a5a6';
  };

  if (!selectedBulletin) {
    return (
      <div className="bulletin-manager">
        <div className="manager-header">
          <h2>Security Bulletins</h2>
          <div className="filter-tabs">
            <button
              className={`tab ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
            >
              All
            </button>
            <button
              className={`tab ${filter === 'draft' ? 'active' : ''}`}
              onClick={() => setFilter('draft')}
            >
              Draft
            </button>
            <button
              className={`tab ${filter === 'sent' ? 'active' : ''}`}
              onClick={() => setFilter('sent')}
            >
              Sent
            </button>
            <button
              className={`tab ${filter === 'archived' ? 'active' : ''}`}
              onClick={() => setFilter('archived')}
            >
              Archived
            </button>
          </div>
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        {loading ? (
          <div className="loading">Loading bulletins...</div>
        ) : bulletins.length === 0 ? (
          <div className="empty-state">
            <p>No bulletins found</p>
          </div>
        ) : (
          <div className="bulletins-list">
            {bulletins.map(bulletin => (
              <div
                key={bulletin.id}
                className="bulletin-card"
                onClick={() => setSelectedBulletin(bulletin)}
              >
                <div className="bulletin-header">
                  <h3>{bulletin.title}</h3>
                  <span
                    className="status-badge"
                    style={{ backgroundColor: getStatusColor(bulletin.status) }}
                  >
                    {bulletin.status}
                  </span>
                </div>
                <div className="bulletin-meta">
                  <span>📅 {new Date(bulletin.created_at).toLocaleDateString()}</span>
                  <span>👤 {bulletin.created_by}</span>
                  <span>🔐 {bulletin.cve_count} CVEs</span>
                  <span>🌍 {bulletin.region_count} regions</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  // Detail view
  return (
    <div className="bulletin-detail">
      <button
        className="btn-back"
        onClick={() => setSelectedBulletin(null)}
      >
        ← Back to List
      </button>

      <div className="detail-header">
        <div>
          <h1>{selectedBulletin.title}</h1>
          <div className="meta-info">
            <span>Created: {new Date(selectedBulletin.created_at).toLocaleDateString()}</span>
            <span>By: {selectedBulletin.created_by}</span>
          </div>
        </div>
        <div className="status-actions">
          <span
            className="status-badge-large"
            style={{ backgroundColor: getStatusColor(selectedBulletin.status) }}
          >
            {selectedBulletin.status}
          </span>
          <div className="action-buttons">
            {selectedBulletin.status === 'DRAFT' && (
              <>
                <button
                  className="btn btn-success"
                  onClick={() => handleStatusChange(selectedBulletin.id, 'SENT')}
                >
                  Send Now
                </button>
                <button
                  className="btn btn-warning"
                  onClick={() => handleStatusChange(selectedBulletin.id, 'ARCHIVED')}
                >
                  Archive
                </button>
              </>
            )}
            {selectedBulletin.status === 'SENT' && (
              <button
                className="btn btn-secondary"
                onClick={() => handleStatusChange(selectedBulletin.id, 'ARCHIVED')}
              >
                Archive
              </button>
            )}
          </div>
        </div>
      </div>

      {selectedBulletin.body && (
        <div className="detail-section">
          <h3>Description</h3>
          <p>{selectedBulletin.body}</p>
        </div>
      )}

      {/* CVE GROUPING SECTION */}
      <div className="detail-section">
        <h3>Grouped Vulnerabilities</h3>
        {selectedBulletin.grouped_cves.length === 0 ? (
          <p className="empty">No CVEs grouped</p>
        ) : (
          <div className="cve-groups">
            {selectedBulletin.grouped_cves.map((group, idx) => (
              <div key={idx} className="cve-group">
                <div className="group-header">
                  <h4>{group.vendor} {group.product}</h4>
                  <span className="cve-count">{group.cve_count} CVE{group.cve_count !== 1 ? 's' : ''}</span>
                </div>

                {group.remediation_guidance && (
                  <div className="remediation-box">
                    <h5>Remediation Guidance</h5>
                    <p>{group.remediation_guidance}</p>
                  </div>
                )}

                <div className="cve-list">
                  {group.cves.map((cve, cveIdx) => (
                    <div key={cveIdx} className="cve-item">
                      <div className="cve-basic">
                        <code>{cve.cve_id}</code>
                        <span
                          className="severity-badge"
                          style={{ backgroundColor: getSeverityColor(cve.severity) }}
                        >
                          {cve.severity}
                        </span>
                        {cve.cvss_score && (
                          <span className="cvss-score">CVSS: {cve.cvss_score}</span>
                        )}
                      </div>
                      {cve.description && (
                        <p className="cve-description">{cve.description.substring(0, 200)}...</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* REGIONS SECTION */}
      <div className="detail-section">
        <h3>Delivery Regions</h3>
        {selectedBulletin.regions.length === 0 ? (
          <p className="empty">No regions selected</p>
        ) : (
          <div className="regions-list">
            {selectedBulletin.regions.map(region => (
              <div key={region.id} className="region-item">
                <h4>{region.name}</h4>
                {region.region_code && <small>{region.region_code}</small>}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ATTACHMENTS SECTION */}
      {selectedBulletin.attachments && selectedBulletin.attachments.length > 0 && (
        <div className="detail-section">
          <h3>Attachments</h3>
          <div className="attachments-list">
            {selectedBulletin.attachments.map(attachment => (
              <div key={attachment.id} className="attachment-item">
                <span className="attachment-name">{attachment.filename}</span>
                <span className="attachment-size">
                  ({(attachment.size / 1024).toFixed(2)} KB)
                </span>
                <button
                  className="btn btn-small"
                  onClick={() => handleDownloadAttachment(attachment.id, attachment.filename)}
                >
                  Download
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default BulletinManager;
