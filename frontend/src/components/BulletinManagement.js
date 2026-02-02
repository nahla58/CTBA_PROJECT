import React, { useState, useEffect } from 'react';
import './BulletinManagement.css';

function BulletinManagement() {
  const [bulletins, setBulletins] = useState([]);
  const [regions, setRegions] = useState([]);
  const [groupedCVEs, setGroupedCVEs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [showCVESelector, setShowCVESelector] = useState(false);
  const [selectedBulletin, setSelectedBulletin] = useState(null);
  const [previewData, setPreviewData] = useState(null);
  
  const [formData, setFormData] = useState({
    title: '',
    body: '',
    regions: [],
    cve_ids: [],
    attachments: [],
    status: 'DRAFT'
  });
  
  const [stats, setStats] = useState({
    total_bulletins: 0,
    by_status: {},
    total_recipients_contacted: 0
  });

  // Charger données au démarrage
  useEffect(() => {
    fetchBulletins();
    fetchRegions();
    fetchStats();
    fetchGroupedCVEs();
  }, []);

  const fetchBulletins = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/bulletins?limit=50&offset=0');
      const data = await response.json();
      setBulletins(data.bulletins || []);
    } catch (error) {
      console.error('Erreur chargement bulletins:', error);
      alert('Error: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchRegions = async () => {
    try {
      // Define regions per specification
      const specRegions = [
        { id: 1, name: 'NORAM', description: 'North American region', recipients: ['admin@noram.local'] },
        { id: 2, name: 'LATAM', description: 'Latin American region', recipients: ['admin@latam.local'] },
        { id: 3, name: 'EUROPE', description: 'European region', recipients: ['admin@europe.local'] },
        { id: 4, name: 'APMEA', description: 'Asia-Pacific and Middle East & Africa', recipients: ['admin@apmea.local'] }
      ];
      setRegions(specRegions);
    } catch (error) {
      console.error('Erreur chargement régions:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/bulletins/stats/overview');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Erreur chargement stats:', error);
    }
  };

  const fetchGroupedCVEs = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/cves/grouped?status=ACCEPTED');
      const data = await response.json();
      setGroupedCVEs(data.groups || []);
    } catch (error) {
      console.error('Erreur chargement CVEs groupées:', error);
    }
  };

  // Créer bulletin
  const handleCreateBulletin = async (e) => {
    e.preventDefault();
    
    if (!formData.title.trim()) {
      alert('Title is required');
      return;
    }
    
    if (formData.regions.length === 0) {
      alert('Select at least one region');
      return;
    }

    try {
      const response = await fetch('http://localhost:8000/api/bulletins', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          title: formData.title,
          body: formData.body || null,
          regions: formData.regions,
          cve_ids: formData.cve_ids && formData.cve_ids.length > 0 ? formData.cve_ids : null
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error('Error details:', errorData);
        
        // FastAPI validation errors are in detail array
        let errorMsg = 'Bulletin creation error';
        if (errorData.detail) {
          if (Array.isArray(errorData.detail)) {
            errorMsg = errorData.detail.map(err => `${err.loc?.join('.')} - ${err.msg}`).join(', ');
          } else {
            errorMsg = errorData.detail;
          }
        }
        console.log('Error message:', errorMsg);
        throw new Error(errorMsg);
      }
      
      const newBulletin = await response.json();
      
      // Update UI immediately
      setBulletins([newBulletin, ...bulletins]);
      setStats(prev => ({
        ...prev,
        total_bulletins: (prev.total_bulletins || 0) + 1,
        by_status: {
          ...prev.by_status,
          DRAFT: (prev.by_status?.DRAFT || 0) + 1
        }
      }));
      
      alert('✅ Bulletin created successfully!');
      setFormData({ title: '', body: '', regions: [], cve_ids: [], attachments: [], status: 'DRAFT' });
      setShowCreateModal(false);
    } catch (error) {
      console.error('Erreur:', error);
      alert('Erreur: ' + error.message);
    }
  };

  // Afficher aperçu
  const handlePreview = async (bulletin) => {
    try {
      const response = await fetch(
        `http://localhost:8000/api/bulletins/${bulletin.id}/preview`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ regions: bulletin.regions })
        }
      );

      if (!response.ok) throw new Error('Preview error');

      const data = await response.json();
      setPreviewData(data);
      setSelectedBulletin(bulletin);
      setShowPreviewModal(true);
    } catch (error) {
      console.error('Erreur:', error);
      alert('Erreur: ' + error.message);
    }
  };

  // Envoyer bulletin
  const handleSendBulletin = async (bulletinId, testMode = false) => {
    try {
      const bulletin = bulletins.find(b => b.id === bulletinId);
      
      const response = await fetch(
        `http://localhost:8000/api/bulletins/${bulletinId}/send`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            test_mode: testMode,
            regions: bulletin.regions 
          })
        }
      );

      if (!response.ok) throw new Error('Send error');

      const data = await response.json();
      alert(testMode ? '✅ Test mode: Email logged' : '✅ Bulletin sent!');
      setShowPreviewModal(false);
      
      // Traiter la queue
      setTimeout(() => {
        fetch('http://localhost:8000/api/bulletins/process-queue', { method: 'POST' });
        fetchBulletins();
        fetchStats();
      }, 1000);
    } catch (error) {
      console.error('Erreur:', error);
      alert('Erreur: ' + error.message);
    }
  };

  // Voir historique
  const handleViewHistory = async (bulletinId) => {
    try {
      const response = await fetch(`http://localhost:8000/api/bulletins/${bulletinId}/history`);
      if (!response.ok) throw new Error('Erreur');

      const data = await response.json();
      alert(
        `📜 Bulletin History ${bulletinId}\n\n` +
        `Status: ${data.bulletin.status}\n` +
        `Sent: ${data.statistics.total_sent}\n` +
        `Failed: ${data.statistics.total_failed}\n` +
        `Success rate: ${data.statistics.success_rate.toFixed(1)}%\n\n` +
        `Logs:\n` +
        data.delivery_logs.map(l => `- ${l.action} to ${l.region}`).join('\n')
      );
    } catch (error) {
      console.error('Erreur:', error);
      alert('Erreur: ' + error.message);
    }
  };

  // Supprimer bulletin
  const handleDeleteBulletin = async (bulletinId) => {
    if (!window.confirm('Are you sure?')) return;

    try {
      // Remove from UI immediately (optimistic update)
      const deletedBulletin = bulletins.find(b => b.id !== bulletinId);
      setBulletins(bulletins.filter(b => b.id !== bulletinId));
      
      if (deletedBulletin?.status) {
        setStats(prev => ({
          ...prev,
          total_bulletins: (prev.total_bulletins || 1) - 1,
          by_status: {
            ...prev.by_status,
            [deletedBulletin.status]: Math.max((prev.by_status?.[deletedBulletin.status] || 1) - 1, 0)
          }
        }));
      }
      
      // Then delete from server
      const response = await fetch(`http://localhost:8000/api/bulletins/${bulletinId}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        throw new Error('Error');
      }

      alert('✅ Bulletin deleted');
    } catch (error) {
      console.error('Erreur:', error);
      // Restore UI on error
      fetchBulletins();
      fetchStats();
      alert('Erreur: ' + error.message);
    }
  };

  // Close bulletin
  const handleCloseBulletin = async (bulletinId) => {
    const reason = window.prompt('Enter closure reason:');
    if (!reason) return;

    try {
      const response = await fetch(`http://localhost:8000/api/bulletins/${bulletinId}/close`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ closure_reason: reason })
      });

      if (!response.ok) throw new Error('Error closing bulletin');

      alert('✅ Bulletin closed successfully');
      fetchBulletins();
      fetchStats();
    } catch (error) {
      console.error('Error:', error);
      alert('Error: ' + error.message);
    }
  };

  // Reopen bulletin
  const handleReopenBulletin = async (bulletinId) => {
    const reason = window.prompt('Enter reason for reopening (optional):');

    try {
      const response = await fetch(`http://localhost:8000/api/bulletins/${bulletinId}/reopen`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ reopen_reason: reason || null })
      });

      if (!response.ok) throw new Error('Error reopening bulletin');

      alert('✅ Bulletin reopened successfully');
      fetchBulletins();
      fetchStats();
    } catch (error) {
      console.error('Error:', error);
      alert('Error: ' + error.message);
    }
  };

  // View reminder status
  const handleViewReminderStatus = async (bulletinId) => {
    try {
      const response = await fetch(`http://localhost:8000/api/bulletins/${bulletinId}/reminder-status`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Error fetching reminder status');

      const data = await response.json();
      
      alert(
        `📨 Reminder Status for Bulletin #${bulletinId}\n\n` +
        `Status: ${data.status}\n` +
        `Sent: ${data.sent_at || 'N/A'}\n` +
        `Days since sent: ${data.days_since_sent || 'N/A'}\n\n` +
        `7-day reminder: ${data.reminder_7_sent ? '✅ Sent at ' + data.reminder_7_sent_at : '❌ Not sent'}\n` +
        `14-day reminder: ${data.reminder_14_sent ? '✅ Sent at ' + data.reminder_14_sent_at : '❌ Not sent'}\n` +
        `30-day escalation: ${data.escalation_30_sent ? '🔴 Sent at ' + data.escalation_30_sent_at : '❌ Not sent'}\n\n` +
        `Closed: ${data.is_closed ? '✅ Yes at ' + data.closed_at : '❌ No'}`
      );
    } catch (error) {
      console.error('Error:', error);
      alert('Error: ' + error.message);
    }
  };

  // Supprimer bulletin
  const handleDeleteBulletin_old = async (bulletinId) => {
    if (!window.confirm('Are you sure?')) return;

    try {
      // Remove from UI immediately (optimistic update)
      const deletedBulletin = bulletins.find(b => b.id === bulletinId);
      setBulletins(bulletins.filter(b => b.id !== bulletinId));
      
      if (deletedBulletin?.status) {
        setStats(prev => ({
          ...prev,
          total_bulletins: (prev.total_bulletins || 1) - 1,
          by_status: {
            ...prev.by_status,
            [deletedBulletin.status]: Math.max((prev.by_status?.[deletedBulletin.status] || 1) - 1, 0)
          }
        }));
      }
      
      // Then delete from server
      const response = await fetch(`http://localhost:8000/api/bulletins/${bulletinId}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        throw new Error('Error');
      }

      alert('✅ Bulletin deleted');
    } catch (error) {
      console.error('Erreur:', error);
      // Restore UI on error
      fetchBulletins();
      fetchStats();
      alert('Erreur: ' + error.message);
    }
  };

  const handleRegionToggle = (regionName) => {
    setFormData(prev => ({
      ...prev,
      regions: prev.regions.includes(regionName)
        ? prev.regions.filter(r => r !== regionName)
        : [...prev.regions, regionName]
    }));
  };

  if (loading) {
    return <div style={{ padding: '20px', textAlign: 'center' }}>⏳ Loading...</div>;
  }

  return (
    <div className="bulletin-container">
      <div className="bulletin-header">
        <h1>📧 Bulletin Management</h1>
        <button 
          className="btn-primary"
          onClick={() => setShowCreateModal(true)}
        >
          ➕ New Bulletin
        </button>
      </div>

      {/* Statistiques */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.total_bulletins}</div>
          <div className="stat-label">Total Bulletins</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.by_status?.DRAFT || 0}</div>
          <div className="stat-label">Drafts</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.by_status?.SENT || 0}</div>
          <div className="stat-label">Sent</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.total_recipients_contacted || 0}</div>
          <div className="stat-label">Recipients</div>
        </div>
      </div>

      {/* Liste des bulletins */}
      <div className="bulletins-list">
        <h2>Recent Bulletins</h2>
        {bulletins.length === 0 ? (
          <p style={{ color: '#999' }}>No bulletins found</p>
        ) : (
          <div className="table-responsive">
            <table className="bulletins-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Regions</th>
                  <th>Status</th>
                  <th>Created by</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {bulletins.map(bulletin => (
                  <tr key={bulletin.id}>
                    <td><strong>{bulletin.title}</strong></td>
                    <td>{bulletin.regions.join(', ')}</td>
                    <td>
                      <span className={`status-badge status-${bulletin.status.toLowerCase()}`}>
                        {bulletin.status}
                      </span>
                    </td>
                    <td>{bulletin.created_by}</td>
                    <td className="actions">
                      <button
                        className="btn-small btn-preview"
                        onClick={() => handlePreview(bulletin)}
                        title="Preview"
                      >
                        👁️
                      </button>
                      <button
                        className="btn-small btn-history"
                        onClick={() => handleViewHistory(bulletin.id)}
                        title="History"
                      >
                        📜
                      </button>
                      <button
                        className="btn-small btn-info"
                        onClick={() => handleViewReminderStatus(bulletin.id)}
                        title="Reminder Status"
                      >
                        📨
                      </button>
                      {bulletin.status === 'SENT' && (
                        <button
                          className="btn-small btn-primary"
                          onClick={() => handleCloseBulletin(bulletin.id)}
                          title="Close Bulletin"
                        >
                          ✅
                        </button>
                      )}
                      {bulletin.status === 'CLOSED' && (
                        <button
                          className="btn-small btn-warning"
                          onClick={() => handleReopenBulletin(bulletin.id)}
                          title="Reopen Bulletin"
                        >
                          🔄
                        </button>
                      )}
                      <button
                        className="btn-small btn-delete"
                        onClick={() => handleDeleteBulletin(bulletin.id)}
                        title="Delete"
                      >
                        🗑️
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal Création */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Create a New Bulletin</h2>
              <button
                className="btn-close"
                onClick={() => setShowCreateModal(false)}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateBulletin} className="form-bulletin">
              <div className="form-group">
                <label>Title *</label>
                <input
                  type="text"
                  placeholder="Ex: Critical Security Update"
                  value={formData.title}
                  onChange={e => setFormData({ ...formData, title: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label>Content</label>
                <textarea
                  placeholder="Bulletin details..."
                  value={formData.body}
                  onChange={e => setFormData({ ...formData, body: e.target.value })}
                  rows="5"
                />
              </div>

              <div className="form-group">
                <label>Status</label>
                <select
                  value={formData.status}
                  onChange={e => setFormData({ ...formData, status: e.target.value })}
                >
                  <option value="DRAFT">📝 Draft</option>
                  <option value="SENT">✅ Sent</option>
                  <option value="NOT_PROCESSED">⏳ Not Processed</option>
                </select>
              </div>

              <div className="form-group">
                <label>Validated CVEs (Grouped) *</label>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowCVESelector(true)}
                  style={{ marginTop: '8px' }}
                >
                  📊 Select Grouped CVEs ({groupedCVEs.length} groups)
                </button>
                {formData.cve_ids.length > 0 && (
                  <div style={{ marginTop: '8px', padding: '8px', backgroundColor: '#f0f0f0', borderRadius: '4px', fontSize: '12px' }}>
                    <strong>{formData.cve_ids.length} CVE(s) selected</strong>
                  </div>
                )}
              </div>

              <div className="form-group">
                <label>Attachments</label>
                <input
                  type="file"
                  multiple
                  onChange={(e) => {
                    const files = Array.from(e.target.files).map(f => f.name);
                    setFormData({ ...formData, attachments: files });
                  }}
                />
                {formData.attachments.length > 0 && (
                  <div style={{ marginTop: '8px', fontSize: '12px', color: '#666' }}>
                    <strong>Files:</strong> {formData.attachments.join(', ')}
                  </div>
                )}
              </div>

              <div className="form-group">
                <label>Regions *</label>
                <div className="regions-checkboxes">
                  {regions.map(region => (
                    <label key={region.id} className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={formData.regions.includes(region.name)}
                        onChange={() => handleRegionToggle(region.name)}
                      />
                      {region.name}
                      <span style={{ fontSize: '12px', color: '#999' }}>
                        ({region.recipients ? region.recipients.length : 0} recipients)
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowCreateModal(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  Create Bulletin
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal Aperçu */}
      {showPreviewModal && previewData && (
        <div className="modal-overlay" onClick={() => setShowPreviewModal(false)}>
          <div className="modal-content large" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Bulletin Preview & Send</h2>
              <button
                className="btn-close"
                onClick={() => setShowPreviewModal(false)}
              >
                ✕
              </button>
            </div>

            <div className="preview-content">
              <div className="preview-info">
                <h3>{previewData.title}</h3>
                <div className="recipients-info">
                  {Object.entries(previewData.recipient_counts).map(([region, count]) => (
                    <div key={region} className="recipient-card">
                      <strong>{region}:</strong> {count} recipients
                    </div>
                  ))}
                  <div className="recipient-card total">
                    <strong>Total:</strong> {previewData.total_recipients} recipients
                  </div>
                </div>
              </div>

              <div className="email-preview">
                <h4>Email Preview</h4>
                <iframe
                  srcDoc={previewData.preview_html}
                  style={{
                    width: '100%',
                    height: '400px',
                    border: '1px solid #ddd',
                    borderRadius: '4px'
                  }}
                  title="Email Preview"
                />
              </div>

              {previewData.validation_errors.length > 0 && (
                <div className="error-box">
                  <strong>⚠️ Validation errors:</strong>
                  <ul>
                    {previewData.validation_errors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setShowPreviewModal(false)}
              >
                Close
              </button>
              <button
                type="button"
                className="btn-test"
                onClick={() => handleSendBulletin(selectedBulletin.id, true)}
                disabled={!previewData.is_valid}
              >
                🧪 Test Send (Log)
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={() => handleSendBulletin(selectedBulletin.id, false)}
                disabled={!previewData.is_valid}
              >
                📤 Send Bulletin
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Sélecteur CVEs Groupées */}
      {showCVESelector && (
        <div className="modal-overlay" onClick={() => setShowCVESelector(false)}>
          <div className="modal-content large" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>📊 Validated CVEs Grouped by Technology and Remediation</h2>
              <button
                className="btn-close"
                onClick={() => setShowCVESelector(false)}
              >
                ✕
              </button>
            </div>

            <div className="cve-groups-container">
              {groupedCVEs.length === 0 ? (
                <p style={{ color: '#999' }}>No validated CVEs found</p>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '16px' }}>
                  {groupedCVEs.map((group, idx) => (
                    <div 
                      key={idx} 
                      style={{
                        border: '1px solid #ddd',
                        borderRadius: '8px',
                        padding: '12px',
                        backgroundColor: formData.cve_ids.some(cveId => group.cves.some(c => c.cve_id === cveId)) ? '#e8f5e9' : '#fff'
                      }}
                    >
                      <div style={{ marginBottom: '8px' }}>
                        <strong style={{ fontSize: '14px' }}>
                          {group.vendor}:{group.product}
                        </strong>
                        <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
                          📊 {group.cve_count} CVE(s)
                        </div>
                      </div>

                      {group.remediation && (
                        <div style={{ 
                          fontSize: '12px', 
                          backgroundColor: '#f5f5f5', 
                          padding: '6px', 
                          borderRadius: '4px',
                          marginBottom: '8px',
                          maxHeight: '60px',
                          overflow: 'auto'
                        }}>
                          <strong>Remediation:</strong> {group.remediation}
                        </div>
                      )}

                      <div style={{ fontSize: '11px', color: '#888', marginBottom: '8px' }}>
                        Severities: {Object.entries(group.severity_levels || {}).map(([sev, count]) => `${sev}(${count})`).join(', ')}
                      </div>

                      <button
                        type="button"
                        className={formData.cve_ids.some(cveId => group.cves.some(c => c.cve_id === cveId)) ? 'btn-primary' : 'btn-secondary'}
                        onClick={() => {
                          const cveIds = group.cves.map(c => c.cve_id);
                          setFormData(prev => ({
                            ...prev,
                            cve_ids: prev.cve_ids.some(id => cveIds.includes(id))
                              ? prev.cve_ids.filter(id => !cveIds.includes(id))
                              : [...prev.cve_ids, ...cveIds]
                          }));
                        }}
                        style={{ width: '100%' }}
                      >
                        {formData.cve_ids.some(cveId => group.cves.some(c => c.cve_id === cveId)) ? '✅ Selected' : '⬜ Select'}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setShowCVESelector(false)}
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

export default BulletinManagement;
