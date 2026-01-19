import React, { useState, useEffect } from 'react';
import './BulletinManagement.css';

function BulletinManagement() {
  const [bulletins, setBulletins] = useState([]);
  const [regions, setRegions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [selectedBulletin, setSelectedBulletin] = useState(null);
  const [previewData, setPreviewData] = useState(null);
  
  const [formData, setFormData] = useState({
    title: '',
    body: '',
    regions: [],
    cve_ids: []
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
  }, []);

  const fetchBulletins = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/bulletins?limit=50&offset=0');
      const data = await response.json();
      setBulletins(data.bulletins || []);
    } catch (error) {
      console.error('Erreur chargement bulletins:', error);
      alert('Erreur: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchRegions = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/regions');
      const data = await response.json();
      setRegions(data || []);
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

  // Créer bulletin
  const handleCreateBulletin = async (e) => {
    e.preventDefault();
    
    if (!formData.title.trim()) {
      alert('Le titre est requis');
      return;
    }
    
    if (formData.regions.length === 0) {
      alert('Sélectionnez au moins une région');
      return;
    }

    try {
      const response = await fetch('http://localhost:8000/api/bulletins', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          created_by: 'analyst1'
        })
      });

      if (!response.ok) throw new Error('Erreur création bulletin');
      
      alert('✅ Bulletin créé avec succès!');
      setFormData({ title: '', body: '', regions: [], cve_ids: [] });
      setShowCreateModal(false);
      fetchBulletins();
      fetchStats();
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

      if (!response.ok) throw new Error('Erreur aperçu');

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

      if (!response.ok) throw new Error('Erreur envoi');

      const data = await response.json();
      alert(testMode ? '✅ Mode test: Email enregistré en log' : '✅ Bulletin envoyé!');
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
        `📜 Historique Bulletin ${bulletinId}\n\n` +
        `Statut: ${data.bulletin.status}\n` +
        `Envoyés: ${data.statistics.total_sent}\n` +
        `Échoués: ${data.statistics.total_failed}\n` +
        `Taux réussite: ${data.statistics.success_rate.toFixed(1)}%\n\n` +
        `Logs:\n` +
        data.delivery_logs.map(l => `- ${l.action} à ${l.region}`).join('\n')
      );
    } catch (error) {
      console.error('Erreur:', error);
      alert('Erreur: ' + error.message);
    }
  };

  // Supprimer bulletin
  const handleDeleteBulletin = async (bulletinId) => {
    if (!window.confirm('Êtes-vous sûr?')) return;

    try {
      const response = await fetch(`http://localhost:8000/api/bulletins/${bulletinId}`, {
        method: 'DELETE'
      });

      if (!response.ok) throw new Error('Erreur');

      alert('✅ Bulletin supprimé');
      fetchBulletins();
      fetchStats();
    } catch (error) {
      console.error('Erreur:', error);
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
    return <div style={{ padding: '20px', textAlign: 'center' }}>⏳ Chargement...</div>;
  }

  return (
    <div className="bulletin-container">
      <div className="bulletin-header">
        <h1>📧 Gestion des Bulletins</h1>
        <button 
          className="btn-primary"
          onClick={() => setShowCreateModal(true)}
        >
          ➕ Nouveau Bulletin
        </button>
      </div>

      {/* Statistiques */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.total_bulletins}</div>
          <div className="stat-label">Bulletins Totaux</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.by_status?.DRAFT || 0}</div>
          <div className="stat-label">Brouillons</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.by_status?.SENT || 0}</div>
          <div className="stat-label">Envoyés</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.total_recipients_contacted || 0}</div>
          <div className="stat-label">Destinataires</div>
        </div>
      </div>

      {/* Liste des bulletins */}
      <div className="bulletins-list">
        <h2>Bulletins Récents</h2>
        {bulletins.length === 0 ? (
          <p style={{ color: '#999' }}>Aucun bulletin trouvé</p>
        ) : (
          <div className="table-responsive">
            <table className="bulletins-table">
              <thead>
                <tr>
                  <th>Titre</th>
                  <th>Régions</th>
                  <th>Statut</th>
                  <th>Créé par</th>
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
                        title="Aperçu"
                      >
                        👁️
                      </button>
                      <button
                        className="btn-small btn-history"
                        onClick={() => handleViewHistory(bulletin.id)}
                        title="Historique"
                      >
                        📜
                      </button>
                      <button
                        className="btn-small btn-delete"
                        onClick={() => handleDeleteBulletin(bulletin.id)}
                        title="Supprimer"
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
              <h2>Créer un Nouveau Bulletin</h2>
              <button
                className="btn-close"
                onClick={() => setShowCreateModal(false)}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateBulletin} className="form-bulletin">
              <div className="form-group">
                <label>Titre *</label>
                <input
                  type="text"
                  placeholder="Ex: Critical Security Update"
                  value={formData.title}
                  onChange={e => setFormData({ ...formData, title: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label>Contenu</label>
                <textarea
                  placeholder="Détails du bulletin..."
                  value={formData.body}
                  onChange={e => setFormData({ ...formData, body: e.target.value })}
                  rows="5"
                />
              </div>

              <div className="form-group">
                <label>Régions *</label>
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
                        ({region.recipients ? region.recipients.length : 0} destinataires)
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
                  Annuler
                </button>
                <button type="submit" className="btn-primary">
                  Créer Bulletin
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
              <h2>Aperçu & Envoi du Bulletin</h2>
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
                      <strong>{region}:</strong> {count} destinataires
                    </div>
                  ))}
                  <div className="recipient-card total">
                    <strong>Total:</strong> {previewData.total_recipients} destinataires
                  </div>
                </div>
              </div>

              <div className="email-preview">
                <h4>Aperçu Email</h4>
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
                  <strong>⚠️ Erreurs de validation:</strong>
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
                Fermer
              </button>
              <button
                type="button"
                className="btn-test"
                onClick={() => handleSendBulletin(selectedBulletin.id, true)}
                disabled={!previewData.is_valid}
              >
                🧪 Envoi Test (Log)
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={() => handleSendBulletin(selectedBulletin.id, false)}
                disabled={!previewData.is_valid}
              >
                📤 Envoyer Bulletin
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default BulletinManagement;
