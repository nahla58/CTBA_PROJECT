import React, { useState, useEffect } from 'react';
import './ActionHistory.css';

function ActionHistory({ user, onLogout }) {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');

  useEffect(() => {
    fetchActionHistory();
  }, [filter]);

  const fetchActionHistory = async () => {
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams();
      if (filter !== 'ALL') {
        params.append('action', filter);
      }
      
      const response = await fetch(
        `http://localhost:8000/api/cve-actions?${params.toString()}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );

      if (response.ok) {
        const data = await response.json();
        // Extract actions from the paginated response
        setActions(data.actions || []);
      }
      setLoading(false);
    } catch (error) {
      console.error('Error fetching action history:', error);
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('fr-FR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getActionBadgeClass = (action) => {
    switch(action) {
      case 'ACCEPTED': return 'badge-accepted';
      case 'REJECTED': return 'badge-rejected';
      case 'DEFERRED': return 'badge-deferred';
      default: return 'badge-default';
    }
  };

  const getActionEmoji = (action) => {
    switch(action) {
      case 'ACCEPTED': return '✅';
      case 'REJECTED': return '❌';
      case 'DEFERRED': return '⏸️';
      default: return '📋';
    }
  };

  return (
    <div className="dashboard-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <div className="logo-icon">⚠️</div>
            <span>CTBA</span>
          </div>
        </div>

        <div className="nav-menu">
          <a href="/" className="nav-item">
            📊 Dashboard
          </a>
          <a href="/accepted" className="nav-item">
            ✅ CVEs Acceptés
          </a>
          <a href="/rejected" className="nav-item">
            ❌ CVEs Rejetés
          </a>
          <a href="/blacklist" className="nav-item">
            🚫 Produits Blacklistés
          </a>
          <a href="/history" className="nav-item active">
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
            <h1>📜 Action History</h1>
            <p>Historique des actions effectuées sur les CVEs</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* Filter */}
        <div className="filter-section">
          <label>Filtrer par action:</label>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="ALL">Toutes les actions</option>
            <option value="ACCEPTED">✅ Acceptées</option>
            <option value="REJECTED">❌ Rejetées</option>
            <option value="DEFERRED">⏸️ Déférées</option>
          </select>
        </div>

        {/* Actions Table */}
        <div className="actions-table-container">
          {loading ? (
            <div className="loading">⏳ Chargement...</div>
          ) : actions.length === 0 ? (
            <div className="no-data">Aucune action trouvée</div>
          ) : (
            <table className="actions-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Action</th>
                  <th>Analyste</th>
                  <th>Commentaires</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((action) => (
                  <tr key={action.id}>
                    <td className="cve-id-cell">
                      <strong>{action.cve_id}</strong>
                    </td>
                    <td>
                      <span className={`badge ${getActionBadgeClass(action.action)}`}>
                        {getActionEmoji(action.action)} {action.action}
                      </span>
                    </td>
                    <td className="analyst-cell">{action.analyst}</td>
                    <td className="comments-cell">{action.comments || '-'}</td>
                    <td className="date-cell">{formatDate(action.action_date)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

export default ActionHistory;
