// components/TechnologyManager.js
import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';
import './TechnologyManager.css';
import AddTechnologyModal from './AddTechnologyModal';

function TechnologyManager() {
  const [technologies, setTechnologies] = useState([]);
  const [filters, setFilters] = useState({ status: '', vendor: '', product: '' });
  const [newTech, setNewTech] = useState({ vendor: '', product: '', status: 'NORMAL', reason: '' });
  const [stats, setStats] = useState(null);
  const [addTechDialogOpen, setAddTechDialogOpen] = useState(false);

  useEffect(() => {
    loadTechnologies();
    loadStats();
  }, [filters]);

  const loadTechnologies = async () => {
    try {
      const params = new URLSearchParams();
      if (filters.status) params.append('status', filters.status);
      if (filters.vendor) params.append('vendor', filters.vendor);
      if (filters.product) params.append('product', filters.product);
      
      const response = await fetch(`http://localhost:8000/technologies?${params}`);
      const data = await response.json();
      setTechnologies(data);
    } catch (error) {
      console.error('Error loading technologies:', error);
    }
  };

  const loadStats = async () => {
    try {
      const response = await fetch('http://localhost:8000/technologies/stats');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  // Add handled by shared modal; onAdded will refresh lists

  const handleUpdateStatus = async (id, newStatus) => {
    if (!window.confirm(`Change status to ${newStatus}?`)) return;

    try {
      await apiService.updateTechnology(id, { status: newStatus });
      alert('✅ Status updated');
      loadTechnologies();
    } catch (error) {
      alert('❌ Error updating status');
    }
  };

  const handleDelete = async (id, vendor, product) => {
    if (!window.confirm(`Delete ${vendor}/${product}?`)) return;

    try {
      await apiService.deleteTechnology(id);
      alert('✅ Technology deleted');
      loadTechnologies();
      loadStats();
    } catch (error) {
      alert('❌ Error deleting technology');
    }
  };

  const getStatusBadge = (status) => {
    const badges = {
      'OUT_OF_SCOPE': { text: 'Out of Scope', class: 'badge-out-of-scope', emoji: '🚫' },
      'PRIORITY': { text: 'Priority', class: 'badge-priority', emoji: '⚡' },
      'NORMAL': { text: 'Normal', class: 'badge-normal', emoji: '✅' }
    };
    
    const badge = badges[status] || { text: status, class: 'badge-unknown', emoji: '❓' };
    
    return (
      <span className={`status-badge ${badge.class}`}>
        {badge.emoji} {badge.text}
      </span>
    );
  };

  return (
    <div className="tech-container">
      <h1>🔧 Technology Management</h1>
      
      {/* Stats Overview */}
      {stats && (
        <div className="stats-overview">
          <div className="stat-card">
            <h3>📊 Overview</h3>
            <p>Total Tracked: <strong>{stats.total_tracked}</strong></p>
            <div className="status-breakdown">
              {stats.by_status.map(item => (
                <div key={item.status} className="status-item">
                  {getStatusBadge(item.status)}
                  <span className="count">{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="filters-panel">
        <div className="filter-group">
          <label>Status:</label>
          <select value={filters.status} onChange={e => setFilters({...filters, status: e.target.value})}>
            <option value="">All</option>
            <option value="OUT_OF_SCOPE">Out of Scope</option>
            <option value="PRIORITY">Priority</option>
            <option value="NORMAL">Normal</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Vendor:</label>
          <input
            type="text"
            placeholder="Filter by vendor..."
            value={filters.vendor}
            onChange={e => setFilters({...filters, vendor: e.target.value})}
          />
        </div>

        <div className="filter-group">
          <label>Product:</label>
          <input
            type="text"
            placeholder="Filter by product..."
            value={filters.product}
            onChange={e => setFilters({...filters, product: e.target.value})}
          />
        </div>

        <button onClick={() => setAddTechDialogOpen(true)} className="btn-add">
          ➕ Add Technology
        </button>
      </div>

      <AddTechnologyModal
        open={addTechDialogOpen}
        onClose={() => setAddTechDialogOpen(false)}
        initialVendor={newTech.vendor}
        initialProduct={newTech.product}
        initialStatus={newTech.status}
        initialReason={newTech.reason}
        addedBy={localStorage.getItem('ctba_user') || 'admin'}
        onAdded={() => { loadTechnologies(); loadStats(); }}
      />

      {/* Technologies Table */}
      <div className="tech-table-container">
        <table className="tech-table">
          <thead>
            <tr>
              <th>Vendor / Product</th>
              <th>Status</th>
              <th>CVEs</th>
              <th>Severities</th>
              <th>Added By</th>
              <th>Reason</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {technologies.map(tech => (
              <tr key={tech.id}>
                <td>
                  <div className="tech-name">
                    <strong>{tech.vendor}</strong><br/>
                    <span className="product-name">{tech.product}</span>
                  </div>
                </td>
                <td>
                  {getStatusBadge(tech.status)}
                </td>
                <td>
                  <div className="cve-stats">
                    <span className="total-cves">📊 {tech.stats?.total_cves || 0}</span>
                    {tech.stats?.critical > 0 && (
                      <span className="critical-count">🔴 {tech.stats.critical}</span>
                    )}
                    {tech.stats?.high > 0 && (
                      <span className="high-count">🟠 {tech.stats.high}</span>
                    )}
                    {tech.stats?.medium > 0 && (
                      <span className="medium-count">🟡 {tech.stats.medium}</span>
                    )}
                  </div>
                </td>
                <td>
                  {tech.stats?.severities ? tech.stats.severities.split(',').slice(0, 3).join(', ') : 'None'}
                </td>
                <td>{tech.added_by}</td>
                <td className="reason-cell">{tech.reason || '-'}</td>
                <td>
                  <div className="action-buttons">
                    <select 
                      value={tech.status}
                      onChange={(e) => handleUpdateStatus(tech.id, e.target.value)}
                      className="status-select"
                    >
                      <option value="NORMAL">Normal</option>
                      <option value="PRIORITY">Priority</option>
                      <option value="OUT_OF_SCOPE">Out of Scope</option>
                    </select>
                    <button 
                      onClick={() => handleDelete(tech.id, tech.vendor, tech.product)}
                      className="btn-delete"
                    >
                      🗑️
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        
        {technologies.length === 0 && (
          <div className="no-data">
            📭 No technologies found. Add your first technology above!
          </div>
        )}
      </div>
    </div>
  );
}

export default TechnologyManager;