/**
 * DeliveryAuditTrail Component - Frontend React
 * Features:
 * - View complete audit trail of bulletin deliveries
 * - Filter by bulletin, action type, region, date range
 * - Search by email, bulletin ID
 * - Export audit logs
 * - Real-time updates
 */

import React, { useState, useEffect } from 'react';
import './DeliveryAuditTrail.css';

function DeliveryAuditTrail({ user }) {
  const [auditLogs, setAuditLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Filter states
  const [searchQuery, setSearchQuery] = useState('');
  const [actionTypeFilter, setActionTypeFilter] = useState('');
  const [regionFilter, setRegionFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [sortBy, setSortBy] = useState('timestamp_desc');

  const actionTypes = [
    'BULLETIN_QUEUED',
    'EMAIL_SENT',
    'EMAIL_FAILED',
    'DELIVERY_STARTED',
    'DELIVERY_COMPLETED',
    'DELIVERY_RETRIED',
    'MAILING_LIST_UPDATED'
  ];

  const statuses = ['SUCCESS', 'FAILED', 'PENDING', 'RETRIED'];

  // Load audit logs on mount
  useEffect(() => {
    fetchAuditLogs();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchAuditLogs, 30000);
    return () => clearInterval(interval);
  }, []);

  // Apply filters when they change
  useEffect(() => {
    applyFilters();
  }, [auditLogs, searchQuery, actionTypeFilter, regionFilter, statusFilter, dateFrom, dateTo, sortBy]);

  const fetchAuditLogs = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('http://localhost:8000/api/audit-logs');
      const data = await response.json();
      
      if (data.success || Array.isArray(data)) {
        const logs = Array.isArray(data) ? data : data.audit_logs || [];
        setAuditLogs(logs);
      } else {
        setError('Failed to load audit logs');
      }
    } catch (err) {
      console.error('Error fetching audit logs:', err);
      setError('Error loading audit logs: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...auditLogs];

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(log =>
        log.bulletin_id?.toString().includes(query) ||
        log.recipients?.toLowerCase().includes(query) ||
        log.actor?.toLowerCase().includes(query) ||
        log.details?.toLowerCase().includes(query)
      );
    }

    // Action type filter
    if (actionTypeFilter) {
      filtered = filtered.filter(log => log.action_type === actionTypeFilter);
    }

    // Region filter
    if (regionFilter) {
      filtered = filtered.filter(log => log.region_id?.toString() === regionFilter);
    }

    // Status filter
    if (statusFilter) {
      filtered = filtered.filter(log => log.status === statusFilter);
    }

    // Date range filter
    if (dateFrom) {
      const fromDate = new Date(dateFrom).getTime();
      filtered = filtered.filter(log => new Date(log.timestamp).getTime() >= fromDate);
    }

    if (dateTo) {
      const toDate = new Date(dateTo).getTime();
      filtered = filtered.filter(log => new Date(log.timestamp).getTime() <= toDate);
    }

    // Sort
    filtered.sort((a, b) => {
      const aTime = new Date(a.timestamp).getTime();
      const bTime = new Date(b.timestamp).getTime();
      return sortBy === 'timestamp_desc' ? bTime - aTime : aTime - bTime;
    });

    setFilteredLogs(filtered);
  };

  const exportLogs = () => {
    try {
      const csv = convertToCSV(filteredLogs);
      downloadCSV(csv, `audit-logs-${new Date().toISOString().split('T')[0]}.csv`);
    } catch (err) {
      console.error('Error exporting logs:', err);
      setError('Failed to export logs');
    }
  };

  const convertToCSV = (logs) => {
    const headers = ['Timestamp', 'Bulletin ID', 'Action', 'Region', 'Status', 'Recipients', 'Actor', 'Details'];
    const rows = logs.map(log => [
      new Date(log.timestamp).toLocaleString(),
      log.bulletin_id || '-',
      log.action_type || '-',
      log.region_id || '-',
      log.status || '-',
      log.recipients || '-',
      log.actor || '-',
      log.details || '-'
    ]);

    let csv = headers.join(',') + '\n';
    rows.forEach(row => {
      csv += row.map(cell => `"${(cell || '').toString().replace(/"/g, '""')}"`).join(',') + '\n';
    });
    return csv;
  };

  const downloadCSV = (csv, filename) => {
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getActionColor = (action) => {
    const colors = {
      'BULLETIN_QUEUED': '#2196F3',
      'EMAIL_SENT': '#4CAF50',
      'EMAIL_FAILED': '#f44336',
      'DELIVERY_STARTED': '#FF9800',
      'DELIVERY_COMPLETED': '#4CAF50',
      'DELIVERY_RETRIED': '#FF9800',
      'MAILING_LIST_UPDATED': '#9C27B0'
    };
    return colors[action] || '#757575';
  };

  const getStatusBadge = (status) => {
    const styles = {
      'SUCCESS': { bg: '#4CAF50', text: 'white' },
      'FAILED': { bg: '#f44336', text: 'white' },
      'PENDING': { bg: '#FF9800', text: 'white' },
      'RETRIED': { bg: '#2196F3', text: 'white' }
    };
    const style = styles[status] || styles['PENDING'];
    return (
      <span style={{
        padding: '4px 8px',
        backgroundColor: style.bg,
        color: style.text,
        borderRadius: '4px',
        fontSize: '12px',
        fontWeight: 'bold'
      }}>
        {status}
      </span>
    );
  };

  if (loading && auditLogs.length === 0) {
    return (
      <div className="audit-trail-container">
        <h1>📋 Delivery Audit Trail</h1>
        <div className="loading">Chargement des journaux d'audit...</div>
      </div>
    );
  }

  return (
    <div className="audit-trail-container">
      <h1>📋 Delivery Audit Trail</h1>
      
      {error && <div className="error-message">{error}</div>}

      {/* Filters Section */}
      <div className="filters-section">
        <div className="filter-group">
          <input
            type="text"
            placeholder="Rechercher par bulletin ID, email, acteur..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
          
          <select
            value={actionTypeFilter}
            onChange={(e) => setActionTypeFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">Tous les types d'actions</option>
            {actionTypes.map(type => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">Tous les statuts</option>
            {statuses.map(status => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="filter-select"
          >
            <option value="timestamp_desc">Plus récents en premier</option>
            <option value="timestamp_asc">Plus anciens en premier</option>
          </select>
        </div>

        <div className="filter-group">
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className="filter-input"
            placeholder="Date de début"
          />
          
          <input
            type="date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className="filter-input"
            placeholder="Date de fin"
          />

          <button onClick={exportLogs} className="export-button">
            📥 Exporter en CSV
          </button>

          <button onClick={fetchAuditLogs} className="refresh-button">
            🔄 Actualiser
          </button>
        </div>
      </div>

      {/* Statistics */}
      <div className="audit-stats">
        <div className="stat-item">
          <div className="stat-label">Total d'entrées</div>
          <div className="stat-value">{filteredLogs.length}</div>
        </div>
        <div className="stat-item">
          <div className="stat-label">Réussis</div>
          <div className="stat-value success">{filteredLogs.filter(l => l.status === 'SUCCESS').length}</div>
        </div>
        <div className="stat-item">
          <div className="stat-label">Échoués</div>
          <div className="stat-value failed">{filteredLogs.filter(l => l.status === 'FAILED').length}</div>
        </div>
        <div className="stat-item">
          <div className="stat-label">En attente</div>
          <div className="stat-value pending">{filteredLogs.filter(l => l.status === 'PENDING').length}</div>
        </div>
      </div>

      {/* Audit Logs Table */}
      <div className="audit-table-wrapper">
        <table className="audit-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Bulletin ID</th>
              <th>Action</th>
              <th>Région</th>
              <th>Statut</th>
              <th>Destinataires</th>
              <th>Acteur</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="8" className="no-data">Aucun journal d'audit disponible</td>
              </tr>
            ) : (
              filteredLogs.map((log, idx) => (
                <tr key={idx} className="audit-row">
                  <td className="timestamp">{new Date(log.timestamp).toLocaleString()}</td>
                  <td className="bulletin-id">{log.bulletin_id || '-'}</td>
                  <td>
                    <span style={{
                      padding: '4px 8px',
                      backgroundColor: getActionColor(log.action_type),
                      color: 'white',
                      borderRadius: '4px',
                      fontSize: '12px'
                    }}>
                      {log.action_type || '-'}
                    </span>
                  </td>
                  <td className="region">{log.region_id || '-'}</td>
                  <td>{getStatusBadge(log.status)}</td>
                  <td className="recipients">
                    <span title={log.recipients || '-'}>{log.recipients || '-'}</span>
                  </td>
                  <td className="actor">{log.actor || '-'}</td>
                  <td className="details" title={log.details || '-'}>
                    {log.details ? log.details.substring(0, 50) + '...' : '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="pagination-info">
        Affichage de {filteredLogs.length} journal(s) sur {auditLogs.length} total(s)
      </div>
    </div>
  );
}

export default DeliveryAuditTrail;
