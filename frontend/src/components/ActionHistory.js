import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './ActionHistory.css';

function ActionHistory({ user, onLogout }) {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');

  useEffect(() => {
    fetchActionHistory();
  }, [filter, user]);

  const fetchActionHistory = async () => {
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams();
      
      // Filter by current analyst username
      if (user && user.username) {
        params.append('analyst', user.username);
      }
      
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
    return new Date(dateString).toLocaleDateString('en-US', {
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
          <Link to="/" className="nav-item">
            📊 Dashboard
          </Link>
          <Link to="/accepted" className="nav-item">
            ✅ Accepted CVEs
          </Link>
          <Link to="/rejected" className="nav-item">
            ❌ Rejected CVEs
          </Link>
          <Link to="/blacklist" className="nav-item">
            🚫 Blacklisted Products
          </Link>
          <Link to="/history" className="nav-item active">
            📜 Action History
          </Link>
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
            <h1>📜 My Action History</h1>
            <p>History of actions performed by {user.username}</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* Filter */}
        <div className="filter-section">
          <label>Filter by action:</label>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="ALL">All actions</option>
            <option value="ACCEPTED">✅ Accepted</option>
            <option value="REJECTED">❌ Rejected</option>
            <option value="DEFERRED">⏸️ Deferred</option>
          </select>
        </div>

        {/* Actions Table */}
        <div className="actions-table-container">
          {loading ? (
            <div className="loading">⏳ Loading...</div>
          ) : actions.length === 0 ? (
            <div className="no-data">No actions found</div>
          ) : (
            <table className="actions-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Action</th>
                  <th>Analyst</th>
                  <th>Comments</th>
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
