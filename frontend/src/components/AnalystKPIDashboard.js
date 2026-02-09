import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './AnalystKPIDashboard.css';

function AnalystKPIDashboard({ user, onLogout }) {
  const [performance, setPerformance] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [trends, setTrends] = useState([]);
  const [period, setPeriod] = useState('month');
  const [trendDays, setTrendDays] = useState(30);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchKPIData();
  }, [period, trendDays]);

  const fetchKPIData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('token');

      // Fetch analyst performance
      const perfResponse = await fetch(`http://localhost:8000/api/kpi/analyst-performance?period=${period}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      // Fetch overall statistics
      const statsResponse = await fetch(`http://localhost:8000/api/kpi/action-statistics?period=${period}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      // Fetch trends
      const trendsResponse = await fetch(`http://localhost:8000/api/kpi/action-trends?days=${trendDays}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (perfResponse.status === 401) {
        console.error('Unauthorized: Invalid or expired token');
        return;
      }

      if (perfResponse.ok) {
        const perfData = await perfResponse.json();
        setPerformance(perfData.analysts || []);
      }

      if (statsResponse.ok) {
        const statsData = await statsResponse.json();
        console.log('📊 Statistics data received:', statsData);
        setStatistics(statsData);
      }

      if (trendsResponse.ok) {
        const trendsData = await trendsResponse.json();
        setTrends(trendsData.trends || []);
      }

      setLoading(false);
    } catch (error) {
      console.error('Error fetching KPI data:', error);
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: '#dc3545',
      HIGH: '#fd7e14',
      MEDIUM: '#ffc107',
      LOW: '#28a745'
    };
    return colors[severity] || '#6c757d';
  };

  return (
    <div className="dashboard-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <div className="logo-icon">📊</div>
            <div>CTBA</div>
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
          <Link to="/ingestion" className="nav-item">
            📡 Source Ingestion
          </Link>
          <Link to="/blacklist" className="nav-item">
            🚫 Blacklisted Products
          </Link>
          <Link to="/history" className="nav-item">
            📜 Action History
          </Link>
          <Link to="/kpi" className="nav-item active">
            📈 Reports & KPIs
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
            <h1>📈 Analyst Reports & KPIs</h1>
            <p>Performance tracking and analysis metrics</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* Controls */}
        <div className="kpi-controls">
          <div className="control-group">
            <label>Analysis Period:</label>
            <select value={period} onChange={(e) => setPeriod(e.target.value)} className="control-select">
              <option value="day">Today</option>
              <option value="week">This Week</option>
              <option value="month">This Month</option>
              <option value="year">This Year</option>
              <option value="all">All Time</option>
            </select>
          </div>
          <div className="control-group">
            <label>Days for trends:</label>
            <select value={trendDays} onChange={(e) => setTrendDays(parseInt(e.target.value))} className="control-select">
              <option value="7">7 days</option>
              <option value="14">14 days</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div style={{ padding: '40px', textAlign: 'center' }}>⏳ Loading...</div>
        ) : (
          <>
            {/* Overall Statistics */}
            {statistics && (
              <div className="kpi-section">
                <h2>📊 Overall Statistics</h2>
                <div className="stats-grid">
                  <div className="stat-card">
                    <div className="stat-label">Total Reviewed</div>
                    <div className="stat-value">{statistics.total_reviewed || 0}</div>
                    <div className="stat-subtext">CVEs</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-label">Accepted</div>
                    <div className="stat-value" style={{ color: '#28a745' }}>
                      {statistics.total_accepted || 0}
                    </div>
                    <div className="stat-subtext">{statistics.acceptance_rate || 0}%</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-label">Rejected</div>
                    <div className="stat-value" style={{ color: '#dc3545' }}>
                      {statistics.total_rejected || 0}
                    </div>
                    <div className="stat-subtext">
                      {(statistics.total_reviewed || 0) > 0 
                        ? Math.round(((statistics.total_rejected || 0) / statistics.total_reviewed) * 100) 
                        : 0}%
                    </div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-label">Deferred</div>
                    <div className="stat-value" style={{ color: '#ffc107' }}>
                      {statistics.total_deferred || 0}
                    </div>
                    <div className="stat-subtext">
                      {(statistics.total_reviewed || 0) > 0 
                        ? Math.round(((statistics.total_deferred || 0) / statistics.total_reviewed) * 100) 
                        : 0}%
                    </div>
                  </div>
                </div>

                {/* Severity Distribution */}
                <div className="severity-section">
                  <h3>Distribution by Severity</h3>
                  <div className="severity-bars">
                    {Object.entries(statistics.severity_distribution || {}).map(([severity, count]) => (
                      <div key={severity} className="severity-bar-item">
                        <div className="severity-bar-label">{severity}</div>
                        <div className="severity-bar-chart">
                          <div
                            className="severity-bar-fill"
                            style={{
                              width: `${(count / Math.max(...Object.values(statistics.severity_distribution || {}))) * 100}%`,
                              backgroundColor: getSeverityColor(severity)
                            }}
                          >
                            {count}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Analyst Performance */}
            <div className="kpi-section">
              <h2>👥 Analyst Performance</h2>
              {performance.length === 0 ? (
                <div style={{ padding: '20px', textAlign: 'center', color: '#666' }}>
                  No data available for this period
                </div>
              ) : (
                <table className="kpi-table">
                  <thead>
                    <tr>
                      <th>Analyst</th>
                      <th>Total Actions</th>
                      <th>Accepted</th>
                      <th>Rejected</th>
                      <th>Deferred</th>
                      <th>Acceptance Rate</th>
                      <th>Avg. Actions/Day</th>
                      <th>Last Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {performance.map((analyst) => (
                      <tr key={analyst.analyst}>
                        <td className="analyst-name">👤 {analyst.analyst}</td>
                        <td className="metric-value">{analyst.total_actions}</td>
                        <td style={{ color: '#28a745' }}>{analyst.accepted}</td>
                        <td style={{ color: '#dc3545' }}>{analyst.rejected}</td>
                        <td style={{ color: '#ffc107' }}>{analyst.deferred}</td>
                        <td>
                          <div className="progress-bar">
                            <div
                              className="progress-fill"
                              style={{
                                width: `${analyst.acceptance_rate}%`,
                                backgroundColor: analyst.acceptance_rate > 70 ? '#28a745' : analyst.acceptance_rate > 40 ? '#ffc107' : '#dc3545'
                              }}
                            >
                              {analyst.acceptance_rate}%
                            </div>
                          </div>
                        </td>
                        <td className="metric-value">{analyst.avg_actions_per_day}</td>
                        <td className="date-cell">
                          {analyst.last_action_date 
                            ? new Date(analyst.last_action_date).toLocaleDateString('en-US')
                            : '-'
                          }
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Trends */}
            <div className="kpi-section">
              <h2>📈 Trends ({trendDays} days)</h2>
              {trends.length === 0 ? (
                <div style={{ padding: '20px', textAlign: 'center', color: '#666' }}>
                  No trend data available
                </div>
              ) : (
                <table className="kpi-table">
                  <thead>
                    <tr>
                      <th>Date</th>
                      <th>Accepted</th>
                      <th>Rejected</th>
                      <th>Deferred</th>
                      <th>Daily Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trends.map((trend) => (
                      <tr key={trend.date}>
                        <td className="date-cell">{new Date(trend.date).toLocaleDateString('en-US')}</td>
                        <td style={{ color: '#28a745' }}>{trend.accepted || 0}</td>
                        <td style={{ color: '#dc3545' }}>{trend.rejected || 0}</td>
                        <td style={{ color: '#ffc107' }}>{trend.deferred || 0}</td>
                        <td className="metric-value" style={{ fontWeight: 'bold' }}>{trend.total}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default AnalystKPIDashboard;
