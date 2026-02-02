/**
 * DeliveryQueueMonitor Component - Frontend React
 * Features:
 * - Monitor bulletin delivery queue status
 * - View pending, processing, and completed jobs
 * - Retry failed jobs
 * - Real-time status updates
 * - Queue statistics
 */

import React, { useState, useEffect } from 'react';
import './DeliveryQueueMonitor.css';

function DeliveryQueueMonitor({ user }) {
  const [queueStatus, setQueueStatus] = useState(null);
  const [queueJobs, setQueueJobs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [filter, setFilter] = useState('all'); // all, pending, processing, completed, failed

  // Auto-refresh
  useEffect(() => {
    fetchQueueStatus();
    const interval = setInterval(fetchQueueStatus, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchQueueStatus = async () => {
    try {
      setLoading(true);
      
      const response = await fetch('http://localhost:8000/api/delivery-queue/status');
      const data = await response.json();
      
      if (data.success || data.status) {
        const status = data.success ? data.status : data;
        setQueueStatus(status);
        
        // Extract jobs from status
        if (status.jobs) {
          setQueueJobs(status.jobs);
        }
      } else {
        setError('Failed to load queue status');
      }
    } catch (err) {
      console.error('Error fetching queue status:', err);
      setError('Error loading queue status: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const getFilteredJobs = () => {
    if (!queueJobs) return [];
    
    if (filter === 'all') return queueJobs;
    return queueJobs.filter(job => job.status === filter);
  };

  const retryJob = async (jobId) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`http://localhost:8000/api/delivery-queue/retry/${jobId}`, {
        method: 'POST'
      });

      const data = await response.json();

      if (data.success || response.ok) {
        setSuccess('Job retry queued successfully');
        setTimeout(() => setSuccess(null), 3000);
        fetchQueueStatus();
      } else {
        setError(data.message || 'Failed to retry job');
      }
    } catch (err) {
      console.error('Error retrying job:', err);
      setError('Error retrying job: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const cancelJob = async (jobId) => {
    if (!window.confirm('Are you sure you want to cancel this job?')) return;

    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`http://localhost:8000/api/delivery-queue/cancel/${jobId}`, {
        method: 'POST'
      });

      const data = await response.json();

      if (data.success || response.ok) {
        setSuccess('Job cancelled successfully');
        setTimeout(() => setSuccess(null), 3000);
        fetchQueueStatus();
      } else {
        setError(data.message || 'Failed to cancel job');
      }
    } catch (err) {
      console.error('Error cancelling job:', err);
      setError('Error cancelling job: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const clearCompleted = async () => {
    if (!window.confirm('Are you sure you want to clear all completed jobs?')) return;

    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('http://localhost:8000/api/delivery-queue/clear-completed', {
        method: 'POST'
      });

      const data = await response.json();

      if (data.success || response.ok) {
        setSuccess('Completed jobs cleared');
        setTimeout(() => setSuccess(null), 3000);
        fetchQueueStatus();
      } else {
        setError(data.message || 'Failed to clear completed jobs');
      }
    } catch (err) {
      console.error('Error clearing completed:', err);
      setError('Error clearing completed jobs: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      'pending': '#FF9800',
      'processing': '#2196F3',
      'completed': '#4CAF50',
      'failed': '#f44336',
      'retried': '#9C27B0'
    };
    return colors[status] || '#757575';
  };

  const getStatusBadge = (status) => {
    const colors = {
      'pending': { bg: '#FFF3E0', text: '#E65100' },
      'processing': { bg: '#E3F2FD', text: '#1565C0' },
      'completed': { bg: '#E8F5E9', text: '#2E7D32' },
      'failed': { bg: '#FFEBEE', text: '#C62828' },
      'retried': { bg: '#F3E5F5', text: '#6A1B9A' }
    };
    const style = colors[status] || colors['pending'];
    return (
      <span style={{
        padding: '6px 12px',
        backgroundColor: style.bg,
        color: style.text,
        borderRadius: '4px',
        fontSize: '12px',
        fontWeight: 'bold'
      }}>
        {status.toUpperCase()}
      </span>
    );
  };

  const filteredJobs = getFilteredJobs();

  return (
    <div className="queue-monitor-container">
      <h1>📦 Delivery Queue Monitor</h1>

      {error && <div className="error-message">{error}</div>}
      {success && <div className="success-message">{success}</div>}

      {/* Queue Statistics */}
      {queueStatus && (
        <div className="queue-stats">
          <div className="stat-card">
            <div className="stat-icon">📊</div>
            <div className="stat-info">
              <div className="stat-label">Total Jobs</div>
              <div className="stat-value">{queueStatus.total_jobs || 0}</div>
            </div>
          </div>

          <div className="stat-card pending">
            <div className="stat-icon">⏳</div>
            <div className="stat-info">
              <div className="stat-label">Pending</div>
              <div className="stat-value">{queueStatus.pending_jobs || 0}</div>
            </div>
          </div>

          <div className="stat-card processing">
            <div className="stat-icon">⚙️</div>
            <div className="stat-info">
              <div className="stat-label">Processing</div>
              <div className="stat-value">{queueStatus.processing_jobs || 0}</div>
            </div>
          </div>

          <div className="stat-card completed">
            <div className="stat-icon">✅</div>
            <div className="stat-info">
              <div className="stat-label">Completed</div>
              <div className="stat-value">{queueStatus.completed_jobs || 0}</div>
            </div>
          </div>

          <div className="stat-card failed">
            <div className="stat-icon">❌</div>
            <div className="stat-info">
              <div className="stat-label">Failed</div>
              <div className="stat-value">{queueStatus.failed_jobs || 0}</div>
            </div>
          </div>
        </div>
      )}

      {/* Filter and Actions */}
      <div className="controls-section">
        <div className="filter-buttons">
          <button
            className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
            onClick={() => setFilter('all')}
          >
            All ({queueJobs.length})
          </button>
          <button
            className={`filter-btn ${filter === 'pending' ? 'active' : ''}`}
            onClick={() => setFilter('pending')}
          >
            Pending ({queueJobs.filter(j => j.status === 'pending').length})
          </button>
          <button
            className={`filter-btn ${filter === 'processing' ? 'active' : ''}`}
            onClick={() => setFilter('processing')}
          >
            Processing ({queueJobs.filter(j => j.status === 'processing').length})
          </button>
          <button
            className={`filter-btn ${filter === 'completed' ? 'active' : ''}`}
            onClick={() => setFilter('completed')}
          >
            Completed ({queueJobs.filter(j => j.status === 'completed').length})
          </button>
          <button
            className={`filter-btn ${filter === 'failed' ? 'active' : ''}`}
            onClick={() => setFilter('failed')}
          >
            Failed ({queueJobs.filter(j => j.status === 'failed').length})
          </button>
        </div>

        <div className="action-buttons">
          <button
            onClick={fetchQueueStatus}
            className="action-btn refresh"
            disabled={loading}
          >
            🔄 Refresh
          </button>
          <button
            onClick={clearCompleted}
            className="action-btn clear"
            disabled={loading}
          >
            🧹 Clear Completed
          </button>
        </div>
      </div>

      {/* Jobs Table */}
      <div className="jobs-table-wrapper">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>Job ID</th>
              <th>Bulletin ID</th>
              <th>Status</th>
              <th>Created</th>
              <th>Started</th>
              <th>Completed</th>
              <th>Attempts</th>
              <th>Region</th>
              <th>Recipients</th>
              <th>Error</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredJobs.length === 0 ? (
              <tr>
                <td colSpan="11" className="no-data">No jobs in queue</td>
              </tr>
            ) : (
              filteredJobs.map((job, idx) => (
                <tr key={idx} className={`job-row ${job.status}`}>
                  <td className="job-id">{job.job_id || job.id || '-'}</td>
                  <td className="bulletin-id">{job.bulletin_id || '-'}</td>
                  <td>{getStatusBadge(job.status)}</td>
                  <td className="timestamp">{job.created_at ? new Date(job.created_at).toLocaleString() : '-'}</td>
                  <td className="timestamp">{job.started_at ? new Date(job.started_at).toLocaleString() : '-'}</td>
                  <td className="timestamp">{job.completed_at ? new Date(job.completed_at).toLocaleString() : '-'}</td>
                  <td className="attempts">{job.attempt_count || 1}</td>
                  <td className="region">{job.region_id || '-'}</td>
                  <td className="recipients" title={job.recipients || '-'}>{job.recipients ? job.recipients.substring(0, 30) + '...' : '-'}</td>
                  <td className="error" title={job.error_message || '-'}>{job.error_message ? job.error_message.substring(0, 30) + '...' : '-'}</td>
                  <td className="actions">
                    {job.status === 'failed' && (
                      <button
                        onClick={() => retryJob(job.job_id || job.id)}
                        className="action-icon retry"
                        title="Retry this job"
                        disabled={loading}
                      >
                        🔁
                      </button>
                    )}
                    {job.status === 'pending' || job.status === 'processing' ? (
                      <button
                        onClick={() => cancelJob(job.job_id || job.id)}
                        className="action-icon cancel"
                        title="Cancel this job"
                        disabled={loading}
                      >
                        ⏹️
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="queue-info">
        <p>Last Updated: {queueStatus?.last_update ? new Date(queueStatus.last_update).toLocaleString() : 'Never'}</p>
        <p>Auto-refreshing every 5 seconds...</p>
      </div>
    </div>
  );
}

export default DeliveryQueueMonitor;
