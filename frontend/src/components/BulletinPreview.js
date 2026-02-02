/**
 * BulletinPreview Component - Frontend React
 * Features:
 * - Preview bulletin before sending
 * - Show formatted HTML email template
 * - Display recipient counts per region
 * - Show mailing lists (To/Cc/Bcc)
 * - Validate bulletin before sending
 */

import React, { useState, useEffect } from 'react';
import './BulletinPreview.css';

function BulletinPreview({ bulletinId, onClose, onSend }) {
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [testMode, setTestMode] = useState(true);

  useEffect(() => {
    if (bulletinId) {
      fetchPreview();
    }
  }, [bulletinId]);

  const fetchPreview = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(
        `http://localhost:8000/api/bulletins/${bulletinId}/preview`
      );
      const data = await response.json();

      if (data.success || data.preview) {
        setPreview(data.preview || data);
      } else {
        setError('Failed to load bulletin preview');
      }
    } catch (err) {
      console.error('Error fetching preview:', err);
      setError('Error loading preview: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSend = () => {
    if (window.confirm('Are you sure you want to send this bulletin?')) {
      if (onSend) {
        onSend(testMode);
      }
    }
  };

  if (loading) {
    return (
      <div className="preview-modal-overlay">
        <div className="preview-modal">
          <div className="loading">Chargement de l'aperçu...</div>
        </div>
      </div>
    );
  }

  if (!preview) {
    return (
      <div className="preview-modal-overlay">
        <div className="preview-modal">
          <div className="error-message">{error || 'No preview available'}</div>
          <button onClick={onClose} className="close-button">Fermer</button>
        </div>
      </div>
    );
  }

  return (
    <div className="preview-modal-overlay" onClick={onClose}>
      <div className="preview-modal" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="preview-header">
          <h2>Bulletin Preview - {preview.title}</h2>
          <button onClick={onClose} className="close-icon">✕</button>
        </div>

        {/* Content */}
        <div className="preview-content">
          {error && <div className="error-message">{error}</div>}

          {/* Bulletin Info */}
          <div className="info-section">
            <h3>Bulletin Information</h3>
            <div className="info-grid">
              <div className="info-item">
                <label>Bulletin ID:</label>
                <span>{preview.id}</span>
              </div>
              <div className="info-item">
                <label>Status:</label>
                <span className="status-badge">{preview.status}</span>
              </div>
              <div className="info-item">
                <label>Created:</label>
                <span>{new Date(preview.created_at).toLocaleString()}</span>
              </div>
              <div className="info-item">
                <label>CVE Count:</label>
                <span>{preview.cve_count || 0}</span>
              </div>
            </div>
          </div>

          {/* Recipients Summary */}
          <div className="recipients-section">
            <h3>Recipients Summary</h3>
            <div className="recipient-stats">
              {preview.recipient_counts && (
                <>
                  <div className="stat">
                    <span className="label">Total Recipients:</span>
                    <span className="value">{preview.recipient_counts.total || 0}</span>
                  </div>
                  <div className="stat">
                    <span className="label">To:</span>
                    <span className="value">{preview.recipient_counts.to || 0}</span>
                  </div>
                  <div className="stat">
                    <span className="label">Cc:</span>
                    <span className="value">{preview.recipient_counts.cc || 0}</span>
                  </div>
                  <div className="stat">
                    <span className="label">Bcc:</span>
                    <span className="value">{preview.recipient_counts.bcc || 0}</span>
                  </div>
                </>
              )}
            </div>

            {/* Mailing Lists per Region */}
            {preview.mailing_lists && (
              <div className="mailing-lists">
                <h4>Mailing Lists by Region:</h4>
                {Object.entries(preview.mailing_lists).map(([region, list]) => (
                  <div key={region} className="region-mailing">
                    <h5>{region}</h5>
                    {list.to_recipients && list.to_recipients.length > 0 && (
                      <div className="mailing-type">
                        <strong>To:</strong>
                        <div className="email-list">
                          {list.to_recipients.map((email, idx) => (
                            <span key={idx} className="email-tag to">{email}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {list.cc_recipients && list.cc_recipients.length > 0 && (
                      <div className="mailing-type">
                        <strong>Cc:</strong>
                        <div className="email-list">
                          {list.cc_recipients.map((email, idx) => (
                            <span key={idx} className="email-tag cc">{email}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {list.bcc_recipients && list.bcc_recipients.length > 0 && (
                      <div className="mailing-type">
                        <strong>Bcc:</strong>
                        <div className="email-list">
                          {list.bcc_recipients.map((email, idx) => (
                            <span key={idx} className="email-tag bcc">{email}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Email Preview */}
          <div className="email-preview-section">
            <h3>Email Preview</h3>
            <div className="email-preview-frame">
              <div className="email-header">
                <div className="email-row">
                  <strong>Subject:</strong> {preview.title}
                </div>
                <div className="email-row">
                  <strong>From:</strong> security@example.com
                </div>
                <div className="email-row">
                  <strong>To:</strong> [Recipients]
                </div>
                <hr />
              </div>

              <div className="email-body">
                {/* Render HTML preview if available */}
                {preview.html_preview ? (
                  <iframe
                    srcDoc={preview.html_preview}
                    className="email-iframe"
                    title="Email Preview"
                  />
                ) : preview.body ? (
                  <pre className="text-preview">{preview.body}</pre>
                ) : (
                  <div className="no-preview">No preview available</div>
                )}
              </div>
            </div>
          </div>

          {/* CVE Summary */}
          {preview.cves && preview.cves.length > 0 && (
            <div className="cve-section">
              <h3>CVEs Included ({preview.cves.length})</h3>
              <div className="cve-list">
                {preview.cves.slice(0, 5).map((cve, idx) => (
                  <div key={idx} className="cve-item">
                    <span className="cve-id">{cve.id}</span>
                    {cve.severity && (
                      <span className={`severity ${cve.severity.toLowerCase()}`}>
                        {cve.severity}
                      </span>
                    )}
                  </div>
                ))}
                {preview.cves.length > 5 && (
                  <div className="cve-item more">
                    ... and {preview.cves.length - 5} more CVEs
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Validation */}
          {preview.is_valid === false && (
            <div className="validation-error">
              ⚠️ This bulletin has validation issues. Please review before sending.
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="preview-footer">
          <div className="test-mode">
            <label>
              <input
                type="checkbox"
                checked={testMode}
                onChange={(e) => setTestMode(e.target.checked)}
              />
              Test Mode (do not send actual emails)
            </label>
          </div>

          <div className="actions">
            <button onClick={onClose} className="button cancel">
              Close
            </button>
            <button onClick={handleSend} className="button send">
              {testMode ? '📧 Send (Test Mode)' : '📧 Send Bulletin'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default BulletinPreview;
