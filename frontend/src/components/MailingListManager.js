/**
 * MailingListManager Component - Frontend React
 * Features:
 * - Manage To/Cc/Bcc recipient lists per region
 * - Add/remove recipients
 * - Email validation
 * - Override default lists
 * - Audit trail for changes
 */

import React, { useState, useEffect } from 'react';
import './MailingListManager.css';

function MailingListManager({ user }) {
  const [regions, setRegions] = useState([]);
  const [selectedRegion, setSelectedRegion] = useState(null);
  const [mailingList, setMailingList] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Form states
  const [toRecipients, setToRecipients] = useState('');
  const [ccRecipients, setCcRecipients] = useState('');
  const [bccRecipients, setBccRecipients] = useState('');
  const [newRecipient, setNewRecipient] = useState('');
  const [recipientType, setRecipientType] = useState('to'); // to, cc, or bcc

  // Load regions on mount
  useEffect(() => {
    fetchRegions();
  }, []);

  // Load mailing list when region is selected
  useEffect(() => {
    if (selectedRegion) {
      fetchMailingList(selectedRegion);
    }
  }, [selectedRegion]);

  const fetchRegions = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8000/api/regions');
      const data = await response.json();
      
      if (response.ok) {
        setRegions(Array.isArray(data) ? data : data.regions || []);
      } else {
        setError('Failed to load regions');
      }
    } catch (err) {
      console.error('Error fetching regions:', err);
      setError('Error loading regions: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchMailingList = async (regionId) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`http://localhost:8000/api/regions/${regionId}/mailing-list`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const data = await response.json();
      
      // Handle direct response or wrapped response
      const list = data.mailing_list || data;
      
      // Check if we have the required fields
      if (list && (list.region_id || list.to_recipients !== undefined)) {
        setMailingList(list);
        setToRecipients(Array.isArray(list.to_recipients) ? list.to_recipients.join(', ') : (list.to_recipients || ''));
        setCcRecipients(Array.isArray(list.cc_recipients) ? list.cc_recipients.join(', ') : (list.cc_recipients || ''));
        setBccRecipients(Array.isArray(list.bcc_recipients) ? list.bcc_recipients.join(', ') : (list.bcc_recipients || ''));
      } else {
        setError('Failed to load mailing list');
      }
    } catch (err) {
      console.error('Error fetching mailing list:', err);
      setError('Error loading mailing list: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email.trim());
  };

  const addRecipient = () => {
    if (!newRecipient.trim()) {
      setError('Please enter an email address');
      return;
    }

    if (!validateEmail(newRecipient)) {
      setError('Invalid email format');
      return;
    }

    let currentList = [];
    if (recipientType === 'to') {
      currentList = toRecipients ? toRecipients.split(',').map(e => e.trim()) : [];
    } else if (recipientType === 'cc') {
      currentList = ccRecipients ? ccRecipients.split(',').map(e => e.trim()) : [];
    } else if (recipientType === 'bcc') {
      currentList = bccRecipients ? bccRecipients.split(',').map(e => e.trim()) : [];
    }

    if (currentList.includes(newRecipient.trim())) {
      setError('This email is already in the list');
      return;
    }

    currentList.push(newRecipient.trim());

    if (recipientType === 'to') {
      setToRecipients(currentList.join(', '));
    } else if (recipientType === 'cc') {
      setCcRecipients(currentList.join(', '));
    } else if (recipientType === 'bcc') {
      setBccRecipients(currentList.join(', '));
    }

    setNewRecipient('');
    setError(null);
    setSuccess('Recipient added successfully');
    setTimeout(() => setSuccess(null), 3000);
  };

  const removeRecipient = (email, type) => {
    let list = [];
    if (type === 'to') {
      list = toRecipients.split(',').map(e => e.trim()).filter(e => e !== email);
      setToRecipients(list.join(', '));
    } else if (type === 'cc') {
      list = ccRecipients.split(',').map(e => e.trim()).filter(e => e !== email);
      setCcRecipients(list.join(', '));
    } else if (type === 'bcc') {
      list = bccRecipients.split(',').map(e => e.trim()).filter(e => e !== email);
      setBccRecipients(list.join(', '));
    }
  };

  const saveMailing = async () => {
    if (!selectedRegion) {
      setError('Please select a region');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const toList = toRecipients ? toRecipients.split(',').map(e => e.trim()).filter(e => e) : [];
      const ccList = ccRecipients ? ccRecipients.split(',').map(e => e.trim()).filter(e => e) : [];
      const bccList = bccRecipients ? bccRecipients.split(',').map(e => e.trim()).filter(e => e) : [];

      // Validate all emails
      const allEmails = [...toList, ...ccList, ...bccList];
      for (let email of allEmails) {
        if (!validateEmail(email)) {
          setError(`Invalid email format: ${email}`);
          setLoading(false);
          return;
        }
      }

      const response = await fetch(`http://localhost:8000/api/regions/${selectedRegion}/mailing-list`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          to_recipients: toList,
          cc_recipients: ccList,
          bcc_recipients: bccList,
          updated_by: user?.username || 'system'
        })
      });

      const data = await response.json();

      if (data.success || response.ok) {
        setSuccess('Mailing list updated successfully');
        setTimeout(() => setSuccess(null), 3000);
        fetchMailingList(selectedRegion);
      } else {
        setError(data.message || 'Failed to update mailing list');
      }
    } catch (err) {
      console.error('Error saving mailing list:', err);
      setError('Error saving mailing list: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const clearAll = () => {
    if (window.confirm('Are you sure you want to clear all recipients for this region?')) {
      setToRecipients('');
      setCcRecipients('');
      setBccRecipients('');
    }
  };

  return (
    <div className="mailing-list-container">
      <h1>📧 Mailing List Manager</h1>

      {error && <div className="error-message">{error}</div>}
      {success && <div className="success-message">{success}</div>}

      {/* Region Selection */}
      <div className="region-selection">
        <label>Select Region:</label>
        <select
          value={selectedRegion || ''}
          onChange={(e) => setSelectedRegion(e.target.value || null)}
          className="region-select"
          disabled={loading}
        >
          <option value="">-- Choose a region --</option>
          {regions.map(region => (
            <option key={region.id} value={region.id}>
              {region.name} ({region.id})
            </option>
          ))}
        </select>
      </div>

      {selectedRegion && mailingList && (
        <div className="mailing-content">
          {/* Add Recipient Form */}
          <div className="add-recipient-section">
            <h3>Add New Recipient</h3>
            <div className="add-form">
              <input
                type="email"
                value={newRecipient}
                onChange={(e) => setNewRecipient(e.target.value)}
                placeholder="recipient@example.com"
                className="email-input"
                onKeyPress={(e) => e.key === 'Enter' && addRecipient()}
              />

              <select
                value={recipientType}
                onChange={(e) => setRecipientType(e.target.value)}
                className="type-select"
              >
                <option value="to">To (Primary)</option>
                <option value="cc">Cc (Carbon Copy)</option>
                <option value="bcc">Bcc (Blind Copy)</option>
              </select>

              <button onClick={addRecipient} className="add-button">
                ➕ Add Recipient
              </button>
            </div>
          </div>

          {/* Recipient Lists */}
          <div className="recipients-grid">
            {/* To Recipients */}
            <div className="recipient-section">
              <h3 className="to-header">📨 To Recipients</h3>
              <div className="recipient-list">
                {toRecipients && toRecipients.split(',').map((email, idx) => {
                  const trimmed = email.trim();
                  return trimmed ? (
                    <div key={idx} className="recipient-chip to-chip">
                      <span>{trimmed}</span>
                      <button
                        onClick={() => removeRecipient(trimmed, 'to')}
                        className="remove-btn"
                        title="Remove"
                      >
                        ✕
                      </button>
                    </div>
                  ) : null;
                })}
                {(!toRecipients || toRecipients.split(',').every(e => !e.trim())) && (
                  <div className="empty-message">No To recipients</div>
                )}
              </div>
            </div>

            {/* Cc Recipients */}
            <div className="recipient-section">
              <h3 className="cc-header">📋 Cc Recipients</h3>
              <div className="recipient-list">
                {ccRecipients && ccRecipients.split(',').map((email, idx) => {
                  const trimmed = email.trim();
                  return trimmed ? (
                    <div key={idx} className="recipient-chip cc-chip">
                      <span>{trimmed}</span>
                      <button
                        onClick={() => removeRecipient(trimmed, 'cc')}
                        className="remove-btn"
                        title="Remove"
                      >
                        ✕
                      </button>
                    </div>
                  ) : null;
                })}
                {(!ccRecipients || ccRecipients.split(',').every(e => !e.trim())) && (
                  <div className="empty-message">No Cc recipients</div>
                )}
              </div>
            </div>

            {/* Bcc Recipients */}
            <div className="recipient-section">
              <h3 className="bcc-header">🔒 Bcc Recipients</h3>
              <div className="recipient-list">
                {bccRecipients && bccRecipients.split(',').map((email, idx) => {
                  const trimmed = email.trim();
                  return trimmed ? (
                    <div key={idx} className="recipient-chip bcc-chip">
                      <span>{trimmed}</span>
                      <button
                        onClick={() => removeRecipient(trimmed, 'bcc')}
                        className="remove-btn"
                        title="Remove"
                      >
                        ✕
                      </button>
                    </div>
                  ) : null;
                })}
                {(!bccRecipients || bccRecipients.split(',').every(e => !e.trim())) && (
                  <div className="empty-message">No Bcc recipients</div>
                )}
              </div>
            </div>
          </div>

          {/* Statistics */}
          <div className="mailing-stats">
            <div className="stat-item">
              <div className="stat-label">To Recipients</div>
              <div className="stat-value">{toRecipients ? toRecipients.split(',').filter(e => e.trim()).length : 0}</div>
            </div>
            <div className="stat-item">
              <div className="stat-label">Cc Recipients</div>
              <div className="stat-value">{ccRecipients ? ccRecipients.split(',').filter(e => e.trim()).length : 0}</div>
            </div>
            <div className="stat-item">
              <div className="stat-label">Bcc Recipients</div>
              <div className="stat-value">{bccRecipients ? bccRecipients.split(',').filter(e => e.trim()).length : 0}</div>
            </div>
            <div className="stat-item">
              <div className="stat-label">Total Recipients</div>
              <div className="stat-value total">
                {(toRecipients ? toRecipients.split(',').filter(e => e.trim()).length : 0) +
                 (ccRecipients ? ccRecipients.split(',').filter(e => e.trim()).length : 0) +
                 (bccRecipients ? bccRecipients.split(',').filter(e => e.trim()).length : 0)}
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="actions">
            <button
              onClick={saveMailing}
              className="save-button"
              disabled={loading}
            >
              💾 Save Mailing List
            </button>
            <button
              onClick={clearAll}
              className="clear-button"
              disabled={loading}
            >
              🗑️ Clear All
            </button>
            <button
              onClick={() => fetchMailingList(selectedRegion)}
              className="refresh-button"
              disabled={loading}
            >
              🔄 Refresh
            </button>
          </div>
        </div>
      )}

      {!selectedRegion && (
        <div className="no-selection">
          <p>👈 Please select a region to manage its mailing list</p>
        </div>
      )}
    </div>
  );
}

export default MailingListManager;
