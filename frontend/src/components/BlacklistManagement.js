import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './BlacklistManagement.css';

function BlacklistManagement({ user, onLogout }) {
  const [blacklistedProducts, setBlacklistedProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showScoreModal, setShowScoreModal] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [scoreAdjustments, setScoreAdjustments] = useState([]);
  const [adjustmentScore, setAdjustmentScore] = useState('');
  const [adjustmentReason, setAdjustmentReason] = useState('');

  useEffect(() => {
    fetchBlacklist();
  }, []);

  const fetchBlacklist = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(
        'http://localhost:8000/api/technologies?status=OUT_OF_SCOPE',
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );

      if (response.ok) {
        const data = await response.json();
        // Extract technologies from response
        setBlacklistedProducts(data.technologies || []);
      }
      setLoading(false);
    } catch (error) {
      console.error('Error fetching blacklist:', error);
      setLoading(false);
      setError('Error loading blacklist');
    }
  };

  const handleAddToBlacklist = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!vendor.trim() || !product.trim()) {
      setError('Please fill all required fields');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/api/technologies', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          vendor: vendor.trim(),
          product: product.trim(),
          status: 'OUT_OF_SCOPE',
          reason: reason.trim()
        })
      });

      if (response.ok) {
        setSuccess(`✅ ${vendor}/${product} added to blacklist`);
        setVendor('');
        setProduct('');
        setReason('');
        fetchBlacklist();
      } else {
        const data = await response.json();
        setError(data.detail || 'Error adding to blacklist');
      }
    } catch (error) {
      console.error('Error adding to blacklist:', error);
      setError('Connection error');
    }
  };

  const handleRemoveFromBlacklist = async (id) => {
    if (!window.confirm('Are you sure you want to reinstate this product?')) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/api/technologies/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        setSuccess('✅ Product reinstated successfully');
        fetchBlacklist();
      } else {
        setError('Error during deletion');
      }
    } catch (error) {
      console.error('Error removing from blacklist:', error);
      setError('Erreur de connexion');
    }
  };

  const openScoreModal = async (item) => {
    setSelectedProduct(item);
    setShowScoreModal(true);
    setAdjustmentScore('');
    setAdjustmentReason('');
    
    // Fetch existing adjustments for this product
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(
        `http://localhost:8000/api/cvss-adjustments?vendor=${encodeURIComponent(item.vendor)}&product=${encodeURIComponent(item.product)}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );
      
      if (response.ok) {
        const data = await response.json();
        setScoreAdjustments(data.adjustments || []);
      }
    } catch (error) {
      console.error('Error fetching adjustments:', error);
    }
  };

  const handleSaveScoreAdjustment = async (e) => {
    e.preventDefault();
    
    if (!selectedProduct || !adjustmentScore) {
      setError('Please enter an adjustment score');
      return;
    }

    const score = parseFloat(adjustmentScore);
    if (isNaN(score) || score < 0 || score > 10) {
      setError('Score must be between 0 and 10');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/api/cvss-adjustments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Bearer ${token}`
        },
        body: new URLSearchParams({
          cve_id: 'multiple',
          vendor: selectedProduct.vendor,
          product: selectedProduct.product,
          adjusted_score: score,
          adjustment_reason: adjustmentReason,
          analyst: user.username
        })
      });

      if (response.ok) {
        setSuccess('✅ Score adjustment saved');
        setShowScoreModal(false);
        setSelectedProduct(null);
        setAdjustmentScore('');
        setAdjustmentReason('');
      } else {
        const data = await response.json();
        setError(data.detail || 'Error saving adjustment');
      }
    } catch (error) {
      console.error('Error saving adjustment:', error);
      setError('Erreur de connexion');
    }
  };

  const canEdit = user.role === 'ADMINISTRATOR' || user.role === 'VOC_L1';

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
          <Link to="/blacklist" className="nav-item active">
            🚫 Blacklisted Products
          </Link>
          <Link to="/history" className="nav-item">
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
            <h1>🚫 Blacklist Management</h1>
            <p>Management of blacklisted products and reinstatement</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* Add to Blacklist Form */}
        {canEdit && (
          <div className="add-blacklist-form">
            <h2>➕ Add to Blacklist</h2>
            
            {error && <div className="alert alert-error">{error}</div>}
            {success && <div className="alert alert-success">{success}</div>}

            <form onSubmit={handleAddToBlacklist}>
              <div className="form-group">
                <label>Vendor *</label>
                <input
                  type="text"
                  value={vendor}
                  onChange={(e) => setVendor(e.target.value)}
                  placeholder="e.g., Apache"
                  required
                />
              </div>

              <div className="form-group">
                <label>Product *</label>
                <input
                  type="text"
                  value={product}
                  onChange={(e) => setProduct(e.target.value)}
                  placeholder="e.g., Apache HTTP Server"
                  required
                />
              </div>

              <div className="form-group">
                <label>Reason</label>
                <textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Reason for adding to blacklist..."
                  rows="3"
                />
              </div>

              <button type="submit" className="btn btn-primary">
                🚫 Add to Blacklist
              </button>
            </form>
          </div>
        )}

        {/* Blacklist Table */}
        <div className="blacklist-section">
          <h2>📋 Blacklisted Products ({blacklistedProducts.length})</h2>

          {loading ? (
            <div className="loading">⏳ Loading...</div>
          ) : blacklistedProducts.length === 0 ? (
            <div className="no-data">No blacklisted products</div>
          ) : (
            <div className="blacklist-table-container">
              <table className="blacklist-table">
                <thead>
                  <tr>
                    <th>Vendor</th>
                    <th>Product</th>
                    <th>Reason</th>
                    <th>Added by</th>
                    <th>Date Added</th>
                    {canEdit && <th>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {blacklistedProducts.map((item) => (
                    <tr key={item.id}>
                      <td className="vendor-cell">{item.vendor}</td>
                      <td className="product-cell">{item.product}</td>
                      <td className="reason-cell">{item.reason || '-'}</td>
                      <td className="added-by-cell">{item.added_by}</td>
                      <td className="date-cell">
                        {new Date(item.created_at).toLocaleDateString('en-US')}
                      </td>
                      {canEdit && (
                        <td className="actions-cell">
                          <button
                            className="btn btn-warning btn-small"
                            onClick={() => openScoreModal(item)}
                            style={{marginRight: '5px'}}
                          >
                            📊 Adjust Score
                          </button>
                          <button
                            className="btn btn-danger btn-small"
                            onClick={() => handleRemoveFromBlacklist(item.id)}
                          >
                            ♻️ Reinstate
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Score Adjustment Modal */}
        {showScoreModal && selectedProduct && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div style={{
              backgroundColor: 'white',
              borderRadius: '8px',
              maxWidth: '500px',
              width: '90%',
              padding: '30px',
              boxShadow: '0 4px 20px rgba(0,0,0,0.2)'
            }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '20px',
                borderBottom: '1px solid #e2e8f0',
                paddingBottom: '15px'
              }}>
                <h2>📊 CVSS Score Adjustment</h2>
                <button 
                  onClick={() => setShowScoreModal(false)}
                  style={{
                    background: 'none',
                    border: 'none',
                    fontSize: '24px',
                    cursor: 'pointer'
                  }}
                >
                  ✕
                </button>
              </div>

              <div style={{marginBottom: '20px'}}>
                <p><strong>Product:</strong> {selectedProduct.vendor}/{selectedProduct.product}</p>
              </div>

              {error && <div className="alert alert-error" style={{marginBottom: '15px'}}>{error}</div>}

              {scoreAdjustments.length > 0 && (
                <div style={{marginBottom: '20px', padding: '10px', backgroundColor: '#f0f9ff', borderRadius: '4px'}}>
                  <h4>Previous Adjustments:</h4>
                  <ul style={{margin: '10px 0', paddingLeft: '20px'}}>
                    {scoreAdjustments.map((adj, i) => (
                      <li key={i}>
                        Adjusted score: <strong>{adj.adjusted_score}/10</strong> (Original: {adj.original_score || 'N/A'})
                        <br/>
                        <small>By {adj.analyst} on {new Date(adj.updated_at).toLocaleDateString('en-US')}</small>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <form onSubmit={handleSaveScoreAdjustment}>
                <div style={{marginBottom: '15px'}}>
                  <label style={{display: 'block', marginBottom: '5px', fontWeight: '600'}}>
                    Adjusted CVSS Score *
                  </label>
                  <input
                    type="number"
                    min="0"
                    max="10"
                    step="0.1"
                    value={adjustmentScore}
                    onChange={(e) => setAdjustmentScore(e.target.value)}
                    placeholder="Between 0 and 10"
                    style={{
                      width: '100%',
                      padding: '8px',
                      border: '1px solid #cbd5e1',
                      borderRadius: '4px',
                      fontSize: '14px'
                    }}
                    required
                  />
                </div>

                <div style={{marginBottom: '15px'}}>
                  <label style={{display: 'block', marginBottom: '5px', fontWeight: '600'}}>
                    Adjustment Reason
                  </label>
                  <textarea
                    value={adjustmentReason}
                    onChange={(e) => setAdjustmentReason(e.target.value)}
                    placeholder="Explain why this score is adjusted..."
                    rows="3"
                    style={{
                      width: '100%',
                      padding: '8px',
                      border: '1px solid #cbd5e1',
                      borderRadius: '4px',
                      fontSize: '14px',
                      fontFamily: 'inherit'
                    }}
                  />
                </div>

                <div style={{display: 'flex', gap: '10px'}}>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    style={{flex: 1}}
                  >
                    ✅ Save
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowScoreModal(false)}
                    style={{
                      flex: 1,
                      padding: '8px 16px',
                      backgroundColor: '#e2e8f0',
                      color: '#1e293b',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontWeight: '500'
                    }}
                  >
                    ✕ Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default BlacklistManagement;
