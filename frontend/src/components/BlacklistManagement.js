import React, { useState, useEffect } from 'react';
import './BlacklistManagement.css';

function BlacklistManagement({ user, onLogout }) {
  const [blacklistedProducts, setBlacklistedProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

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
      setError('Erreur lors du chargement de la blacklist');
    }
  };

  const handleAddToBlacklist = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!vendor.trim() || !product.trim()) {
      setError('Veuillez remplir tous les champs obligatoires');
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
        setSuccess(`✅ ${vendor}/${product} ajouté à la blacklist`);
        setVendor('');
        setProduct('');
        setReason('');
        fetchBlacklist();
      } else {
        const data = await response.json();
        setError(data.detail || 'Erreur lors de l\'ajout à la blacklist');
      }
    } catch (error) {
      console.error('Error adding to blacklist:', error);
      setError('Erreur de connexion');
    }
  };

  const handleRemoveFromBlacklist = async (id) => {
    if (!window.confirm('Êtes-vous sûr de vouloir réintégrer ce produit?')) {
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
        setSuccess('✅ Produit réintégré avec succès');
        fetchBlacklist();
      } else {
        setError('Erreur lors de la suppression');
      }
    } catch (error) {
      console.error('Error removing from blacklist:', error);
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
          <a href="/" className="nav-item">
            📊 Dashboard
          </a>
          <a href="/accepted" className="nav-item">
            ✅ CVEs Acceptés
          </a>
          <a href="/rejected" className="nav-item">
            ❌ CVEs Rejetés
          </a>
          <a href="/blacklist" className="nav-item active">
            🚫 Produits Blacklistés
          </a>
          <a href="/history" className="nav-item">
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
            <h1>🚫 Blacklist Management</h1>
            <p>Gestion des produits blacklistés et réintégration</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* Add to Blacklist Form */}
        {canEdit && (
          <div className="add-blacklist-form">
            <h2>➕ Ajouter à la blacklist</h2>
            
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
                  placeholder="Raison de l'ajout à la blacklist..."
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
          <h2>📋 Produits Blacklistés ({blacklistedProducts.length})</h2>

          {loading ? (
            <div className="loading">⏳ Chargement...</div>
          ) : blacklistedProducts.length === 0 ? (
            <div className="no-data">Aucun produit blacklisté</div>
          ) : (
            <div className="blacklist-table-container">
              <table className="blacklist-table">
                <thead>
                  <tr>
                    <th>Vendor</th>
                    <th>Product</th>
                    <th>Reason</th>
                    <th>Ajouté par</th>
                    <th>Date d'ajout</th>
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
                        {new Date(item.created_at).toLocaleDateString('fr-FR')}
                      </td>
                      {canEdit && (
                        <td className="actions-cell">
                          <button
                            className="btn btn-danger btn-small"
                            onClick={() => handleRemoveFromBlacklist(item.id)}
                          >
                            ♻️ Réintégrer
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
      </div>
    </div>
  );
}

export default BlacklistManagement;
