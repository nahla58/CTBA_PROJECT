import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';
import './BlacklistManager.css';

function BlacklistManager() {
  const [blacklist, setBlacklist] = useState([]);
  const [newProduct, setNewProduct] = useState({ vendor: '', product: '', reason: '' });
  const [stats, setStats] = useState(null);

  useEffect(() => {
    loadBlacklist();
    loadStats();
  }, []);

  const loadBlacklist = async () => {
    try {
      const data = await apiService.getBlacklist();
      setBlacklist(data);
    } catch (error) {
      console.error('Erreur blacklist:', error);
    }
  };

  const loadStats = async () => {
    try {
      const data = await apiService.getStats();
      setStats(data);
    } catch (error) {
      console.error('Erreur stats:', error);
    }
  };

  const handleAdd = async () => {
    if (!newProduct.vendor || !newProduct.product) {
      alert('Vendor et Product requis');
      return;
    }

    try {
      await apiService.addToBlacklist(
        newProduct.vendor,
        newProduct.product,
        newProduct.reason
      );
      alert('✅ Produit ajouté à la blacklist');
      setNewProduct({ vendor: '', product: '', reason: '' });
      loadBlacklist();
    } catch (error) {
      alert('❌ Erreur ajout');
    }
  };

  return (
    <div className="blacklist-container">
      <h1>⚫ Gestion Blacklist</h1>
      
      {/* Statistiques */}
      {stats && (
        <div className="stats-card">
          <h3>📊 Impact Blacklist</h3>
          <div className="stats-grid">
            <div className="stat-item">
              <div className="stat-value">{blacklist.length}</div>
              <div className="stat-label">Produits blacklistés</div>
            </div>
            <div className="stat-item">
              <div className="stat-value">{stats.summary?.total_cves || 0}</div>
              <div className="stat-label">CVE totales</div>
            </div>
            <div className="stat-item">
              <div className="stat-value">{stats.summary?.pending_cves || 0}</div>
              <div className="stat-label">CVE en attente</div>
            </div>
          </div>
        </div>
      )}

      {/* Formulaire ajout */}
      <div className="add-form">
        <h3>➕ Ajouter un produit</h3>
        <div className="form-grid">
          <input
            type="text"
            placeholder="Vendor (ex: Microsoft)"
            value={newProduct.vendor}
            onChange={e => setNewProduct({...newProduct, vendor: e.target.value})}
          />
          <input
            type="text"
            placeholder="Product (ex: Internet Explorer)"
            value={newProduct.product}
            onChange={e => setNewProduct({...newProduct, product: e.target.value})}
          />
          <input
            type="text"
            placeholder="Raison (optionnel)"
            value={newProduct.reason}
            onChange={e => setNewProduct({...newProduct, reason: e.target.value})}
          />
          <button onClick={handleAdd} className="btn-add">
            Ajouter à Blacklist
          </button>
        </div>
      </div>

      {/* Liste */}
      <div className="blacklist-table">
        <h3>📋 Produits Blacklistés</h3>
        <table>
          <thead>
            <tr>
              <th>Vendor</th>
              <th>Product</th>
              <th>Raison</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {blacklist.map(item => (
              <tr key={item.id}>
                <td><strong>{item.vendor}</strong></td>
                <td>{item.product}</td>
                <td>{item.reason || '-'}</td>
                <td>{new Date(item.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default BlacklistManager;