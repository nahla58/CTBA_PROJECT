import React, { useState } from 'react';
import './NLPImprovement.css';

function NLPImprovement({ user, onLogout }) {
  const [batchSize, setBatchSize] = useState(10);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const handleImproveWithNLP = async () => {
    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await fetch(
        `http://localhost:8000/api/nlp/improve-cves?batch_size=${batchSize}`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        }
      );

      if (response.ok) {
        const data = await response.json();
        setResults(data);
      } else {
        const data = await response.json();
        setError(data.detail || 'Error improving CVEs with NLP');
      }
    } catch (err) {
      console.error('Error:', err);
      setError('Error communicating with server');
    } finally {
      setLoading(false);
    }
  };

  const handleTestNLPOnCVE = async (cveId) => {
    setLoading(true);
    setError('');

    try {
      const response = await fetch(
        `http://localhost:8000/api/nlp/test-cve/${cveId}`,
        {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        }
      );

      if (response.ok) {
        const data = await response.json();
        setResults(data);
      } else {
        setError('Error testing CVE');
      }
    } catch (err) {
      console.error('Error:', err);
      setError('Error communicating with server');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dashboard-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <div className="logo-icon">🤖</div>
            <div>CTBA</div>
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
          <a href="/blacklist" className="nav-item">
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
            <h1>🤖 NLP Product Extraction</h1>
            <p>Améliorer l'extraction des produits affectés avec NLP et CPE URIs</p>
          </div>
          <div className="user-section">
            <span className="user-info">👤 {user.username} ({user.role})</span>
            <button onClick={onLogout} className="btn-logout">🔓 Logout</button>
          </div>
        </div>

        {/* Controls Section */}
        <div className="controls-section">
          <div className="control-card">
            <h2>🔧 Amélioration Batch</h2>
            <p>Améliorer les CVEs avec extraction faible ou manquante</p>
            <div className="form-group">
              <label>Nombre de CVEs à traiter:</label>
              <input
                type="number"
                min="1"
                max="100"
                value={batchSize}
                onChange={(e) => setBatchSize(parseInt(e.target.value))}
                style={{padding: '10px', fontSize: '14px', marginRight: '10px'}}
              />
            </div>
            <button
              onClick={handleImproveWithNLP}
              disabled={loading}
              className="btn-primary"
              style={{marginTop: '10px'}}
            >
              {loading ? '⏳ Traitement...' : '▶️ Lancer l\'amélioration'}
            </button>
          </div>

          <div className="control-card">
            <h2>🔍 Test sur un CVE</h2>
            <p>Tester NLP sur un CVE spécifique</p>
            <div className="form-group">
              <input
                type="text"
                placeholder="Ex: CVE-2026-1234"
                id="cveIdInput"
                style={{padding: '10px', fontSize: '14px', marginRight: '10px'}}
              />
              <button
                onClick={() => {
                  const cveId = document.getElementById('cveIdInput').value;
                  if (cveId) handleTestNLPOnCVE(cveId);
                }}
                disabled={loading}
                className="btn-secondary"
              >
                {loading ? '⏳ Test...' : '🔍 Tester'}
              </button>
            </div>
          </div>

          <div className="control-card">
            <h2>🧹 Nettoyer les Extractions</h2>
            <p>Supprimer les produits mal extraits (Github:, Vuldb:, génériques)</p>
            <button
              onClick={() => {
                if (window.confirm('Cela va nettoyer et supprimer les mauvaises extractions. Continuer ?')) {
                  setLoading(true);
                  setError('');
                  fetch('http://localhost:8000/api/nlp/clean-affected-products?limit=1000', {
                    method: 'POST',
                    headers: {
                      'Authorization': `Bearer ${localStorage.getItem('token')}`
                    }
                  })
                  .then(r => r.json())
                  .then(data => {
                    if (data.success) {
                      setError(`✅ ${data.message}`);
                    } else {
                      setError('Erreur: ' + (data.detail || 'Nettoyage échoué'));
                    }
                  })
                  .catch(err => setError('Erreur serveur: ' + err.message))
                  .finally(() => setLoading(false));
                }
              }}
              disabled={loading}
              className="btn-danger"
              style={{marginTop: '10px'}}
            >
              {loading ? '⏳ Nettoyage...' : '🧹 Nettoyer les extractions'}
            </button>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div style={{
            padding: '16px',
            backgroundColor: '#fee2e2',
            color: '#991b1b',
            borderRadius: '8px',
            marginBottom: '20px'
          }}>
            ❌ {error}
          </div>
        )}

        {/* Results Section */}
        {results && (
          <div className="results-section">
            {results.improvements ? (
              // Batch improvement results
              <>
                <div className="stats-cards">
                  <div className="stat-card-small">
                    <div className="stat-number">{results.processed}</div>
                    <div className="stat-label">CVEs traités</div>
                  </div>
                  <div className="stat-card-small">
                    <div className="stat-number">{results.improved}</div>
                    <div className="stat-label">CVEs améliorés</div>
                  </div>
                  <div className="stat-card-small">
                    <div className="stat-number">
                      {results.improvements.reduce((sum, imp) => sum + imp.new_products, 0)}
                    </div>
                    <div className="stat-label">Nouveaux produits</div>
                  </div>
                </div>

                {results.improvements.length > 0 && (
                  <div className="improvements-list">
                    <h3>📋 Improvement Details</h3>
                    {results.improvements.map((imp, idx) => (
                      <div key={idx} className="improvement-item">
                        <h4>{imp.cve_id}</h4>
                        <p>{imp.new_products} nouveau(x) produit(s) détecté(s):</p>
                        <ul>
                          {imp.products.map((prod, pidx) => (
                            <li key={pidx}>
                              <strong>{prod.vendor}/{prod.product}</strong>
                              <span className="confidence">
                                Confiance: {(prod.confidence * 100).toFixed(0)}%
                              </span>
                              <span className="source">{prod.source}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              // Single CVE test results
              <>
                <div className="cve-test-results">
                  <h3>CVE: {results.cve_id}</h3>
                  <p><strong>Description:</strong> {results.description_preview}</p>
                  
                  <div className="comparison">
                    <div className="col">
                      <h4>🤖 Extraction NLP ({results.nlp_products.length})</h4>
                      {results.nlp_products.length > 0 ? (
                        <ul>
                          {results.nlp_products.map((prod, idx) => (
                            <li key={idx}>
                              <strong>{prod.vendor}/{prod.product}</strong>
                              <span className="confidence">Confiance: {(prod.confidence * 100).toFixed(0)}%</span>
                              <span className="source">{prod.source}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p>Aucun produit détecté</p>
                      )}
                    </div>

                    <div className="col">
                      <h4>📊 Extraction existante ({results.existing_products.length})</h4>
                      {results.existing_products.length > 0 ? (
                        <ul>
                          {results.existing_products.map((prod, idx) => (
                            <li key={idx}>
                              <strong>{prod.vendor}/{prod.product}</strong>
                              <span className="confidence">Confiance: {(prod.confidence * 100).toFixed(0)}%</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p>Aucun produit enregistré</p>
                      )}
                    </div>
                  </div>

                  <div className="comparison-stats">
                    <p><strong>Correspondances:</strong> {results.comparison.matches}/{results.comparison.nlp_count} produits NLP trouvés existants</p>
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default NLPImprovement;
