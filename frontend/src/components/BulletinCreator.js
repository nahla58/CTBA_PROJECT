import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './BulletinCreator.css';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

/**
 * BulletinCreator Component
 * 
 * Features:
 * - Create bulletins with automatic CVE grouping
 * - Select multiple regions for delivery
 * - Upload file attachments
 * - Preview CVE grouping before submission
 * - Status management (Draft, Send, Archive)
 */
const BulletinCreator = () => {
  const [step, setStep] = useState('details'); // details, cves, regions, attachments, preview, submit
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Form State
  const [formData, setFormData] = useState({
    title: '',
    body: '',
    cveIds: [],
    cveInput: '',
    regionIds: [],
    auto_group: true,
    created_by: localStorage.getItem('username') || ''
  });

  // UI State
  const [regions, setRegions] = useState([]);
  const [cveGrouping, setCveGrouping] = useState(null);
  const [attachments, setAttachments] = useState([]);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [previewHtml, setPreviewHtml] = useState('');

  // Load regions on mount
  useEffect(() => {
    loadRegions();
  }, []);

  const loadRegions = async () => {
    try {
      const response = await axios.get(`${API_BASE}/regions/`);
      setRegions(response.data.regions || []);
    } catch (err) {
      setError('Failed to load regions');
      console.error(err);
    }
  };

  // ========== STEP 1: BULLETIN DETAILS ==========
  const handleDetailChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleAddCVE = () => {
    const cveId = formData.cveInput.trim().toUpperCase();
    if (cveId && /^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      if (!formData.cveIds.includes(cveId)) {
        setFormData(prev => ({
          ...prev,
          cveIds: [...prev.cveIds, cveId],
          cveInput: ''
        }));
      } else {
        setError('CVE already added');
      }
    } else {
      setError('Invalid CVE format. Use: CVE-YYYY-NNNNN');
    }
  };

  const handleRemoveCVE = (cveId) => {
    setFormData(prev => ({
      ...prev,
      cveIds: prev.cveIds.filter(id => id !== cveId)
    }));
  };

  const handleNextFromDetails = async () => {
    if (!formData.title.trim()) {
      setError('Title is required');
      return;
    }
    if (formData.cveIds.length === 0) {
      setError('At least one CVE is required');
      return;
    }

    // Analyze CVE grouping
    try {
      setLoading(true);
      const response = await axios.post(
        `${API_BASE}/bulletins/analyze/group-cves`,
        null,
        { params: { cve_ids: formData.cveIds } }
      );
      setCveGrouping(response.data);
      setStep('regions');
    } catch (err) {
      setError('Failed to analyze CVE grouping');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // ========== STEP 2: REGION SELECTION ==========
  const handleRegionToggle = (regionId) => {
    setFormData(prev => ({
      ...prev,
      regionIds: prev.regionIds.includes(regionId)
        ? prev.regionIds.filter(id => id !== regionId)
        : [...prev.regionIds, regionId]
    }));
  };

  const handleNextFromRegions = () => {
    if (formData.regionIds.length === 0) {
      setError('At least one region is required');
      return;
    }
    setStep('attachments');
  };

  // ========== STEP 3: ATTACHMENTS ==========
  const handleFileUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    
    for (const file of files) {
      // Validate file
      const ext = file.name.split('.').pop().toLowerCase();
      const allowedExt = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'zip', 'csv'];
      
      if (!allowedExt.includes(ext)) {
        setError(`File type .${ext} not allowed`);
        continue;
      }
      
      if (file.size > 50 * 1024 * 1024) {
        setError('File size exceeds 50 MB limit');
        continue;
      }

      setUploadedFiles(prev => [...prev, {
        name: file.name,
        size: file.size,
        file: file
      }]);
    }
  };

  const handleRemoveFile = (index) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index));
  };

  // ========== STEP 4: PREVIEW & SUBMIT ==========
  const handleCreateBulletin = async () => {
    try {
      setLoading(true);
      setError(null);

      // Create bulletin with CVE grouping
      const bulletinResponse = await axios.post(`${API_BASE}/bulletins/`, {
        title: formData.title,
        body: formData.body,
        cve_ids: formData.cveIds,
        region_ids: formData.regionIds,
        created_by: formData.created_by,
        auto_group: formData.auto_group
      });

      const bulletinId = bulletinResponse.data.id;

      // Upload attachments
      for (const file of uploadedFiles) {
        const fileData = new FormData();
        fileData.append('file', file.file);
        fileData.append('uploaded_by', formData.created_by);

        await axios.post(
          `${API_BASE}/bulletins/${bulletinId}/attachments/upload`,
          fileData,
          { headers: { 'Content-Type': 'multipart/form-data' } }
        );
      }

      setSuccess(`Bulletin created successfully (ID: ${bulletinId})`);
      
      // Reset form
      setTimeout(() => {
        setFormData({
          title: '',
          body: '',
          cveIds: [],
          cveInput: '',
          regionIds: [],
          auto_group: true,
          created_by: localStorage.getItem('username') || ''
        });
        setCveGrouping(null);
        setUploadedFiles([]);
        setStep('details');
      }, 2000);

    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create bulletin');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // ========== RENDER STEPS ==========

  if (step === 'details') {
    return (
      <div className="bulletin-creator">
        <h2>Create Security Bulletin</h2>
        
        {error && <div className="alert alert-error">{error}</div>}
        {success && <div className="alert alert-success">{success}</div>}

        <form className="form-section">
          <div className="form-group">
            <label>Bulletin Title *</label>
            <input
              type="text"
              name="title"
              value={formData.title}
              onChange={handleDetailChange}
              placeholder="e.g., Critical PHP Security Update"
              maxLength="200"
            />
          </div>

          <div className="form-group">
            <label>Description/Body</label>
            <textarea
              name="body"
              value={formData.body}
              onChange={handleDetailChange}
              placeholder="Additional information about this bulletin"
              rows="5"
              maxLength="5000"
            />
          </div>

          <div className="form-group">
            <label>CVE IDs to Include *</label>
            <div className="cve-input-group">
              <input
                type="text"
                name="cveInput"
                value={formData.cveInput}
                onChange={handleDetailChange}
                onKeyPress={(e) => e.key === 'Enter' && handleAddCVE()}
                placeholder="e.g., CVE-2026-1234"
              />
              <button
                type="button"
                onClick={handleAddCVE}
                className="btn btn-secondary"
              >
                Add CVE
              </button>
            </div>

            {formData.cveIds.length > 0 && (
              <div className="cve-list">
                <h4>Selected CVEs ({formData.cveIds.length})</h4>
                <div className="cve-tags">
                  {formData.cveIds.map(cveId => (
                    <span key={cveId} className="cve-tag">
                      {cveId}
                      <button
                        type="button"
                        onClick={() => handleRemoveCVE(cveId)}
                        className="cve-remove"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="form-group">
            <label className="checkbox">
              <input
                type="checkbox"
                name="auto_group"
                checked={formData.auto_group}
                onChange={(e) => setFormData(prev => ({
                  ...prev,
                  auto_group: e.target.checked
                }))}
              />
              Automatically group CVEs by technology/product
            </label>
          </div>

          <div className="form-actions">
            <button
              type="button"
              onClick={handleNextFromDetails}
              disabled={loading}
              className="btn btn-primary"
            >
              {loading ? 'Analyzing...' : 'Next: Select Regions'}
            </button>
          </div>
        </form>
      </div>
    );
  }

  if (step === 'regions') {
    return (
      <div className="bulletin-creator">
        <h2>Select Delivery Regions</h2>

        {error && <div className="alert alert-error">{error}</div>}

        <div className="regions-grid">
          {regions.map(region => (
            <div key={region.id} className="region-card">
              <label className="checkbox-card">
                <input
                  type="checkbox"
                  checked={formData.regionIds.includes(region.id)}
                  onChange={() => handleRegionToggle(region.id)}
                />
                <div className="region-info">
                  <h3>{region.name}</h3>
                  <p>{region.description}</p>
                  {region.region_code && <small>Code: {region.region_code}</small>}
                </div>
              </label>
            </div>
          ))}
        </div>

        {formData.regionIds.length > 0 && (
          <div className="selected-regions">
            <h4>Selected Regions ({formData.regionIds.length})</h4>
            <ul>
              {formData.regionIds.map(id => {
                const region = regions.find(r => r.id === id);
                return region ? <li key={id}>{region.name}</li> : null;
              })}
            </ul>
          </div>
        )}

        <div className="form-actions">
          <button
            type="button"
            onClick={() => setStep('details')}
            className="btn btn-secondary"
          >
            Back
          </button>
          <button
            type="button"
            onClick={handleNextFromRegions}
            className="btn btn-primary"
          >
            Next: Add Attachments
          </button>
        </div>
      </div>
    );
  }

  if (step === 'attachments') {
    return (
      <div className="bulletin-creator">
        <h2>Add Attachments (Optional)</h2>

        {error && <div className="alert alert-error">{error}</div>}

        <div className="file-upload-zone">
          <label htmlFor="file-input" className="upload-label">
            <div className="upload-icon">📎</div>
            <p>Click to select files or drag and drop</p>
            <small>Max 50 MB per file. Supported: PDF, DOC, XLSX, TXT, ZIP, CSV, JPG, PNG</small>
          </label>
          <input
            id="file-input"
            type="file"
            multiple
            onChange={handleFileUpload}
            className="file-input-hidden"
            accept=".pdf,.doc,.docx,.xls,.xlsx,.txt,.zip,.csv,.jpg,.png"
          />
        </div>

        {uploadedFiles.length > 0 && (
          <div className="uploaded-files">
            <h4>Files to Upload ({uploadedFiles.length})</h4>
            <ul>
              {uploadedFiles.map((file, index) => (
                <li key={index}>
                  <span>{file.name}</span>
                  <span className="file-size">({(file.size / 1024).toFixed(2)} KB)</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveFile(index)}
                    className="btn-remove"
                  >
                    ✕
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="form-actions">
          <button
            type="button"
            onClick={() => setStep('regions')}
            className="btn btn-secondary"
          >
            Back
          </button>
          <button
            type="button"
            onClick={handleCreateBulletin}
            disabled={loading}
            className="btn btn-success"
          >
            {loading ? 'Creating...' : 'Create Bulletin'}
          </button>
        </div>
      </div>
    );
  }

  return null;
};

export default BulletinCreator;
