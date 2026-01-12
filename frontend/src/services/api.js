// frontend/src/services/api.js
const API_BASE = 'http://localhost:8000';

// Configuration de base
const apiConfig = {
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
};

// Service principal
export const apiService = {
  // ========== CVEs ==========
  async getCVEs(filters = {}) {
    const params = new URLSearchParams();
    
    // Filtres supportés
    if (filters.status) params.append('status', filters.status);
    if (filters.severity) params.append('severity', filters.severity);
    if (filters.techStatus) params.append('tech_status', filters.techStatus);
    if (filters.limit) params.append('limit', filters.limit);
    if (filters.offset) params.append('offset', filters.offset);
    
    const response = await fetch(`${API_BASE}/cves?${params}`);
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    
    const data = await response.json();
    
    // Formater les données pour le frontend
    return {
      cves: data.cves.map(cve => ({
        id: cve.cve_id,
        cve_id: cve.cve_id,
        description: cve.description || 'No description available',
        severity: cve.severity || 'LOW',
        cvss_score: cve.cvss_score || 0.0,
        published_date: cve.published_date,
        status: cve.status || 'PENDING',
        analyst: cve.analyst || null,
        decision_date: cve.decision_date,
        matched_technology_status: cve.matched_technology_status,
        affected_products: cve.affected_products || [],
        // Calculer les statuts
        isCritical: cve.severity === 'CRITICAL',
        isHighPriority: cve.severity === 'HIGH' || cve.matched_technology_status === 'PRIORITY',
        needsAttention: cve.status === 'PENDING' && (cve.severity === 'CRITICAL' || cve.severity === 'HIGH')
      })),
      pagination: data.pagination
    };
  },

  async getCVEDetail(cveId) {
    const response = await fetch(`${API_BASE}/cves/${cveId}`);
    if (!response.ok) throw new Error('CVE not found');
    return await response.json();
  },

  async makeDecision(cveId, decision, analyst, comments = '') {
    const response = await fetch(`${API_BASE}/cves/${cveId}/decision`, {
      method: 'POST',
      headers: apiConfig.headers,
      body: JSON.stringify({
        decision: decision.toUpperCase(),
        analyst,
        comments
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Decision failed');
    }
    
    return await response.json();
  },

  // ========== TECHNOLOGIES ==========
  async getTechnologies(filters = {}) {
    const params = new URLSearchParams();
    if (filters.status) params.append('status', filters.status);
    
    const response = await fetch(`${API_BASE}/technologies?${params}`);
    if (!response.ok) throw new Error('Failed to fetch technologies');
    
    const data = await response.json();
    
    // Formater pour le frontend
    return {
      technologies: data.technologies.map(tech => ({
        id: `${tech.vendor}-${tech.product}`,
        vendor: tech.vendor,
        product: tech.product,
        status: tech.status,
        reason: tech.reason || '',
        added_by: tech.added_by || 'system',
        created_at: tech.created_at,
        // Informations supplémentaires
        statusText: this.getTechStatusText(tech.status),
        statusColor: this.getTechStatusColor(tech.status),
        isOutOfScope: tech.status === 'OUT_OF_SCOPE',
        isPriority: tech.status === 'PRIORITY',
        isNormal: tech.status === 'NORMAL'
      })),
      statistics: data.statistics,
      total: data.total
    };
  },

  async addTechnology(techData) {
    const response = await fetch(`${API_BASE}/technologies`, {
      method: 'POST',
      headers: apiConfig.headers,
      body: JSON.stringify({
        vendor: techData.vendor,
        product: techData.product,
        status: techData.status,
        added_by: techData.added_by || 'analyst',
        reason: techData.reason || ''
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to add technology');
    }
    
    return await response.json();
  },

  async deleteTechnology(vendor, product) {
    const response = await fetch(`${API_BASE}/technologies/${vendor}/${product}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) throw new Error('Failed to delete technology');
    return await response.json();
  },

  async getTechnologyStats() {
    const response = await fetch(`${API_BASE}/technologies/stats`);
    if (!response.ok) throw new Error('Failed to fetch technology stats');
    return await response.json();
  },

  // ========== STATISTICS ==========
  async getStats() {
    const response = await fetch(`${API_BASE}/stats`);
    if (!response.ok) throw new Error('Failed to fetch statistics');
    return await response.json();
  },

  // ========== IMPORT ==========
  async triggerImport() {
    const response = await fetch(`${API_BASE}/import/trigger`, {
      method: 'POST'
    });
    
    if (!response.ok) throw new Error('Import failed');
    return await response.json();
  },

  // ========== UTILITIES ==========
  getSeverityColor(severity) {
    const colors = {
      CRITICAL: '#dc3545',
      HIGH: '#fd7e14',
      MEDIUM: '#ffc107',
      LOW: '#28a745'
    };
    return colors[severity?.toUpperCase()] || '#6c757d';
  },

  getTechStatusColor(status) {
    const colors = {
      'OUT_OF_SCOPE': '#dc3545',
      'PRIORITY': '#ffc107',
      'NORMAL': '#28a745',
      'NOT_TRACKED': '#6c757d'
    };
    return colors[status] || '#6c757d';
  },

  getTechStatusText(status) {
    const texts = {
      'OUT_OF_SCOPE': 'Out of Scope',
      'PRIORITY': 'Priority',
      'NORMAL': 'Normal',
      'NOT_TRACKED': 'Not Tracked'
    };
    return texts[status] || status;
  },

  getStatusText(status) {
    const texts = {
      'PENDING': 'Pending Review',
      'VALIDATED': 'Validated',
      'REJECTED': 'Rejected'
    };
    return texts[status] || status;
  },

  // ========== FILTERING ==========
  filterCVEsByScope(cves, scopeFilter) {
    if (!scopeFilter || scopeFilter === 'ALL') return cves;
    
    return cves.filter(cve => {
      const techStatus = cve.matched_technology_status;
      
      switch (scopeFilter) {
        case 'IN_SCOPE':
          return techStatus === 'NORMAL' || techStatus === 'PRIORITY';
        case 'OUT_OF_SCOPE':
          return techStatus === 'OUT_OF_SCOPE';
        case 'PRIORITY':
          return techStatus === 'PRIORITY';
        case 'NO_MATCH':
          return !techStatus;
        default:
          return true;
      }
    });
  },

  // ========== PRIORITY CALCULATION ==========
  calculatePriority(cve) {
    let score = 0;
    
    // Sévérité
    if (cve.severity === 'CRITICAL') score += 10;
    if (cve.severity === 'HIGH') score += 7;
    if (cve.severity === 'MEDIUM') score += 3;
    
    // Statut technologie
    if (cve.matched_technology_status === 'PRIORITY') score += 5;
    if (cve.matched_technology_status === 'NORMAL') score += 2;
    
    // Ancienneté
    const daysOld = cve.published_date ? 
      (new Date() - new Date(cve.published_date)) / (1000 * 60 * 60 * 24) : 0;
    if (daysOld < 7) score += 3; // Récent
    if (daysOld > 30) score -= 2; // Ancien
    
    return score;
  }
};

// Instance unique
export default apiService;