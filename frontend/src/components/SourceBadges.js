import React, { useState } from 'react';

/**
 * SourceBadges Component
 * Displays source information in a user-friendly way
 * Shows primary source and secondary sources with tooltip
 * Clicking on "+X" opens a modal showing all secondary sources
 * Displays special indicator when CVE is enriched with CVE.org data
 */
function SourceBadges({ sourcePrimary, sourcesSecondary = [] }) {
  const [showModal, setShowModal] = useState(false);

  // Check if CVE.org is one of the sources
  const hasCveorg = sourcesSecondary && sourcesSecondary.some(s => 
    (s.name || s).toLowerCase() === 'cveorg'
  );

  // Color mapping for sources - Thème Nomios (Bleu Roi + Rouge)
  const getSourceColor = (source) => {
    const source_lower = (source || '').toLowerCase();
    const colors = {
      'nvd': '#0047AB',           // Bleu roi
      'cvedetails': '#3366CC',    // Bleu roi clair
      'cveorg': '#003380',        // Bleu roi foncé
      'hackuity': '#6495ED',      // Bleu cornflower
      'msrc': '#DC143C',          // Rouge vif (MSRC = Microsoft)
      'test': '#6C757D'           // Gris
    };
    return colors[source_lower] || '#6C757D'; // Gray default
  };

  const formatSourceName = (source) => {
    if (!source) return 'N/A';
    const mapping = {
      'nvd': 'NVD',
      'cvedetails': 'CVEdetails',
      'cveorg': 'CVE.org',
      'hackuity': 'Hackuity',
      'msrc': 'MSRC',
      'test': 'TEST'
    };
    return mapping[source.toLowerCase()] || source.toUpperCase();
  };

  // Generate tooltip text for secondary sources
  const secondarySourcesText = Array.isArray(sourcesSecondary)
    ? sourcesSecondary
        .map(s => `• ${formatSourceName(s.name || s)} (${s.added_at ? new Date(s.added_at).toLocaleDateString('fr-FR') : 'date inconnue'})`)
        .join('\n')
    : '';

  const badgeContainerStyle = {
    display: 'flex',
    gap: '4px',
    flexWrap: 'wrap',
    alignItems: 'center'
  };

  const badgeStyle = {
    backgroundColor: getSourceColor(sourcePrimary),
    color: 'white',
    padding: '4px 8px',
    borderRadius: '4px',
    fontSize: '0.8em',
    fontWeight: '600',
    textTransform: 'uppercase',
    whiteSpace: 'nowrap'
  };

  const cveorgBadgeStyle = {
    backgroundColor: '#06b6d4',
    color: 'white',
    padding: '4px 10px',
    borderRadius: '4px',
    fontSize: '0.8em',
    fontWeight: '700',
    textTransform: 'uppercase',
    whiteSpace: 'nowrap',
    border: '1px solid #0891b2',
    boxShadow: '0 0 6px rgba(6, 182, 212, 0.4)'
  };

  const secondaryBadgeStyle = {
    backgroundColor: '#6b7280',
    color: 'white',
    padding: '4px 8px',
    borderRadius: '4px',
    fontSize: '0.8em',
    fontWeight: '600',
    cursor: 'pointer',
    position: 'relative',
    transition: 'background-color 0.2s',
  };

  const secondaryBadgeHoverStyle = {
    ...secondaryBadgeStyle,
    backgroundColor: '#4b5563'
  };

  const modalOverlayStyle = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 1000
  };

  const modalContentStyle = {
    backgroundColor: 'white',
    borderRadius: '8px',
    padding: '24px',
    maxWidth: '500px',
    boxShadow: '0 10px 40px rgba(0, 0, 0, 0.3)',
    animation: 'slideIn 0.3s ease-out'
  };

  const modalHeaderStyle = {
    fontSize: '1.2em',
    fontWeight: '700',
    marginBottom: '16px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    color: '#1f2937'
  };

  const closeButtonStyle = {
    background: 'none',
    border: 'none',
    fontSize: '1.5em',
    cursor: 'pointer',
    color: '#6b7280',
    padding: '0 4px'
  };

  const sourceListStyle = {
    listStyle: 'none',
    padding: 0,
    margin: 0
  };

  const sourceItemStyle = {
    padding: '12px',
    marginBottom: '8px',
    backgroundColor: '#f3f4f6',
    borderRadius: '6px',
    borderLeft: '4px solid',
    display: 'flex',
    alignItems: 'center',
    gap: '12px'
  };

  const sourceColorBoxStyle = (source) => ({
    width: '20px',
    height: '20px',
    borderRadius: '4px',
    backgroundColor: getSourceColor(source.name),
    flexShrink: 0
  });

  const sourceInfoStyle = {
    flex: 1
  };

  const sourceNameStyle = {
    fontWeight: '600',
    color: '#1f2937',
    marginBottom: '4px'
  };

  const sourceDateStyle = {
    fontSize: '0.85em',
    color: '#6b7280'
  };

  return (
    <>
      <div style={badgeContainerStyle}>
        {/* Primary Source */}
        {sourcePrimary && (
          <span 
            style={badgeStyle}
            title={`Source primaire: ${formatSourceName(sourcePrimary)}`}
          >
            {formatSourceName(sourcePrimary)}
          </span>
        )}

        {/* CVE.org Badge - if this CVE was enriched from CVE.org */}
        {hasCveorg && (
          <span 
            style={cveorgBadgeStyle}
            title={`Données enrichies avec les informations officielles CVE.org (MITRE)`}
          >
            ✓ CVE.org
          </span>
        )}

        {/* Secondary Sources - Clickable */}
        {Array.isArray(sourcesSecondary) && sourcesSecondary.length > 0 && (
          <span
            style={secondaryBadgeStyle}
            onClick={() => setShowModal(true)}
            onMouseEnter={(e) => e.target.style.backgroundColor = '#4b5563'}
            onMouseLeave={(e) => e.target.style.backgroundColor = '#6b7280'}
            title={`Cliquez pour voir les sources secondaires`}
          >
            +{sourcesSecondary.length}
          </span>
        )}
      </div>

      {/* Modal for Secondary Sources */}
      {showModal && (
        <div style={modalOverlayStyle} onClick={() => setShowModal(false)}>
          <div style={modalContentStyle} onClick={(e) => e.stopPropagation()}>
            <div style={modalHeaderStyle}>
              <span>Sources Secondaires ({sourcesSecondary.length})</span>
              <button style={closeButtonStyle} onClick={() => setShowModal(false)}>
                ✕
              </button>
            </div>
            <ul style={sourceListStyle}>
              {Array.isArray(sourcesSecondary) && sourcesSecondary.map((source, idx) => (
                <li key={idx} style={{...sourceItemStyle, borderLeftColor: getSourceColor(source.name)}}>
                  <div style={sourceColorBoxStyle(source)}></div>
                  <div style={sourceInfoStyle}>
                    <div style={sourceNameStyle}>
                      {formatSourceName(source.name || source)}
                    </div>
                    <div style={sourceDateStyle}>
                      Ajoutée le {source.added_at ? new Date(source.added_at).toLocaleDateString('fr-FR', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                      }) : 'date inconnue'}
                    </div>
                    {source.data_enrichment && (
                      <div style={sourceDateStyle}>
                        Enrichissement: {source.data_enrichment}
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <style>{`
        @keyframes slideIn {
          from {
            opacity: 0;
            transform: translateY(-20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </>
  );
}

export default SourceBadges;
