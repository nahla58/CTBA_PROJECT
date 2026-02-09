import React from 'react';

export default function BootstrapDashboard() {
  return (
    <div className="container py-4">
      <div className="d-flex align-items-center mb-4">
        <img src="/logo_nomios.svg" alt="Nomios" style={{height:64, marginRight:16}}/>
        <div>
          <h1 className="h3 mb-0">CTBA Platform</h1>
          <small className="text-muted">CVE tracking & technology risk management</small>
        </div>
      </div>

      <div className="row">
        <div className="col-md-8">
          <div className="card mb-3">
            <div className="card-body">
              <h5 className="card-title">Bulletin Template</h5>
              <p className="card-text text-muted">Use this area to prepare internal bulletins. The logo above is hosted in <code>/public</code>.</p>
              <a href="/cves" className="btn btn-primary">View CVEs</a>
            </div>
          </div>

          <div className="card">
            <div className="card-body">
              <h5 className="card-title">Latest CVEs (preview)</h5>
              <div className="list-group">
                <div className="list-group-item">CVE-2025-0001 — <span className="badge bg-danger">HIGH</span> — ExampleApp RCE</div>
                <div className="list-group-item">CVE-2025-0002 — <span className="badge bg-warning text-dark">MEDIUM</span> — WidgetLib info leak</div>
              </div>
            </div>
          </div>
        </div>

        <div className="col-md-4">
          <div className="card mb-3">
            <div className="card-body">
              <h6 className="card-subtitle mb-2 text-muted">Quick Actions</h6>
              <div className="d-grid gap-2">
                <a className="btn btn-outline-secondary" href="/technologies">Manage Technologies</a>
                <a className="btn btn-outline-secondary" href="/stats">View Stats</a>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-body">
              <h6 className="card-subtitle mb-2 text-muted">Template Notes</h6>
              <p className="small text-muted">This is a frontend-only bootstrap template. Replace content with dynamic data from API as needed.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
