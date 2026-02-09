import React, { useState, useEffect, useCallback } from 'react';
import {
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Paper, Chip, IconButton, Button, Dialog, DialogTitle, DialogContent,
  DialogActions, TextField, Select, MenuItem, FormControl, InputLabel,
  Alert, Snackbar, Box, Typography, Tooltip, Card, CardContent,
  CircularProgress, Grid
} from '@mui/material';
import {
  CheckCircle, Cancel, Visibility, PriorityHigh,
  Warning, BugReport, Security, Refresh, FilterList
} from '@mui/icons-material';
import axios from 'axios';
import AddTechnologyModal from './AddTechnologyModal';
import AIRemediationPanel from './AIRemediationPanel';
import { format, parseISO, differenceInDays } from 'date-fns';

const API_URL = 'http://localhost:8000';

const CVEList = () => {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCve, setSelectedCve] = useState(null);
  const [actionDialogOpen, setActionDialogOpen] = useState(false);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [filters, setFilters] = useState({
    status: 'PENDING',
    severity: '',
    vendor: ''
  });
  const [analystName, setAnalystName] = useState('admin');
  const [authToken, setAuthToken] = useState(localStorage.getItem('ctba_token') || null);
  const [userRole, setUserRole] = useState(localStorage.getItem('ctba_role') || null);
  const [loginDialogOpen, setLoginDialogOpen] = useState(false);
  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [addTechDialogOpen, setAddTechDialogOpen] = useState(false);
  const [techToAdd, setTechToAdd] = useState({ vendor: '', product: '' });
  const [newTechStatus, setNewTechStatus] = useState('NORMAL');
  const [newTechReason, setNewTechReason] = useState('Added from CVE list');
  const [stats, setStats] = useState({
    summary: {
      total_cves: 0,
      pending_cves: 0,
      accepted_cves: 0,
      rejected_cves: 0,
      cves_by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    }
  });

  // Fetch CVEs
  const fetchCves = useCallback(async () => {
    try {
      setLoading(true);
      console.log('Fetching CVEs with filters:', filters);
      
      const response = await axios.get(`${API_URL}/api/cves`, {
        params: {
          status: filters.status,
          severity: filters.severity,
          vendor: filters.vendor,
          limit: 50
        }
      });
      
      console.log('CVEs response:', response.data);
      
      if (response.data.success) {
        setCves(response.data.cves || []);
      }
      
    } catch (error) {
      console.error('Error fetching CVEs:', error);
      showSnackbar('Error fetching CVE data', 'error');
    } finally {
      setLoading(false);
    }
  }, [filters]);

  // Fetch Stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await axios.get(`${API_URL}/api/stats`);
      if (response.data.success) {
        setStats(response.data);
      }
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  }, []);

  // Initial load
  useEffect(() => {
    fetchCves();
    fetchStats();
    
    // Refresh every 30 seconds
    const interval = setInterval(fetchCves, 30000);
    return () => clearInterval(interval);
  }, []);

  // Load persisted user
  useEffect(() => {
    const u = localStorage.getItem('ctba_user');
    const t = localStorage.getItem('ctba_token');
    const r = localStorage.getItem('ctba_role');
    if (u) setAnalystName(u);
    if (t) {
      setAuthToken(t);
      axios.defaults.headers.common['Authorization'] = `Bearer ${t}`;
    }
    if (r) setUserRole(r);
  }, []);

  // Re-fetch when filters change
  useEffect(() => {
    fetchCves();
  }, [filters]);

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  // Handle action - SIMPLIFIED
  const handleAction = async (action) => {
    if (!selectedCve) return;
    
    try {
      console.log(`Action ${action} for ${selectedCve.cve_id}`);
      
      const response = await axios.post(
        `${API_URL}/api/cves/${selectedCve.cve_id}/action`,
        {
          action,
          analyst: analystName,
          comments: `${action} by ${analystName}`,
          priority: 'NORMAL'
        }
      );
      
      console.log('Action response:', response.data);
      
      if (response.data.success) {
        showSnackbar(`CVE ${selectedCve.cve_id} marked as ${action}`, 'success');
        setActionDialogOpen(false);
        
        // Refresh data after action
        setTimeout(() => {
          fetchCves();
          fetchStats();
        }, 500);
      }
      
    } catch (error) {
      console.error('Error recording action:', error);
      showSnackbar('Error recording action', 'error');
    }
  };

  // Trigger import
  const triggerImport = async () => {
    try {
      await axios.post(`${API_URL}/api/import/trigger`);
      showSnackbar('Manual import triggered', 'info');
      setTimeout(() => {
        fetchCves();
        fetchStats();
      }, 10000); // Wait longer for import to complete
    } catch (error) {
      console.error('Error triggering import:', error);
      showSnackbar('Error triggering import', 'error');
    }
  };

  const handleLogin = async () => {
    try {
      const resp = await axios.post(`${API_URL}/api/auth/login`, { username: loginUser, password: loginPass });
      const data = resp.data;
      if (data && data.access_token) {
        const token = data.access_token;
        localStorage.setItem('ctba_token', token);
        localStorage.setItem('ctba_user', data.username || loginUser);
        localStorage.setItem('ctba_role', data.role || '');
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        setAuthToken(token);
        setAnalystName(data.username || loginUser);
        setUserRole(data.role || '');
        setLoginDialogOpen(false);
        showSnackbar('Login successful', 'success');
      }
    } catch (err) {
      console.error('Login failed', err);
      showSnackbar('Login failed', 'error');
    }
  };

  // Severity badge
  const SeverityBadge = ({ severity }) => {
    const colors = {
      CRITICAL: '#dc2626',
      HIGH: '#ea580c',
      MEDIUM: '#d97706',
      LOW: '#65a30d'
    };
    
    return (
      <Chip
        label={severity}
        size="small"
        sx={{
          backgroundColor: colors[severity] || '#6b7280',
          color: 'white',
          fontWeight: 'bold'
        }}
      />
    );
  };

  // Status chip
  const StatusChip = ({ status }) => {
    const config = {
      PENDING: { color: '#f59e0b' },
      ACCEPTED: { color: '#10b981' },
      REJECTED: { color: '#ef4444' },
      DEFERRED: { color: '#8b5cf6' }
    };
    
    const cfg = config[status] || { color: '#6b7280' };
    
    return (
      <Chip
        label={status}
        size="small"
        sx={{
          backgroundColor: cfg.color,
          color: 'white',
          fontWeight: 'bold'
        }}
      />
    );
  };

  // Stats Panel
  const StatsPanel = () => {
    const safeStats = stats.summary || {
      total_cves: 0,
      pending_cves: 0,
      accepted_cves: 0,
      rejected_cves: 0,
      cves_by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    };
    
    return (
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">CTBA Platform Dashboard</Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                startIcon={<Refresh />}
                onClick={fetchCves}
                variant="outlined"
                size="small"
              >
                Refresh
              </Button>
              <Button
                startIcon={<Refresh />}
                onClick={triggerImport}
                variant="contained"
                size="small"
              >
                Import CVEs
              </Button>
            </Box>
          </Box>
          
          <Grid container spacing={2}>
            <Grid item xs={6} sm={3}>
              <StatCard
                title="Total CVEs"
                value={safeStats.total_cves}
                color="#3b82f6"
                icon={<Security />}
              />
            </Grid>
            <Grid item xs={6} sm={3}>
              <StatCard
                title="Pending"
                value={safeStats.pending_cves}
                color="#f59e0b"
                icon={<Warning />}
              />
            </Grid>
            <Grid item xs={6} sm={3}>
              <StatCard
                title="Critical"
                value={safeStats.cves_by_severity?.CRITICAL || 0}
                color="#dc2626"
                icon={<PriorityHigh />}
              />
            </Grid>
            <Grid item xs={6} sm={3}>
              <StatCard
                title="High"
                value={safeStats.cves_by_severity?.HIGH || 0}
                color="#ea580c"
                icon={<BugReport />}
              />
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    );
  };

  const StatCard = ({ title, value, color, icon }) => (
    <Card variant="outlined">
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <Box sx={{ color, mr: 1 }}>{icon}</Box>
          <Typography variant="body2" color="text.secondary">
            {title}
          </Typography>
        </Box>
        <Typography variant="h4" sx={{ color, fontWeight: 'bold' }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  );

  if (loading && cves.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', flexDirection: 'column' }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading CTBA Platform...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <StatsPanel />
      
      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            <Typography variant="subtitle1" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <FilterList /> Filters
            </Typography>
            
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={filters.status}
                label="Status"
                onChange={(e) => setFilters({ ...filters, status: e.target.value })}
              >
                <MenuItem value="PENDING">Pending</MenuItem>
                <MenuItem value="ACCEPTED">Accepted</MenuItem>
                <MenuItem value="REJECTED">Rejected</MenuItem>
                <MenuItem value="">All Statuses</MenuItem>
              </Select>
            </FormControl>
            
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Severity</InputLabel>
              <Select
                value={filters.severity}
                label="Severity"
                onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="CRITICAL">Critical</MenuItem>
                <MenuItem value="HIGH">High</MenuItem>
                <MenuItem value="MEDIUM">Medium</MenuItem>
                <MenuItem value="LOW">Low</MenuItem>
              </Select>
            </FormControl>
            
            <TextField
              size="small"
              label="Vendor"
              value={filters.vendor}
              onChange={(e) => setFilters({ ...filters, vendor: e.target.value })}
              placeholder="Filter vendor..."
              sx={{ minWidth: 200 }}
            />
            
            <Box sx={{ flexGrow: 1 }} />
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                {authToken ? (
                  <>
                    <Typography variant="body2">{analystName} ({userRole})</Typography>
                    <Button size="small" onClick={() => {
                      localStorage.removeItem('ctba_token');
                      localStorage.removeItem('ctba_user');
                      localStorage.removeItem('ctba_role');
                      delete axios.defaults.headers.common['Authorization'];
                      setAuthToken(null); setAnalystName(''); setUserRole(null);
                    }}>Logout</Button>
                  </>
                ) : (
                  <Button size="small" variant="outlined" onClick={() => setLoginDialogOpen(true)}>Login</Button>
                )}
              </Box>

            <Typography variant="body2" color="text.secondary">
              {cves.length} CVEs
            </Typography>
          </Box>
        </CardContent>
      </Card>
      
      {/* CVE Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow sx={{ backgroundColor: '#f8fafc' }}>
              <TableCell><strong>CVE ID</strong></TableCell>
              <TableCell><strong>Severity</strong></TableCell>
              <TableCell><strong>Score</strong></TableCell>
              <TableCell><strong>Affected Products</strong></TableCell>
              <TableCell><strong>Status</strong></TableCell>
              <TableCell><strong>Published</strong></TableCell>
              <TableCell><strong>Actions</strong></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {cves.length > 0 ? cves.map((cve) => (
              <TableRow 
                key={cve.cve_id}
                sx={{
                  '&:hover': { backgroundColor: '#f8fafc' },
                  borderLeft: cve.severity === 'CRITICAL' ? '4px solid #dc2626' : 
                             cve.severity === 'HIGH' ? '4px solid #ea580c' : 'none'
                }}
              >
                <TableCell>
                  <Typography sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>
                    {cve.cve_id}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                    {cve.description?.substring(0, 80)}...
                  </Typography>
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={cve.severity} />
                </TableCell>
                <TableCell>
                  <Typography variant="h6" color={
                    cve.cvss_score >= 9 ? 'error' :
                    cve.cvss_score >= 7 ? 'warning' :
                    'success'
                  }>
                    {cve.cvss_score?.toFixed(1) || 'N/A'}
                  </Typography>
                </TableCell>
                <TableCell>
                  {cve.affected_products && cve.affected_products.length > 0 ? (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {cve.affected_products.slice(0, 2).map((prod, idx) => {
                        const status = prod.tech_status;
                        const bg = status === 'OUT_OF_SCOPE' ? '#fecaca' : status === 'PRIORITY' ? '#fed7aa' : status === 'NORMAL' ? '#bbf7d0' : '#e5e7eb';
                        const color = status === 'OUT_OF_SCOPE' ? '#7f1d1d' : status === 'PRIORITY' ? '#92400e' : status === 'NORMAL' ? '#14532d' : '#374151';
                            return (
                              <Chip
                                key={idx}
                                label={`${prod.vendor}/${prod.product}`}
                                size="small"
                                variant="outlined"
                                onClick={() => {
                                  setTechToAdd({ vendor: prod.vendor, product: prod.product });
                                  setNewTechStatus(prod.tech_status || 'NORMAL');
                                  setNewTechReason('Added from CVE list');
                                  setAddTechDialogOpen(true);
                                }}
                                sx={{ backgroundColor: bg, color: color }}
                              />
                            );
                      })}
                      {cve.affected_products.length > 2 && (
                        <Chip
                          label={`+${cve.affected_products.length - 2}`}
                          size="small"
                        />
                      )}
                    </Box>
                  ) : (
                    <Typography variant="caption" color="text.secondary">
                      No products
                    </Typography>
                  )}
                </TableCell>
                <TableCell>
                  <StatusChip status={cve.status} />
                </TableCell>
                <TableCell>
                  {cve.published_date ? (
                    <>
                      <Typography variant="body2">
                        {format(new Date(cve.published_date), 'dd/MM/yyyy')}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {differenceInDays(new Date(), new Date(cve.published_date))} days ago
                      </Typography>
                    </>
                  ) : 'N/A'}
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Tooltip title="View Details">
                      <IconButton
                        size="small"
                        onClick={() => {
                          setSelectedCve(cve);
                          setDetailDialogOpen(true);
                        }}
                      >
                        <Visibility fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    
                    {cve.status === 'PENDING' && (
                      <>
                        <Tooltip title={userRole === 'VOC_L1' ? 'Accept' : 'Only VOC_L1 can accept/reject'}>
                          <IconButton
                            size="small"
                            color="success"
                            onClick={() => { setSelectedCve(cve); handleAction('ACCEPTED'); }}
                            disabled={userRole !== 'VOC_L1'}
                          >
                            <CheckCircle fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        
                        <Tooltip title={userRole === 'VOC_L1' ? 'Reject' : 'Only VOC_L1 can accept/reject'}>
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => { setSelectedCve(cve); handleAction('REJECTED'); }}
                            disabled={userRole !== 'VOC_L1'}
                          >
                            <Cancel fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </>
                    )}
                  </Box>
                </TableCell>
              </TableRow>
            )) : (
              <TableRow>
                <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                  <Typography variant="h6" color="text.secondary">
                    No CVEs found
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                    {filters.status === 'PENDING' 
                      ? 'No pending CVEs. Try importing some.'
                      : 'No CVEs match your filters.'}
                  </Typography>
                  <Button 
                    variant="contained" 
                    sx={{ mt: 2 }}
                    onClick={triggerImport}
                  >
                    Import CVEs
                  </Button>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      
      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert 
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>

      {/* Login Dialog */}
      <Dialog open={loginDialogOpen} onClose={() => setLoginDialogOpen(false)}>
        <DialogTitle>Login</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 360 }}>
            <TextField label="Username" size="small" value={loginUser} onChange={(e) => setLoginUser(e.target.value)} />
            <TextField label="Password" size="small" type="password" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setLoginDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleLogin}>Login</Button>
        </DialogActions>
      </Dialog>

      <AddTechnologyModal
        open={addTechDialogOpen}
        onClose={() => setAddTechDialogOpen(false)}
        initialVendor={techToAdd.vendor}
        initialProduct={techToAdd.product}
        initialStatus={newTechStatus}
        initialReason={newTechReason}
        addedBy={analystName}
        onAdded={() => { showSnackbar(`Technology ${techToAdd.vendor}/${techToAdd.product} added`, 'success'); setTimeout(() => { fetchCves(); fetchStats(); }, 500); }}
      />

      {/* CVE Detail Dialog with AI Remediation */}
      <Dialog 
        open={detailDialogOpen} 
        onClose={() => setDetailDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
              {selectedCve?.cve_id}
            </Typography>
            <Chip
              label={selectedCve?.severity || 'N/A'}
              color={
                selectedCve?.severity === 'CRITICAL' ? 'error' :
                selectedCve?.severity === 'HIGH' ? 'warning' :
                selectedCve?.severity === 'MEDIUM' ? 'info' : 'success'
              }
            />
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedCve && (
            <Box>
              {/* CVE Details */}
              <Card sx={{ mb: 2 }}>
                <CardContent>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Description
                  </Typography>
                  <Typography variant="body2" paragraph>
                    {selectedCve.description || 'No description available'}
                  </Typography>

                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        CVSS Score
                      </Typography>
                      <Typography variant="body2">
                        {selectedCve.cvss_score || 'N/A'}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Status
                      </Typography>
                      <Chip
                        size="small"
                        label={selectedCve.status}
                        color={
                          selectedCve.status === 'PENDING' ? 'warning' :
                          selectedCve.status === 'ACCEPTED' ? 'success' : 'error'
                        }
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Affected Products
                      </Typography>
                      <Typography variant="body2">
                        {selectedCve.affected_products || 'N/A'}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Published Date
                      </Typography>
                      <Typography variant="body2">
                        {selectedCve.published_date 
                          ? format(new Date(selectedCve.published_date), 'dd/MM/yyyy HH:mm')
                          : 'N/A'}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Source
                      </Typography>
                      <Typography variant="body2">
                        {selectedCve.source || 'N/A'}
                      </Typography>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>

              {/* AI Remediation Panel */}
              <AIRemediationPanel
                cveId={selectedCve.cve_id}
                cveSeverity={selectedCve.severity}
                cveScore={selectedCve.cvss_score}
              />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailDialogOpen(false)}>
            Fermer
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default CVEList;