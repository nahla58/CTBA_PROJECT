import React, { useState, useEffect } from 'react';
import { Dialog, DialogTitle, DialogContent, DialogActions, TextField, Button, Box, FormControl, InputLabel, Select, MenuItem } from '@mui/material';
import axios from 'axios';

const API_URL = 'http://localhost:8000';

export default function AddTechnologyModal({ open, onClose, initialVendor = '', initialProduct = '', initialStatus = 'NORMAL', initialReason = '', addedBy = 'analyst', onAdded = () => {} }) {
  const [vendor, setVendor] = useState(initialVendor);
  const [product, setProduct] = useState(initialProduct);
  const [status, setStatus] = useState(initialStatus);
  const [reason, setReason] = useState(initialReason);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    setVendor(initialVendor);
    setProduct(initialProduct);
    setStatus(initialStatus);
    setReason(initialReason);
  }, [initialVendor, initialProduct, initialStatus, initialReason, open]);

  const handleAdd = async () => {
    if (!vendor || !product) return;
    setSubmitting(true);
    try {
      await axios.post(`${API_URL}/technologies`, {
        vendor: vendor.trim(),
        product: product.trim(),
        status,
        reason
      });
      onAdded({ vendor: vendor.trim(), product: product.trim(), status });
      onClose();
    } catch (err) {
      console.error('Error adding technology', err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Add Technology</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 360 }}>
          <TextField label="Vendor" size="small" value={vendor} onChange={(e) => setVendor(e.target.value)} />
          <TextField label="Product" size="small" value={product} onChange={(e) => setProduct(e.target.value)} />
          <FormControl size="small">
            <InputLabel>Status</InputLabel>
            <Select value={status} label="Status" onChange={(e) => setStatus(e.target.value)}>
              <MenuItem value="NORMAL">NORMAL</MenuItem>
              <MenuItem value="PRIORITY">PRIORITY</MenuItem>
              <MenuItem value="OUT_OF_SCOPE">OUT_OF_SCOPE</MenuItem>
            </Select>
          </FormControl>
          <TextField label="Reason" size="small" value={reason} onChange={(e) => setReason(e.target.value)} />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={submitting}>Cancel</Button>
        <Button variant="contained" onClick={handleAdd} disabled={submitting}>Add</Button>
      </DialogActions>
    </Dialog>
  );
}
