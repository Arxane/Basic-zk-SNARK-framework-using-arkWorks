import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  TextField,
  Button,
  Alert,
  CircularProgress,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';

const CreateTransaction = () => {
  const navigate = useNavigate();
  const [amount, setAmount] = useState('');
  const [recipient, setRecipient] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // TODO: Implement actual transaction creation with zk-SNARKs
      const response = await fetch('http://localhost:3000/api/transactions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          amount: parseFloat(amount),
          recipient,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to create transaction');
      }

      navigate('/transactions');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Create New Transaction
      </Typography>
      <Paper sx={{ p: 3 }}>
        <form onSubmit={handleSubmit}>
          <TextField
            fullWidth
            label="Amount"
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            margin="normal"
            required
            inputProps={{ step: '0.01', min: '0' }}
          />
          <TextField
            fullWidth
            label="Recipient Address"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            margin="normal"
            required
          />
          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
            </Alert>
          )}
          <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
            <Button
              variant="contained"
              type="submit"
              disabled={loading}
              startIcon={loading ? <CircularProgress size={20} /> : null}
            >
              Create Transaction
            </Button>
            <Button
              variant="outlined"
              onClick={() => navigate('/')}
              disabled={loading}
            >
              Cancel
            </Button>
          </Box>
        </form>
      </Paper>
    </Box>
  );
};

export default CreateTransaction; 