import React from 'react';
import { Box, Typography, Paper, Grid } from '@mui/material';
import { useNavigate } from 'react-router-dom';

const Dashboard = () => {
  const navigate = useNavigate();

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper
            sx={{
              p: 3,
              cursor: 'pointer',
              '&:hover': {
                backgroundColor: 'action.hover',
              },
            }}
            onClick={() => navigate('/create')}
          >
            <Typography variant="h6" gutterBottom>
              Create New Transaction
            </Typography>
            <Typography color="text.secondary">
              Create a new private transaction using zk-SNARKs
            </Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper
            sx={{
              p: 3,
              cursor: 'pointer',
              '&:hover': {
                backgroundColor: 'action.hover',
              },
            }}
            onClick={() => navigate('/transactions')}
          >
            <Typography variant="h6" gutterBottom>
              View Transactions
            </Typography>
            <Typography color="text.secondary">
              View your transaction history and status
            </Typography>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard; 