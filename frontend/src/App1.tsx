import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Container from '@mui/material/Container';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { Link as RouterLink } from 'react-router-dom';

// Pages
import Dashboard from './pages/Dashboard';
import CreateTransaction from './pages/CreateTransaction';
import TransactionList from './pages/TransactionList';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#90caf9',
    },
    secondary: {
      main: '#f48fb1',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Box sx={{ flexGrow: 1 }}>
          <AppBar position="static">
            <Toolbar>
              <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                ZK Payment System
              </Typography>
              <Button color="inherit" component={RouterLink} to="/">
                Dashboard
              </Button>
              <Button color="inherit" component={RouterLink} to="/create">
                New Transaction
              </Button>
              <Button color="inherit" component={RouterLink} to="/transactions">
                Transactions
              </Button>
            </Toolbar>
          </AppBar>
          <Container maxWidth="lg" sx={{ mt: 4 }}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/create" element={<CreateTransaction />} />
              <Route path="/transactions" element={<TransactionList />} />
            </Routes>
          </Container>
        </Box>
      </Router>
    </ThemeProvider>
  );
}

export default App; 