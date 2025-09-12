const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'xero-mcp-wrapper',
    timestamp: new Date().toISOString()
  });
});

// OAuth initiation
app.get('/', (req, res) => {
  const authUrl = `https://login.xero.com/identity/connect/authorize?` +
    `response_type=code&` +
    `client_id=${process.env.XERO_CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(`https://${req.get('host')}/callback`)}&` +
    `scope=offline_access accounting.transactions accounting.contacts accounting.settings&` +
    `state=railway-test`;
  
  res.redirect(authUrl);
});

// OAuth callback
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code) {
    return res.status(400).json({ error: 'No authorization code received' });
  }

  try {
    // Exchange code for tokens
    const tokenResponse = await axios.post('https://identity.xero.com/connect/token', {
      grant_type: 'authorization_code',
      client_id: process.env.XERO_CLIENT_ID,
      client_secret: process.env.XERO_CLIENT_SECRET,
      code: code,
      redirect_uri: `https://${req.get('host')}/callback`
    }, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const { access_token, refresh_token } = tokenResponse.data;

    // Get connections (tenant info)
    const connectionsResponse = await axios.get('https://api.xero.com/connections', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });

    res.json({
      success: true,
      message: 'OAuth completed successfully!',
      connections: connectionsResponse.data,
      tokens: {
        access_token: access_token.substring(0, 20) + '...',
        refresh_token: refresh_token ? refresh_token.substring(0, 20) + '...' : null
      }
    });

  } catch (error) {
    console.error('OAuth error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'OAuth failed', 
      details: error.response?.data || error.message 
    });
  }
});

// MCP-style endpoints
app.get('/mcp/contacts', async (req, res) => {
  // Implementation for listing contacts
  res.json({ message: 'MCP contacts endpoint - implement with stored tokens' });
});

app.get('/mcp/invoices', async (req, res) => {
  // Implementation for listing invoices
  res.json({ message: 'MCP invoices endpoint - implement with stored tokens' });
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Xero MCP Wrapper running on 0.0.0.0:${port}`);
  console.log(`🔗 Visit: https://your-railway-url.up.railway.app`);
  console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔑 Xero Client ID: ${process.env.XERO_CLIENT_ID ? 'SET' : 'MISSING'}`);
});
