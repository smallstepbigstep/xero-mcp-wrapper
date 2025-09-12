const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// In-memory token storage (use Redis/database in production)
let tokenStore = {};

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Utility functions
const generateState = () => crypto.randomBytes(16).toString('hex');

const getBaseUrl = (req) => {
  const protocol = req.get('x-forwarded-proto') || req.protocol;
  const host = req.get('host');
  return `${protocol}://${host}`;
};

// Validate environment variables
const validateEnv = () => {
  if (!process.env.XERO_CLIENT_ID || !process.env.XERO_CLIENT_SECRET) {
    console.error('❌ Missing required environment variables');
    console.error('Required: XERO_CLIENT_ID, XERO_CLIENT_SECRET');
    process.exit(1);
  }
  console.log('✅ Environment variables validated');
};

// OAuth Discovery Endpoints for ChatGPT Integration
// ================================================

// OAuth Authorization Server Metadata (RFC 8414)
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const baseUrl = getBaseUrl(req);
  
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    scopes_supported: [
      "offline_access",
      "accounting.transactions",
      "accounting.contacts", 
      "accounting.settings",
      "accounting.reports.read"
    ],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    service_documentation: `${baseUrl}/mcp`,
    ui_locales_supported: ["en-US"],
    op_policy_uri: `${baseUrl}/privacy`,
    op_tos_uri: `${baseUrl}/terms`
  });
});

// OpenID Connect Discovery (optional but helpful)
app.get('/.well-known/openid_configuration', (req, res) => {
  const baseUrl = getBaseUrl(req);
  
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    scopes_supported: ["openid", "profile", "email"],
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    claims_supported: ["sub", "name", "email", "preferred_username"]
  });
});

// JWKS endpoint (minimal implementation)
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({
    keys: []
  });
});

// OAuth Endpoints for ChatGPT
// ============================

// OAuth Authorization endpoint (redirects to Xero)
app.get('/oauth/authorize', (req, res) => {
  const baseUrl = getBaseUrl(req);
  const state = generateState();
  
  // Store the original OAuth parameters for later use
  const { client_id, redirect_uri, scope, response_type, state: original_state } = req.query;
  
  // Store state and original parameters for validation
  tokenStore[state] = { 
    created: Date.now(),
    original_params: {
      client_id,
      redirect_uri,
      scope,
      response_type,
      original_state
    }
  };
  
  // Build Xero OAuth URL
  const xeroAuthUrl = `https://login.xero.com/identity/connect/authorize?` +
    `response_type=code&` +
    `client_id=${process.env.XERO_CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(`${baseUrl}/oauth/callback`)}&` +
    `scope=offline_access accounting.transactions accounting.contacts accounting.settings accounting.reports.read&` +
    `state=${state}`;
  
  console.log(`🔗 OAuth authorization initiated for ChatGPT integration`);
  res.redirect(xeroAuthUrl);
});

// OAuth Token endpoint
app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;
  
  try {
    if (grant_type === 'authorization_code') {
      // Handle authorization code flow
      const baseUrl = getBaseUrl(req);
      
      console.log('🔄 Processing OAuth token request...');
      
      // Exchange code with Xero
      const tokenResponse = await axios.post('https://identity.xero.com/connect/token', 
        new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: process.env.XERO_CLIENT_ID,
          client_secret: process.env.XERO_CLIENT_SECRET,
          code: code,
          redirect_uri: `${baseUrl}/oauth/callback`
        }), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      const { access_token, refresh_token: xero_refresh_token, expires_in } = tokenResponse.data;
      
      // Get tenant connections
      const connectionsResponse = await axios.get('https://api.xero.com/connections', {
        headers: {
          'Authorization': `Bearer ${access_token}`
        }
      });

      const connections = connectionsResponse.data;
      
      // Store session
      const sessionId = crypto.randomBytes(16).toString('hex');
      tokenStore[sessionId] = {
        access_token,
        refresh_token: xero_refresh_token,
        expires_at: Date.now() + (expires_in * 1000),
        connections,
        created: Date.now()
      };

      console.log('✅ OAuth token exchange successful');
      
      // Return OAuth-compliant response
      res.json({
        access_token: sessionId, // Use session ID as access token for our API
        token_type: 'Bearer',
        expires_in: expires_in,
        refresh_token: sessionId, // Same session ID for refresh
        scope: 'accounting.transactions accounting.contacts accounting.settings accounting.reports.read'
      });
      
    } else if (grant_type === 'refresh_token') {
      // Handle refresh token flow
      const session = tokenStore[refresh_token];
      
      if (!session || !session.refresh_token) {
        return res.status(400).json({ error: 'invalid_grant' });
      }
      
      // Refresh Xero token
      const refreshResponse = await axios.post('https://identity.xero.com/connect/token',
        new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: process.env.XERO_CLIENT_ID,
          client_secret: process.env.XERO_CLIENT_SECRET,
          refresh_token: session.refresh_token
        }), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      const { access_token, refresh_token: new_refresh_token, expires_in } = refreshResponse.data;
      
      // Update session
      session.access_token = access_token;
      session.refresh_token = new_refresh_token || session.refresh_token;
      session.expires_at = Date.now() + (expires_in * 1000);
      
      console.log('✅ Token refreshed successfully');
      
      res.json({
        access_token: refresh_token, // Keep same session ID
        token_type: 'Bearer',
        expires_in: expires_in,
        refresh_token: refresh_token,
        scope: 'accounting.transactions accounting.contacts accounting.settings accounting.reports.read'
      });
      
    } else {
      res.status(400).json({ error: 'unsupported_grant_type' });
    }
    
  } catch (error) {
    console.error('❌ OAuth token error:', error.response?.data || error.message);
    res.status(400).json({ 
      error: 'invalid_grant',
      error_description: error.response?.data?.error_description || error.message
    });
  }
});

// OAuth Callback (handles Xero redirect)
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  if (error) {
    console.error('❌ OAuth error:', error);
    return res.status(400).json({ 
      error: 'OAuth authorization failed', 
      details: error 
    });
  }

  if (!code || !state || !tokenStore[state]) {
    return res.status(400).json({ 
      error: 'Invalid OAuth callback parameters' 
    });
  }

  const stateData = tokenStore[state];
  const { original_params } = stateData;
  
  // Clean up state
  delete tokenStore[state];
  
  // Redirect back to ChatGPT with authorization code
  if (original_params && original_params.redirect_uri) {
    const redirectUrl = `${original_params.redirect_uri}?code=${code}&state=${original_params.original_state}`;
    res.redirect(redirectUrl);
  } else {
    // Fallback: show success message
    res.json({
      success: true,
      message: 'OAuth authorization completed',
      code: code
    });
  }
});

// OAuth User Info endpoint
app.get('/oauth/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  const sessionId = authHeader.substring(7);
  const session = tokenStore[sessionId];
  
  if (!session) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  try {
    // Get user info from Xero
    const userResponse = await axios.get('https://api.xero.com/api.xro/2.0/Organisation', {
      headers: {
        'Authorization': `Bearer ${session.access_token}`,
        'Xero-tenant-id': session.connections[0]?.tenantId,
        'Accept': 'application/json'
      }
    });
    
    const org = userResponse.data.Organisations?.[0];
    
    res.json({
      sub: session.connections[0]?.tenantId || 'unknown',
      name: org?.Name || 'Xero User',
      email: org?.DefaultPurchasesTax || '',
      preferred_username: org?.Name || 'xero_user',
      organization: org?.Name || 'Unknown Organization'
    });
    
  } catch (error) {
    console.error('❌ UserInfo error:', error.response?.data || error.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'xero-mcp-wrapper',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    environment: process.env.NODE_ENV || 'development',
    chatgpt_ready: true
  });
});

// Root endpoint - start OAuth flow (legacy support)
app.get('/', (req, res) => {
  const baseUrl = getBaseUrl(req);
  const state = generateState();
  
  // Store state for validation (in production, use proper session management)
  tokenStore[state] = { created: Date.now() };
  
  const authUrl = `https://login.xero.com/identity/connect/authorize?` +
    `response_type=code&` +
    `client_id=${process.env.XERO_CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(`${baseUrl}/callback`)}&` +
    `scope=offline_access accounting.transactions accounting.contacts accounting.settings accounting.reports.read&` +
    `state=${state}`;
  
  console.log(`🔗 Legacy OAuth initiated for ${baseUrl}`);
  res.redirect(authUrl);
});

// Legacy OAuth callback endpoint
app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  const baseUrl = getBaseUrl(req);
  
  if (error) {
    console.error('❌ OAuth error:', error);
    return res.status(400).json({ 
      error: 'OAuth authorization failed', 
      details: error 
    });
  }

  if (!code) {
    return res.status(400).json({ 
      error: 'No authorization code received' 
    });
  }

  if (!state || !tokenStore[state]) {
    return res.status(400).json({ 
      error: 'Invalid or missing state parameter' 
    });
  }

  try {
    console.log('🔄 Exchanging code for tokens...');
    
    // Exchange authorization code for tokens
    const tokenResponse = await axios.post('https://identity.xero.com/connect/token', 
      new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: process.env.XERO_CLIENT_ID,
        client_secret: process.env.XERO_CLIENT_SECRET,
        code: code,
        redirect_uri: `${baseUrl}/callback`
      }), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    console.log('✅ Tokens received successfully');

    // Get tenant connections
    console.log('🔄 Fetching tenant connections...');
    const connectionsResponse = await axios.get('https://api.xero.com/connections', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });

    const connections = connectionsResponse.data;
    console.log(`✅ Found ${connections.length} connection(s)`);

    // Store tokens (in production, use secure storage)
    const sessionId = crypto.randomBytes(16).toString('hex');
    tokenStore[sessionId] = {
      access_token,
      refresh_token,
      expires_at: Date.now() + (expires_in * 1000),
      connections,
      created: Date.now()
    };

    // Clean up state
    delete tokenStore[state];

    // Return success page with connection info
    res.json({
      success: true,
      message: 'Xero OAuth completed successfully!',
      session_id: sessionId,
      connections: connections.map(conn => ({
        id: conn.id,
        tenantId: conn.tenantId,
        tenantName: conn.tenantName,
        tenantType: conn.tenantType,
        createdDateUtc: conn.createdDateUtc
      })),
      endpoints: {
        contacts: `${baseUrl}/api/contacts?session=${sessionId}`,
        invoices: `${baseUrl}/api/invoices?session=${sessionId}`,
        accounts: `${baseUrl}/api/accounts?session=${sessionId}`,
        reports: `${baseUrl}/api/reports?session=${sessionId}`
      }
    });

  } catch (error) {
    console.error('❌ OAuth callback error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'OAuth token exchange failed', 
      details: error.response?.data || error.message 
    });
  }
});

// Middleware to validate session and get tokens
const validateSession = async (req, res, next) => {
  let sessionId = req.query.session || req.headers['x-session-id'];
  
  // For OAuth Bearer tokens, extract session ID
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    sessionId = authHeader.substring(7);
  }
  
  if (!sessionId || !tokenStore[sessionId]) {
    return res.status(401).json({ 
      error: 'Invalid or missing session. Please authenticate first.',
      auth_url: `${getBaseUrl(req)}/oauth/authorize`
    });
  }

  const session = tokenStore[sessionId];
  
  // Check if token is expired
  if (Date.now() >= session.expires_at) {
    if (session.refresh_token) {
      try {
        console.log('🔄 Refreshing expired token...');
        
        const refreshResponse = await axios.post('https://identity.xero.com/connect/token',
          new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: process.env.XERO_CLIENT_ID,
            client_secret: process.env.XERO_CLIENT_SECRET,
            refresh_token: session.refresh_token
          }), {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            }
          }
        );

        const { access_token, refresh_token, expires_in } = refreshResponse.data;
        
        // Update stored tokens
        session.access_token = access_token;
        session.refresh_token = refresh_token || session.refresh_token;
        session.expires_at = Date.now() + (expires_in * 1000);
        
        console.log('✅ Token refreshed successfully');
        
      } catch (error) {
        console.error('❌ Token refresh failed:', error.response?.data || error.message);
        delete tokenStore[sessionId];
        return res.status(401).json({ 
          error: 'Token refresh failed. Please re-authenticate.',
          auth_url: `${getBaseUrl(req)}/oauth/authorize`
        });
      }
    } else {
      delete tokenStore[sessionId];
      return res.status(401).json({ 
        error: 'Token expired and no refresh token available. Please re-authenticate.',
        auth_url: `${getBaseUrl(req)}/oauth/authorize`
      });
    }
  }

  req.session = session;
  next();
};

// API Endpoints (ChatGPT-compatible)
// ==================================

// List contacts
app.get('/api/contacts', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    console.log(`🔄 Fetching contacts for tenant: ${tenantId}`);
    
    const response = await axios.get('https://api.xero.com/api.xro/2.0/Contacts', {
      headers: {
        'Authorization': `Bearer ${access_token}`,
        'Xero-tenant-id': tenantId,
        'Accept': 'application/json'
      }
    });

    console.log(`✅ Retrieved ${response.data.Contacts?.length || 0} contacts`);
    
    res.json({
      success: true,
      tenant_id: tenantId,
      count: response.data.Contacts?.length || 0,
      contacts: response.data.Contacts || []
    });

  } catch (error) {
    console.error('❌ Contacts API error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to fetch contacts', 
      details: error.response?.data || error.message 
    });
  }
});

// List invoices
app.get('/api/invoices', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    console.log(`🔄 Fetching invoices for tenant: ${tenantId}`);
    
    const response = await axios.get('https://api.xero.com/api.xro/2.0/Invoices', {
      headers: {
        'Authorization': `Bearer ${access_token}`,
        'Xero-tenant-id': tenantId,
        'Accept': 'application/json'
      }
    });

    console.log(`✅ Retrieved ${response.data.Invoices?.length || 0} invoices`);
    
    res.json({
      success: true,
      tenant_id: tenantId,
      count: response.data.Invoices?.length || 0,
      invoices: response.data.Invoices || []
    });

  } catch (error) {
    console.error('❌ Invoices API error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to fetch invoices', 
      details: error.response?.data || error.message 
    });
  }
});

// List accounts
app.get('/api/accounts', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    console.log(`🔄 Fetching accounts for tenant: ${tenantId}`);
    
    const response = await axios.get('https://api.xero.com/api.xro/2.0/Accounts', {
      headers: {
        'Authorization': `Bearer ${access_token}`,
        'Xero-tenant-id': tenantId,
        'Accept': 'application/json'
      }
    });

    console.log(`✅ Retrieved ${response.data.Accounts?.length || 0} accounts`);
    
    res.json({
      success: true,
      tenant_id: tenantId,
      count: response.data.Accounts?.length || 0,
      accounts: response.data.Accounts || []
    });

  } catch (error) {
    console.error('❌ Accounts API error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to fetch accounts', 
      details: error.response?.data || error.message 
    });
  }
});

// Create invoice
app.post('/api/invoices', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    const invoiceData = req.body;
    
    console.log(`🔄 Creating invoice for tenant: ${tenantId}`);
    
    const response = await axios.post('https://api.xero.com/api.xro/2.0/Invoices', 
      { Invoices: [invoiceData] }, 
      {
        headers: {
          'Authorization': `Bearer ${access_token}`,
          'Xero-tenant-id': tenantId,
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      }
    );

    console.log(`✅ Invoice created successfully`);
    
    res.json({
      success: true,
      tenant_id: tenantId,
      invoice: response.data.Invoices?.[0] || response.data
    });

  } catch (error) {
    console.error('❌ Create invoice error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to create invoice', 
      details: error.response?.data || error.message 
    });
  }
});

// Get reports
app.get('/api/reports/:reportType', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    const { reportType } = req.params;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    console.log(`🔄 Fetching ${reportType} report for tenant: ${tenantId}`);
    
    const response = await axios.get(`https://api.xero.com/api.xro/2.0/Reports/${reportType}`, {
      headers: {
        'Authorization': `Bearer ${access_token}`,
        'Xero-tenant-id': tenantId,
        'Accept': 'application/json'
      },
      params: req.query
    });

    console.log(`✅ Retrieved ${reportType} report`);
    
    res.json({
      success: true,
      tenant_id: tenantId,
      report_type: reportType,
      report: response.data
    });

  } catch (error) {
    console.error(`❌ ${reportType} report error:`, error.response?.data || error.message);
    res.status(500).json({ 
      error: `Failed to fetch ${reportType} report`, 
      details: error.response?.data || error.message 
    });
  }
});

// Legacy MCP endpoints (for backward compatibility)
app.get('/mcp/contacts', validateSession, async (req, res) => {
  req.url = '/api/contacts';
  return app._router.handle(req, res);
});

app.get('/mcp/invoices', validateSession, async (req, res) => {
  req.url = '/api/invoices';
  return app._router.handle(req, res);
});

app.get('/mcp/accounts', validateSession, async (req, res) => {
  req.url = '/api/accounts';
  return app._router.handle(req, res);
});

app.post('/mcp/invoices', validateSession, async (req, res) => {
  req.url = '/api/invoices';
  return app._router.handle(req, res);
});

app.get('/mcp/reports/:reportType', validateSession, async (req, res) => {
  req.url = `/api/reports/${req.params.reportType}`;
  return app._router.handle(req, res);
});

// API Documentation
app.get('/api', (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    service: 'Xero API Wrapper',
    version: '2.0.0',
    chatgpt_compatible: true,
    oauth: {
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
      discovery: `${baseUrl}/.well-known/oauth-authorization-server`
    },
    endpoints: {
      'GET /api/contacts': 'List all contacts',
      'GET /api/invoices': 'List all invoices',
      'GET /api/accounts': 'List all accounts',
      'POST /api/invoices': 'Create a new invoice',
      'GET /api/reports/:reportType': 'Get financial reports (ProfitAndLoss, BalanceSheet, etc.)'
    },
    authentication: {
      type: 'OAuth 2.0',
      flow: 'authorization_code',
      scopes: [
        'offline_access',
        'accounting.transactions',
        'accounting.contacts',
        'accounting.settings',
        'accounting.reports.read'
      ]
    },
    example_usage: {
      oauth_flow: `${baseUrl}/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT&response_type=code&scope=accounting.contacts`,
      list_contacts: `${baseUrl}/api/contacts`,
      list_invoices: `${baseUrl}/api/invoices`,
      profit_loss: `${baseUrl}/api/reports/ProfitAndLoss`
    }
  });
});

// Legacy MCP documentation
app.get('/mcp', (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    service: 'Xero MCP Wrapper (Legacy)',
    version: '2.0.0',
    note: 'This is the legacy MCP interface. Use /api endpoints for ChatGPT integration.',
    authentication: {
      oauth_url: `${baseUrl}/`,
      description: 'Visit the OAuth URL to authenticate with Xero'
    },
    endpoints: {
      'GET /mcp/contacts': 'List all contacts',
      'GET /mcp/invoices': 'List all invoices',
      'GET /mcp/accounts': 'List all accounts',
      'POST /mcp/invoices': 'Create a new invoice',
      'GET /mcp/reports/:reportType': 'Get financial reports (ProfitAndLoss, BalanceSheet, etc.)'
    },
    parameters: {
      session: 'Required: Session ID from OAuth callback',
      tenant: 'Optional: Specific tenant ID (defaults to first connection)'
    },
    example_usage: {
      authenticate: `${baseUrl}/`,
      list_contacts: `${baseUrl}/mcp/contacts?session=YOUR_SESSION_ID`,
      list_invoices: `${baseUrl}/mcp/invoices?session=YOUR_SESSION_ID`,
      profit_loss: `${baseUrl}/mcp/reports/ProfitAndLoss?session=YOUR_SESSION_ID`
    }
  });
});

// Privacy Policy (required for OAuth)
app.get('/privacy', (req, res) => {
  res.json({
    service: 'Xero API Wrapper',
    privacy_policy: 'This service acts as a proxy to Xero APIs. No user data is stored permanently. Session tokens are kept in memory only during active sessions.',
    data_handling: 'All data requests are forwarded directly to Xero APIs. This service does not store, log, or process any financial data.',
    contact: 'For privacy concerns, please contact your system administrator.'
  });
});

// Terms of Service (required for OAuth)
app.get('/terms', (req, res) => {
  res.json({
    service: 'Xero API Wrapper',
    terms: 'This service is provided as-is for authorized users only. Use is subject to Xero\'s terms of service.',
    limitations: 'This service is a development tool and should not be used for production financial operations without proper security review.',
    contact: 'For terms questions, please contact your system administrator.'
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res.status(500).json({ 
    error: 'Internal server error', 
    message: error.message 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    available_endpoints: [
      'GET /.well-known/oauth-authorization-server',
      'GET /oauth/authorize',
      'POST /oauth/token',
      'GET /oauth/userinfo',
      'GET /health',
      'GET /api',
      'GET /api/contacts',
      'GET /api/invoices',
      'GET /api/accounts',
      'POST /api/invoices',
      'GET /api/reports/:reportType'
    ]
  });
});

// Cleanup old sessions (run every hour)
setInterval(() => {
  const now = Date.now();
  const oneHour = 60 * 60 * 1000;
  
  Object.keys(tokenStore).forEach(key => {
    const session = tokenStore[key];
    if (session.created && (now - session.created) > oneHour) {
      delete tokenStore[key];
    }
  });
}, 60 * 60 * 1000);

// Start server
const startServer = () => {
  validateEnv();
  
  app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Xero API Wrapper running on 0.0.0.0:${port}`);
    console.log(`🔗 OAuth URL: http://localhost:${port}/oauth/authorize`);
    console.log(`🏥 Health check: http://localhost:${port}/health`);
    console.log(`📚 API docs: http://localhost:${port}/api`);
    console.log(`🔍 OAuth Discovery: http://localhost:${port}/.well-known/oauth-authorization-server`);
    console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔑 Xero Client ID: ${process.env.XERO_CLIENT_ID ? 'SET' : 'MISSING'}`);
    console.log(`🔐 Xero Client Secret: ${process.env.XERO_CLIENT_SECRET ? 'SET' : 'MISSING'}`);
    console.log(`🤖 ChatGPT Ready: YES`);
  });
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('📴 Received SIGTERM, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('📴 Received SIGINT, shutting down gracefully');
  process.exit(0);
});

startServer();
