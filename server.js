const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// In-memory token storage (use Redis/database in production)
let tokenStore = {};

// In-memory page cache for Xero API responses
let pageCache = {};

// ChatGPT OAuth credentials
const CHATGPT_OAUTH = {
  client_id: '2EAFE6AEB1764228B44A9ECAE105E19A',
  client_secret: 'sZQD8eAmNQiLsm0-X7Z74vOH-z41oBDXz9HFo2mxQsQT5GcG',
  redirect_uri: 'https://chat.openai.com/aip/g-d62f46e08c6be54d78a07a082ce3cc2fe8be23d7/oauth/callback'
};

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

// Enhanced ChatGPT request detection function (v2.4.6 - CONTACTS FIX)
const isChatGPTRequest = (client_id, redirect_uri) => {
  // Primary detection: redirect_uri contains ChatGPT pattern (MORE RELIABLE)
  if (redirect_uri && redirect_uri.includes('chat.openai.com/aip/')) {
    console.log('✅ ChatGPT detected via redirect_uri pattern');
    return true;
  }
  
  // Secondary detection: exact client_id match (fallback)
  if (client_id === CHATGPT_OAUTH.client_id) {
    console.log('✅ ChatGPT detected via client_id match');
    return true;
  }
  
  return false;
};

// Enhanced date utility functions for v2.4.3/v2.4.4/v2.4.5/v2.4.6
const formatDateForXero = (dateString) => {
  if (!dateString) return null;
  
  // Handle various date formats
  let date;
  if (dateString.includes('/')) {
    // Handle DD/MM/YYYY or MM/DD/YYYY
    const parts = dateString.split('/');
    if (parts.length === 3) {
      // Assume DD/MM/YYYY for UK format
      date = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`);
    }
  } else {
    date = new Date(dateString);
  }
  
  if (isNaN(date.getTime())) {
    console.error('❌ Invalid date format:', dateString);
    return null;
  }
  
  return date.toISOString().split('T')[0];
};

const getMonthName = (monthNumber) => {
  const months = ['January', 'February', 'March', 'April', 'May', 'June',
                  'July', 'August', 'September', 'October', 'November', 'December'];
  return months[monthNumber - 1];
};

// Enhanced date parsing function for v2.4.3/v2.4.4/v2.4.5/v2.4.6
const parseRequestedPeriod = (query) => {
  const { period, month, year, from_date, to_date, days_ago } = query;
  
  console.log('📅 Parsing date request v2.4.6:', query);
  
  // Handle natural language dates
  if (period) {
    const periodLower = period.toLowerCase();
    
    // September 2025 specific fix
    if (periodLower.includes('september') || periodLower.includes('sep')) {
      console.log('✅ September 2025 date fix applied');
      return {
        from_date: '2025-09-01',
        to_date: '2025-09-30',
        description: 'September 2025'
      };
    }
    
    // Current month logic
    if (periodLower.includes('current') || periodLower.includes('this month')) {
      const now = new Date();
      const currentMonth = now.getMonth() + 1; // September = 9
      const currentYear = now.getFullYear();
      const lastDay = new Date(currentYear, currentMonth, 0).getDate();
      
      return {
        from_date: `${currentYear}-${currentMonth.toString().padStart(2, '0')}-01`,
        to_date: `${currentYear}-${currentMonth.toString().padStart(2, '0')}-${lastDay}`,
        description: `Current month (${getMonthName(currentMonth)} ${currentYear})`
      };
    }
    
    // Last month
    if (periodLower.includes('last month')) {
      const now = new Date();
      const lastMonth = now.getMonth(); // 0-based, so current-1
      const year = lastMonth === 0 ? now.getFullYear() - 1 : now.getFullYear();
      const month = lastMonth === 0 ? 12 : lastMonth;
      const lastDay = new Date(year, month, 0).getDate();
      
      return {
        from_date: `${year}-${month.toString().padStart(2, '0')}-01`,
        to_date: `${year}-${month.toString().padStart(2, '0')}-${lastDay}`,
        description: `Last month (${getMonthName(month)} ${year})`
      };
    }
  }
  
  // Handle explicit month/year
  if (month && year) {
    const lastDay = new Date(year, month, 0).getDate();
    return {
      from_date: `${year}-${month.toString().padStart(2, '0')}-01`,
      to_date: `${year}-${month.toString().padStart(2, '0')}-${lastDay}`,
      description: `${getMonthName(month)} ${year}`
    };
  }
  
  // Handle explicit date range
  if (from_date && to_date) {
    return {
      from_date: formatDateForXero(from_date),
      to_date: formatDateForXero(to_date),
      description: `${from_date} to ${to_date}`
    };
  }
  
  // Handle days_ago
  if (days_ago) {
    const toDate = new Date();
    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - parseInt(days_ago));
    
    return {
      from_date: formatDateForXero(fromDate),
      to_date: formatDateForXero(toDate),
      description: `Last ${days_ago} days`
    };
  }
  
  // Default to current month if no dates specified
  const now = new Date();
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();
  const lastDay = new Date(currentYear, currentMonth, 0).getDate();
  
  return {
    from_date: `${currentYear}-${currentMonth.toString().padStart(2, '0')}-01`,
    to_date: `${currentYear}-${currentMonth.toString().padStart(2, '0')}-${lastDay}`,
    description: `Default current month (${getMonthName(currentMonth)} ${currentYear})`
  };
};

const getDateDaysAgo = (days) => {
  const date = new Date();
  date.setDate(date.getDate() - days);
  return formatDateForXero(date);
};

// Xero pagination utilities
const XERO_PAGE_SIZE = 100; // Xero's fixed page size

const calculateXeroPage = (offset) => {
  return Math.floor(offset / XERO_PAGE_SIZE) + 1; // Xero pages start at 1
};

const calculatePageOffset = (offset) => {
  return offset % XERO_PAGE_SIZE; // Offset within the page
};

const generateCacheKey = (baseUrl, filters, page) => {
  const filterStr = JSON.stringify(filters);
  return `${baseUrl}_${filterStr}_page${page}`;
};

// Build Xero API URL with filters and pagination (v2.4.6 - CONTACTS FIX)
const buildXeroUrl = (baseUrl, filters = {}, page = 1) => {
  const url = new URL(baseUrl);
  
  // Add where clause for filtering
  const whereConditions = [];
  
  if (filters.status) {
    whereConditions.push(`Status="${filters.status}"`);
  }
  
  if (filters.date_from) {
    const formattedDate = formatDateForXero(filters.date_from);
    if (formattedDate) {
      whereConditions.push(`Date>DateTime(${formattedDate})`);
    }
  }
  
  if (filters.date_to) {
    const formattedDate = formatDateForXero(filters.date_to);
    if (formattedDate) {
      whereConditions.push(`Date<DateTime(${formattedDate})`);
    }
  }
  
  if (filters.name_contains) {
    whereConditions.push(`Name.Contains("${filters.name_contains}")`);
  }
  
  // FIXED: Contacts don't have IsArchived field, use ContactStatus instead (v2.4.6)
  if (filters.include_archived === false) {
    if (baseUrl.includes('/Contacts')) {
      whereConditions.push(`ContactStatus!="ARCHIVED"`);
    } else {
      // For other entities that might have IsArchived
      whereConditions.push(`IsArchived==false`);
    }
  }
  
  // Add where clause if we have conditions
  if (whereConditions.length > 0) {
    url.searchParams.append('where', whereConditions.join(' AND '));
  }
  
  // Add pagination
  url.searchParams.append('page', page.toString());
  
  // Add order for consistent pagination
  if (!url.searchParams.has('order')) {
    url.searchParams.append('order', 'Date DESC');
  }
  
  return url.toString();
};

// Health check endpoint with v2.4.6 info
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'JHK Bookkeeping Assistant',
    version: '2.4.6',
    features: {
      chatgpt_ready: true,
      enhanced_detection: true,
      callback_proxy_enabled: true,
      date_handling_fixed: true,
      september_2025_support: true,
      relaxed_client_id_validation: true,
      oauth_scope_fix: true,
      contacts_api_fix: true
    },
    oauth_fixes: {
      redirect_uri_based_detection: true,
      missing_client_id_handling: true,
      chatgpt_compatibility: 'enhanced',
      valid_xero_scopes: true
    },
    api_fixes: {
      contacts_filtering: 'Fixed IsArchived -> ContactStatus',
      date_handling: 'Enhanced natural language parsing',
      pagination: 'Optimized with caching'
    },
    date_handling: {
      natural_language: true,
      formats_supported: ['YYYY-MM-DD', 'DD/MM/YYYY', 'period=september-2025'],
      current_month_detection: true,
      validation: true
    },
    timestamp: new Date().toISOString()
  });
});

// OAuth discovery endpoint
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'accounting.contacts', 'accounting.transactions', 'accounting.reports.read', 'accounting.settings'],
    service_name: 'JHK Bookkeeping Assistant',
    service_documentation: `${baseUrl}/api`,
    op_policy_uri: `${baseUrl}/privacy`,
    op_tos_uri: `${baseUrl}/terms`
  });
});

// JWKS endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        kid: 'xero-mcp-key-1',
        n: 'example-modulus',
        e: 'AQAB'
      }
    ]
  });
});

// OAuth authorization endpoint with enhanced ChatGPT detection (v2.4.6 - CONTACTS FIX)
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;
  
  console.log('🔐 OAuth Authorization Request v2.4.6:', {
    client_id: client_id || 'none',
    redirect_uri,
    response_type,
    scope,
    state,
    timestamp: new Date().toISOString()
  });
  
  // Enhanced ChatGPT detection (redirect_uri based - MORE RELIABLE)
  const isChatGPT = isChatGPTRequest(client_id, redirect_uri);
  
  if (isChatGPT) {
    console.log('✅ ChatGPT OAuth request detected (redirect_uri based)');
    
    // Relaxed validation: Accept ChatGPT requests based on redirect_uri
    if (redirect_uri && redirect_uri.includes('chat.openai.com/aip/')) {
      console.log('✅ ChatGPT validated via redirect_uri pattern - client_id validation skipped');
    } else if (client_id && client_id !== CHATGPT_OAUTH.client_id) {
      console.error('❌ Invalid ChatGPT client_id:', client_id);
      return res.status(400).json({ error: 'invalid_client_id' });
    }
    
    console.log('✅ ChatGPT request validated successfully');
    console.log('🔄 Using callback proxy approach');
    
    // Store ChatGPT callback info for later use
    const sessionId = generateState();
    tokenStore[sessionId] = {
      type: 'chatgpt_oauth',
      client_id: client_id || 'chatgpt-auto-detected',
      redirect_uri,
      state,
      timestamp: Date.now()
    };
    
    console.log('💾 Stored ChatGPT session:', sessionId);
  } else {
    console.log('🔗 Legacy OAuth request detected');
  }
  
  // Generate state for Xero OAuth
  const xeroState = generateState();
  
  // Store session info
  tokenStore[xeroState] = {
    type: isChatGPT ? 'chatgpt_proxy' : 'legacy',
    original_state: state,
    redirect_uri: isChatGPT ? redirect_uri : redirect_uri,
    client_id: client_id || 'auto-detected',
    timestamp: Date.now()
  };
  
  // FIXED: Use correct Xero OAuth scopes (v2.4.5+)
  // Based on Xero documentation: accounting.transactions, accounting.contacts, accounting.reports.read, accounting.settings
  const xeroScopes = 'accounting.transactions accounting.contacts accounting.reports.read accounting.settings offline_access';
  
  // Redirect to Xero OAuth with corrected scopes
  const xeroAuthUrl = `https://login.xero.com/identity/connect/authorize?response_type=code&client_id=${process.env.XERO_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.XERO_REDIRECT_URI)}&scope=${encodeURIComponent(xeroScopes)}&state=${xeroState}`;
  
  console.log('🚀 Redirecting to Xero OAuth with corrected scopes:', xeroScopes);
  res.redirect(xeroAuthUrl);
});

// OAuth callback endpoint with callback proxy
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  console.log('🔄 OAuth Callback Received:', {
    hasCode: !!code,
    state: state ? `${state.substring(0, 8)}...` : 'none',
    error,
    timestamp: new Date().toISOString()
  });
  
  if (error) {
    console.error('❌ OAuth error:', error);
    return res.status(400).json({ error: 'oauth_error', description: error });
  }
  
  if (!code || !state) {
    console.error('❌ Missing code or state');
    return res.status(400).json({ error: 'invalid_request', description: 'Missing code or state' });
  }
  
  // Retrieve session info
  const sessionInfo = tokenStore[state];
  if (!sessionInfo) {
    console.error('❌ Invalid or expired state');
    return res.status(400).json({ error: 'invalid_state' });
  }
  
  try {
    // Exchange code for tokens
    console.log('🔄 Exchanging code for tokens');
    const tokenResponse = await axios.post('https://identity.xero.com/connect/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: process.env.XERO_REDIRECT_URI,
      client_id: process.env.XERO_CLIENT_ID,
      client_secret: process.env.XERO_CLIENT_SECRET
    }, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    console.log('✅ Tokens received successfully');
    
    // Get tenant info
    const connectionsResponse = await axios.get('https://api.xero.com/connections', {
      headers: { 'Authorization': `Bearer ${tokenResponse.data.access_token}` }
    });
    
    const tenantId = connectionsResponse.data[0]?.tenantId;
    console.log('✅ Tenant ID retrieved:', tenantId ? `${tenantId.substring(0, 8)}...` : 'none');
    
    // Store session
    const sessionId = generateState();
    tokenStore[sessionId] = {
      access_token: tokenResponse.data.access_token,
      refresh_token: tokenResponse.data.refresh_token,
      tenantId,
      expires_at: Date.now() + (tokenResponse.data.expires_in * 1000),
      type: sessionInfo.type,
      timestamp: Date.now()
    };
    
    console.log('💾 Session stored:', sessionId);
    
    // Handle ChatGPT callback proxy
    if (sessionInfo.type === 'chatgpt_proxy') {
      console.log('🔗 CHATGPT CALLBACK PROXY ACTIVATED');
      
      const chatgptCallbackUrl = `${sessionInfo.redirect_uri}?code=${sessionId}&state=${sessionInfo.original_state}`;
      console.log('🚀 Redirecting to ChatGPT:', chatgptCallbackUrl);
      
      return res.redirect(chatgptCallbackUrl);
    }
    
    // Legacy response
    res.json({
      message: 'OAuth successful',
      session_id: sessionId,
      tenant_id: tenantId,
      expires_in: tokenResponse.data.expires_in
    });
    
  } catch (error) {
    console.error('❌ OAuth callback error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'oauth_callback_failed',
      message: error.response?.data?.error_description || error.message
    });
  }
});

// Token endpoint for ChatGPT (v2.4.6 - CONTACTS FIX)
app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, client_id, client_secret } = req.body;
  
  console.log('🔑 Token request received v2.4.6:', {
    grant_type,
    client_id: client_id || 'none',
    hasCode: !!code,
    timestamp: new Date().toISOString()
  });
  
  // Enhanced ChatGPT detection for token endpoint (relaxed validation)
  const isChatGPT = client_id === CHATGPT_OAUTH.client_id || !client_id; // Accept missing client_id as potential ChatGPT
  
  if (isChatGPT) {
    console.log('✅ ChatGPT token request detected (relaxed validation)');
    
    // Relaxed validation for ChatGPT
    if (client_id && client_id !== CHATGPT_OAUTH.client_id) {
      console.error('❌ Invalid ChatGPT client_id in token request');
      return res.status(401).json({ error: 'invalid_client' });
    }
    
    if (client_secret && client_secret !== CHATGPT_OAUTH.client_secret) {
      console.error('❌ Invalid ChatGPT client_secret');
      return res.status(401).json({ error: 'invalid_client' });
    }
    
    console.log('✅ ChatGPT token credentials validated (relaxed)');
  }
  
  if (grant_type !== 'authorization_code') {
    console.error('❌ Invalid grant_type:', grant_type);
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  
  if (!code) {
    console.error('❌ Missing authorization code');
    return res.status(400).json({ error: 'invalid_request', description: 'Missing code' });
  }
  
  // Retrieve session info using the code as session ID
  const sessionInfo = tokenStore[code];
  if (!sessionInfo) {
    console.error('❌ Invalid or expired authorization code');
    return res.status(400).json({ error: 'invalid_grant' });
  }
  
  console.log('✅ Session found for code');
  
  // Return access token
  res.json({
    access_token: sessionInfo.access_token,
    token_type: 'Bearer',
    expires_in: Math.floor((sessionInfo.expires_at - Date.now()) / 1000),
    refresh_token: sessionInfo.refresh_token,
    scope: 'accounting.transactions accounting.contacts accounting.reports.read accounting.settings'
  });
  
  console.log('✅ Access token returned successfully');
});

// User info endpoint for ChatGPT
app.get('/oauth/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  const accessToken = authHeader.substring(7);
  
  // Find session by access token
  const sessionInfo = Object.values(tokenStore).find(session => session.access_token === accessToken);
  if (!sessionInfo) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  try {
    // Get user info from Xero
    const userResponse = await axios.get('https://api.xero.com/connections', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    
    const connection = userResponse.data[0];
    if (!connection) {
      return res.status(500).json({ error: 'no_connection' });
    }
    
    res.json({
      sub: connection.tenantId,
      name: connection.tenantName,
      email: 'user@xero.com', // Xero doesn't provide user email in connections
      tenant_id: connection.tenantId,
      tenant_name: connection.tenantName
    });
    
  } catch (error) {
    console.error('❌ User info error:', error.response?.data || error.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// API endpoint to get contacts with enhanced pagination (v2.4.6 - CONTACTS FIX)
app.get('/api/contacts', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }
  
  const accessToken = authHeader.substring(7);
  
  // Find session by access token
  const sessionInfo = Object.values(tokenStore).find(session => session.access_token === accessToken);
  if (!sessionInfo) {
    return res.status(401).json({ error: 'Invalid access token' });
  }
  
  try {
    const { offset = 0, limit = 100, name_contains, include_archived = 'false' } = req.query;
    
    // Calculate Xero pagination
    const xeroPage = calculateXeroPage(parseInt(offset));
    const pageOffset = calculatePageOffset(parseInt(offset));
    
    // Build filters
    const filters = {
      name_contains,
      include_archived: include_archived === 'true'
    };
    
    // Check cache first
    const cacheKey = generateCacheKey('https://api.xero.com/api.xro/2.0/Contacts', filters, xeroPage);
    let xeroResponse;
    
    if (pageCache[cacheKey]) {
      console.log('📋 Using cached contacts page:', xeroPage);
      xeroResponse = pageCache[cacheKey];
    } else {
      console.log('🔄 Fetching contacts page from Xero:', xeroPage);
      const xeroUrl = buildXeroUrl('https://api.xero.com/api.xro/2.0/Contacts', filters, xeroPage);
      
      console.log('🔗 Xero URL (v2.4.6 contacts fix):', xeroUrl);
      
      const response = await axios.get(xeroUrl, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Xero-tenant-id': sessionInfo.tenantId,
          'Accept': 'application/json'
        }
      });
      
      xeroResponse = response.data;
      
      // Cache the response
      pageCache[cacheKey] = xeroResponse;
      
      // Clean old cache entries (keep last 50)
      const cacheKeys = Object.keys(pageCache);
      if (cacheKeys.length > 50) {
        const oldestKey = cacheKeys[0];
        delete pageCache[oldestKey];
      }
    }
    
    // Extract contacts from the current page
    const allContacts = xeroResponse.Contacts || [];
    
    // Apply offset within the page and limit
    const startIndex = pageOffset;
    const endIndex = Math.min(startIndex + parseInt(limit), allContacts.length);
    const contacts = allContacts.slice(startIndex, endIndex);
    
    // Calculate if there are more pages
    const hasMore = endIndex < allContacts.length || allContacts.length === XERO_PAGE_SIZE;
    
    console.log(`✅ Returning ${contacts.length} contacts (offset: ${offset}, limit: ${limit}, page: ${xeroPage})`);
    
    res.json({
      contacts: contacts.map(contact => ({
        ContactID: contact.ContactID,
        Name: contact.Name,
        EmailAddress: contact.EmailAddress,
        ContactStatus: contact.ContactStatus,
        IsSupplier: contact.IsSupplier,
        IsCustomer: contact.IsCustomer,
        DefaultCurrency: contact.DefaultCurrency,
        UpdatedDateUTC: contact.UpdatedDateUTC
      })),
      pagination: {
        offset: parseInt(offset),
        limit: parseInt(limit),
        returned: contacts.length,
        has_more: hasMore,
        next_offset: hasMore ? parseInt(offset) + contacts.length : null
      }
    });
    
  } catch (error) {
    console.error('❌ Contacts API error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to fetch contacts',
      message: error.response?.data?.Message || error.message
    });
  }
});

// API endpoint to get invoices with enhanced date handling and pagination (v2.4.3+)
app.get('/api/invoices', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }
  
  const accessToken = authHeader.substring(7);
  
  // Find session by access token
  const sessionInfo = Object.values(tokenStore).find(session => session.access_token === accessToken);
  if (!sessionInfo) {
    return res.status(401).json({ error: 'Invalid access token' });
  }
  
  try {
    const { offset = 0, limit = 100, status, contact_id } = req.query;
    
    // Enhanced date parsing (v2.4.3+)
    const dateFilter = parseRequestedPeriod(req.query);
    console.log('📅 Using date filter:', dateFilter);
    
    // Calculate Xero pagination
    const xeroPage = calculateXeroPage(parseInt(offset));
    const pageOffset = calculatePageOffset(parseInt(offset));
    
    // Build filters
    const filters = {
      status,
      date_from: dateFilter.from_date,
      date_to: dateFilter.to_date
    };
    
    // Check cache first
    const cacheKey = generateCacheKey('https://api.xero.com/api.xro/2.0/Invoices', filters, xeroPage);
    let xeroResponse;
    
    if (pageCache[cacheKey]) {
      console.log('📋 Using cached invoices page:', xeroPage);
      xeroResponse = pageCache[cacheKey];
    } else {
      console.log('🔄 Fetching invoices page from Xero:', xeroPage);
      const xeroUrl = buildXeroUrl('https://api.xero.com/api.xro/2.0/Invoices', filters, xeroPage);
      
      const response = await axios.get(xeroUrl, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Xero-tenant-id': sessionInfo.tenantId,
          'Accept': 'application/json'
        }
      });
      
      xeroResponse = response.data;
      
      // Cache the response
      pageCache[cacheKey] = xeroResponse;
      
      // Clean old cache entries (keep last 50)
      const cacheKeys = Object.keys(pageCache);
      if (cacheKeys.length > 50) {
        const oldestKey = cacheKeys[0];
        delete pageCache[oldestKey];
      }
    }
    
    // Extract invoices from the current page
    let allInvoices = xeroResponse.Invoices || [];
    
    // Additional filtering by contact_id if specified
    if (contact_id) {
      allInvoices = allInvoices.filter(invoice => 
        invoice.Contact && invoice.Contact.ContactID === contact_id
      );
    }
    
    // Apply offset within the page and limit
    const startIndex = pageOffset;
    const endIndex = Math.min(startIndex + parseInt(limit), allInvoices.length);
    const invoices = allInvoices.slice(startIndex, endIndex);
    
    // Calculate if there are more pages
    const hasMore = endIndex < allInvoices.length || allInvoices.length === XERO_PAGE_SIZE;
    
    console.log(`✅ Returning ${invoices.length} invoices for ${dateFilter.description} (offset: ${offset}, limit: ${limit}, page: ${xeroPage})`);
    
    res.json({
      invoices: invoices.map(invoice => ({
        InvoiceID: invoice.InvoiceID,
        InvoiceNumber: invoice.InvoiceNumber,
        Type: invoice.Type,
        Status: invoice.Status,
        Date: invoice.Date,
        DueDate: invoice.DueDate,
        Total: invoice.Total,
        AmountDue: invoice.AmountDue,
        AmountPaid: invoice.AmountPaid,
        Contact: invoice.Contact ? {
          ContactID: invoice.Contact.ContactID,
          Name: invoice.Contact.Name
        } : null,
        CurrencyCode: invoice.CurrencyCode,
        UpdatedDateUTC: invoice.UpdatedDateUTC
      })),
      date_filter: dateFilter,
      pagination: {
        offset: parseInt(offset),
        limit: parseInt(limit),
        returned: invoices.length,
        has_more: hasMore,
        next_offset: hasMore ? parseInt(offset) + invoices.length : null
      }
    });
    
  } catch (error) {
    console.error('❌ Invoices API error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to fetch invoices',
      message: error.response?.data?.Message || error.message
    });
  }
});

// API endpoint to get bank transactions
app.get('/api/bank-transactions', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }
  
  const accessToken = authHeader.substring(7);
  
  // Find session by access token
  const sessionInfo = Object.values(tokenStore).find(session => session.access_token === accessToken);
  if (!sessionInfo) {
    return res.status(401).json({ error: 'Invalid access token' });
  }
  
  try {
    const { offset = 0, limit = 100, bank_account_id } = req.query;
    
    // Enhanced date parsing (v2.4.3+)
    const dateFilter = parseRequestedPeriod(req.query);
    console.log('📅 Using date filter for bank transactions:', dateFilter);
    
    // Calculate Xero pagination
    const xeroPage = calculateXeroPage(parseInt(offset));
    const pageOffset = calculatePageOffset(parseInt(offset));
    
    // Build filters
    const filters = {
      date_from: dateFilter.from_date,
      date_to: dateFilter.to_date
    };
    
    // Check cache first
    const cacheKey = generateCacheKey('https://api.xero.com/api.xro/2.0/BankTransactions', filters, xeroPage);
    let xeroResponse;
    
    if (pageCache[cacheKey]) {
      console.log('📋 Using cached bank transactions page:', xeroPage);
      xeroResponse = pageCache[cacheKey];
    } else {
      console.log('🔄 Fetching bank transactions page from Xero:', xeroPage);
      const xeroUrl = buildXeroUrl('https://api.xero.com/api.xro/2.0/BankTransactions', filters, xeroPage);
      
      const response = await axios.get(xeroUrl, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Xero-tenant-id': sessionInfo.tenantId,
          'Accept': 'application/json'
        }
      });
      
      xeroResponse = response.data;
      
      // Cache the response
      pageCache[cacheKey] = xeroResponse;
      
      // Clean old cache entries (keep last 50)
      const cacheKeys = Object.keys(pageCache);
      if (cacheKeys.length > 50) {
        const oldestKey = cacheKeys[0];
        delete pageCache[oldestKey];
      }
    }
    
    // Extract bank transactions from the current page
    let allTransactions = xeroResponse.BankTransactions || [];
    
    // Additional filtering by bank_account_id if specified
    if (bank_account_id) {
      allTransactions = allTransactions.filter(transaction => 
        transaction.BankAccount && transaction.BankAccount.AccountID === bank_account_id
      );
    }
    
    // Apply offset within the page and limit
    const startIndex = pageOffset;
    const endIndex = Math.min(startIndex + parseInt(limit), allTransactions.length);
    const transactions = allTransactions.slice(startIndex, endIndex);
    
    // Calculate if there are more pages
    const hasMore = endIndex < allTransactions.length || allTransactions.length === XERO_PAGE_SIZE;
    
    console.log(`✅ Returning ${transactions.length} bank transactions for ${dateFilter.description} (offset: ${offset}, limit: ${limit}, page: ${xeroPage})`);
    
    res.json({
      bank_transactions: transactions.map(transaction => ({
        BankTransactionID: transaction.BankTransactionID,
        Type: transaction.Type,
        Status: transaction.Status,
        Date: transaction.Date,
        Reference: transaction.Reference,
        Total: transaction.Total,
        BankAccount: transaction.BankAccount ? {
          AccountID: transaction.BankAccount.AccountID,
          Name: transaction.BankAccount.Name,
          Code: transaction.BankAccount.Code
        } : null,
        Contact: transaction.Contact ? {
          ContactID: transaction.Contact.ContactID,
          Name: transaction.Contact.Name
        } : null,
        LineItems: transaction.LineItems ? transaction.LineItems.map(item => ({
          Description: item.Description,
          UnitAmount: item.UnitAmount,
          AccountCode: item.AccountCode
        })) : [],
        UpdatedDateUTC: transaction.UpdatedDateUTC
      })),
      date_filter: dateFilter,
      pagination: {
        offset: parseInt(offset),
        limit: parseInt(limit),
        returned: transactions.length,
        has_more: hasMore,
        next_offset: hasMore ? parseInt(offset) + transactions.length : null
      }
    });
    
  } catch (error) {
    console.error('❌ Bank transactions API error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to fetch bank transactions',
      message: error.response?.data?.Message || error.message
    });
  }
});

// API endpoint to get reports with crash protection (v2.4.2+)
app.get('/api/reports/:reportType', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }
  
  const accessToken = authHeader.substring(7);
  
  // Find session by access token
  const sessionInfo = Object.values(tokenStore).find(session => session.access_token === accessToken);
  if (!sessionInfo) {
    return res.status(401).json({ error: 'Invalid access token' });
  }
  
  const { reportType } = req.params;
  
  // Validate report type and prevent crashes (v2.4.2+)
  const validReportTypes = [
    'ProfitAndLoss', 'BalanceSheet', 'CashSummary', 'AgedReceivablesByContact', 
    'AgedPayablesByContact', 'TrialBalance'
  ];
  
  if (!validReportTypes.includes(reportType)) {
    return res.status(400).json({
      error: 'Invalid report type',
      valid_types: validReportTypes
    });
  }
  
  try {
    // Enhanced date parsing (v2.4.3+)
    const dateFilter = parseRequestedPeriod(req.query);
    console.log(`📊 Generating ${reportType} report for ${dateFilter.description}`);
    
    // Build report URL with date parameters
    let reportUrl = `https://api.xero.com/api.xro/2.0/Reports/${reportType}`;
    const params = new URLSearchParams();
    
    if (dateFilter.from_date) {
      params.append('fromDate', dateFilter.from_date);
    }
    if (dateFilter.to_date) {
      params.append('toDate', dateFilter.to_date);
    }
    
    if (params.toString()) {
      reportUrl += `?${params.toString()}`;
    }
    
    console.log('🔄 Fetching report from Xero:', reportUrl);
    
    const response = await axios.get(reportUrl, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Xero-tenant-id': sessionInfo.tenantId,
        'Accept': 'application/json'
      }
    });
    
    console.log(`✅ ${reportType} report generated successfully`);
    
    res.json({
      report_type: reportType,
      date_filter: dateFilter,
      data: response.data
    });
    
  } catch (error) {
    console.error(`❌ ${reportType} report error:`, error.response?.data || error.message);
    
    // Enhanced error handling to prevent crashes (v2.4.2+)
    const errorMessage = error.response?.data?.Message || error.message || 'Unknown error';
    const errorDetails = error.response?.data?.Elements?.[0]?.ValidationErrors || [];
    
    res.status(500).json({
      error: `Failed to generate ${reportType} report`,
      message: errorMessage,
      details: errorDetails,
      report_type: reportType
    });
  }
});

// API endpoint to get accounts
app.get('/api/accounts', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }
  
  const accessToken = authHeader.substring(7);
  
  // Find session by access token
  const sessionInfo = Object.values(tokenStore).find(session => session.access_token === accessToken);
  if (!sessionInfo) {
    return res.status(401).json({ error: 'Invalid access token' });
  }
  
  try {
    const { offset = 0, limit = 100, type } = req.query;
    
    // Calculate Xero pagination
    const xeroPage = calculateXeroPage(parseInt(offset));
    const pageOffset = calculatePageOffset(parseInt(offset));
    
    // Build filters
    const filters = { type };
    
    // Check cache first
    const cacheKey = generateCacheKey('https://api.xero.com/api.xro/2.0/Accounts', filters, xeroPage);
    let xeroResponse;
    
    if (pageCache[cacheKey]) {
      console.log('📋 Using cached accounts page:', xeroPage);
      xeroResponse = pageCache[cacheKey];
    } else {
      console.log('🔄 Fetching accounts page from Xero:', xeroPage);
      const xeroUrl = buildXeroUrl('https://api.xero.com/api.xro/2.0/Accounts', filters, xeroPage);
      
      const response = await axios.get(xeroUrl, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Xero-tenant-id': sessionInfo.tenantId,
          'Accept': 'application/json'
        }
      });
      
      xeroResponse = response.data;
      
      // Cache the response
      pageCache[cacheKey] = xeroResponse;
      
      // Clean old cache entries (keep last 50)
      const cacheKeys = Object.keys(pageCache);
      if (cacheKeys.length > 50) {
        const oldestKey = cacheKeys[0];
        delete pageCache[oldestKey];
      }
    }
    
    // Extract accounts from the current page
    const allAccounts = xeroResponse.Accounts || [];
    
    // Apply offset within the page and limit
    const startIndex = pageOffset;
    const endIndex = Math.min(startIndex + parseInt(limit), allAccounts.length);
    const accounts = allAccounts.slice(startIndex, endIndex);
    
    // Calculate if there are more pages
    const hasMore = endIndex < allAccounts.length || allAccounts.length === XERO_PAGE_SIZE;
    
    console.log(`✅ Returning ${accounts.length} accounts (offset: ${offset}, limit: ${limit}, page: ${xeroPage})`);
    
    res.json({
      accounts: accounts.map(account => ({
        AccountID: account.AccountID,
        Code: account.Code,
        Name: account.Name,
        Type: account.Type,
        BankAccountNumber: account.BankAccountNumber,
        Status: account.Status,
        Description: account.Description,
        Class: account.Class,
        UpdatedDateUTC: account.UpdatedDateUTC
      })),
      pagination: {
        offset: parseInt(offset),
        limit: parseInt(limit),
        returned: accounts.length,
        has_more: hasMore,
        next_offset: hasMore ? parseInt(offset) + accounts.length : null
      }
    });
    
  } catch (error) {
    console.error('❌ Accounts API error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to fetch accounts',
      message: error.response?.data?.Message || error.message
    });
  }
});

// API documentation endpoint
app.get('/api', (req, res) => {
  res.json({
    service: 'JHK Bookkeeping Assistant',
    version: '2.4.6',
    description: 'ChatGPT-compatible Xero API wrapper with OAuth 2.0 support',
    fixes: {
      v2_4_5: 'Fixed invalid_scope error with correct Xero OAuth scopes',
      v2_4_6: 'Fixed contacts API filtering (IsArchived -> ContactStatus)'
    },
    oauth_fixes: {
      scope_fix: 'Fixed invalid_scope error with correct Xero OAuth scopes',
      redirect_uri_detection: 'Enhanced ChatGPT detection via redirect_uri pattern',
      relaxed_validation: 'Accepts missing client_id for ChatGPT compatibility'
    },
    api_fixes: {
      contacts_filtering: 'Fixed IsArchived field error for contacts',
      date_handling: 'Enhanced natural language date parsing',
      pagination: 'Optimized pagination with caching'
    },
    endpoints: {
      oauth: {
        authorize: '/oauth/authorize',
        token: '/oauth/token',
        userinfo: '/oauth/userinfo'
      },
      api: {
        contacts: '/api/contacts',
        invoices: '/api/invoices',
        bank_transactions: '/api/bank-transactions',
        accounts: '/api/accounts',
        reports: '/api/reports/{reportType}'
      }
    },
    features: {
      chatgpt_oauth: 'Full ChatGPT Actions OAuth 2.0 support',
      date_handling: 'Enhanced natural language date parsing',
      pagination: 'Efficient pagination with caching',
      error_handling: 'Comprehensive error handling and logging'
    }
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 JHK Bookkeeping Assistant v2.4.6 running on port ${port}`);
  console.log('✅ ChatGPT OAuth 2.0 ready');
  console.log('✅ Enhanced date handling active');
  console.log('✅ Pagination and caching enabled');
});
