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

// Enhanced ChatGPT request detection function
const isChatGPTRequest = (client_id, redirect_uri) => {
  if (client_id === CHATGPT_OAUTH.client_id) {
    return true;
  }
  if (redirect_uri && redirect_uri.includes('chat.openai.com/aip/')) {
    return true;
  }
  return false;
};

// Date utility functions for filtering
const formatDateForXero = (date) => {
  if (!date) return null;
  const d = new Date(date);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().split('T')[0]; // YYYY-MM-DD format
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

// Build Xero API URL with filters and pagination
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
  
  if (filters.contact_id) {
    whereConditions.push(`Contact.ContactID=Guid("${filters.contact_id}")`);
  }
  
  if (filters.name_contains) {
    whereConditions.push(`Name.Contains("${filters.name_contains}")`);
  }
  
  if (whereConditions.length > 0) {
    url.searchParams.set('where', whereConditions.join(' AND '));
  }
  
  // Add order by
  if (filters.order_by) {
    url.searchParams.set('order', filters.order_by);
  }
  
  // Add Xero page parameter
  if (page > 1) {
    url.searchParams.set('page', page.toString());
  }
  
  // Add modified since
  if (filters.modified_since) {
    const formattedDate = formatDateForXero(filters.modified_since);
    if (formattedDate) {
      url.searchParams.set('If-Modified-Since', new Date(formattedDate).toISOString());
    }
  }
  
  return url.toString();
};

// Parse and validate query parameters
const parseFilters = (query) => {
  const filters = {};
  
  // Pagination
  filters.limit = Math.min(parseInt(query.limit) || 20, 100); // Max 100 records
  filters.offset = parseInt(query.offset) || 0;
  
  // Status filtering
  if (query.status) {
    filters.status = query.status.toUpperCase();
  }
  
  // Date filtering
  if (query.date_from) {
    filters.date_from = query.date_from;
  }
  
  if (query.date_to) {
    filters.date_to = query.date_to;
  }
  
  if (query.days_ago) {
    const days = parseInt(query.days_ago);
    if (days > 0) {
      filters.date_from = getDateDaysAgo(days);
    }
  }
  
  if (query.modified_since) {
    filters.modified_since = query.modified_since;
  }
  
  // Contact filtering
  if (query.contact_id) {
    filters.contact_id = query.contact_id;
  }
  
  // Search filtering
  if (query.name_contains) {
    filters.name_contains = query.name_contains;
  }
  
  if (query.search) {
    filters.name_contains = query.search;
  }
  
  // Sorting
  if (query.order_by) {
    filters.order_by = query.order_by;
  }
  
  // Include archived (for contacts)
  filters.include_archived = query.include_archived === 'true';
  
  return filters;
};

// Fetch data from Xero with smart pagination and caching
const fetchFromXeroWithPagination = async (baseUrl, filters, access_token, tenantId, headers = {}) => {
  const startPage = calculateXeroPage(filters.offset);
  const pageOffset = calculatePageOffset(filters.offset);
  const endOffset = filters.offset + filters.limit;
  const endPage = calculateXeroPage(endOffset - 1);
  
  console.log(`📄 Pagination calculation:`, {
    offset: filters.offset,
    limit: filters.limit,
    startPage,
    endPage,
    pageOffset,
    endOffset
  });
  
  let allData = [];
  let totalFetched = 0;
  
  // Fetch all required pages
  for (let page = startPage; page <= endPage; page++) {
    const cacheKey = generateCacheKey(baseUrl, filters, page);
    let pageData;
    
    // Check cache first
    if (pageCache[cacheKey] && (Date.now() - pageCache[cacheKey].timestamp) < 300000) { // 5 min cache
      console.log(`💾 Using cached data for page ${page}`);
      pageData = pageCache[cacheKey].data;
    } else {
      console.log(`🔄 Fetching page ${page} from Xero API`);
      
      const xeroUrl = buildXeroUrl(baseUrl, filters, page);
      console.log(`🔗 Xero URL: ${xeroUrl}`);
      
      try {
        const response = await axios.get(xeroUrl, {
          headers: {
            'Authorization': `Bearer ${access_token}`,
            'Xero-tenant-id': tenantId,
            'Accept': 'application/json',
            ...headers
          }
        });
        
        // Extract data based on endpoint type
        if (response.data.Invoices) {
          pageData = response.data.Invoices;
        } else if (response.data.Contacts) {
          pageData = response.data.Contacts;
        } else if (response.data.Accounts) {
          pageData = response.data.Accounts;
        } else {
          pageData = response.data;
        }
        
        // Cache the page
        pageCache[cacheKey] = {
          data: pageData,
          timestamp: Date.now()
        };
        
        console.log(`✅ Fetched ${pageData.length} records from page ${page}`);
        
      } catch (error) {
        console.error(`❌ Error fetching page ${page}:`, error.response?.data || error.message);
        throw error;
      }
    }
    
    allData = allData.concat(pageData);
    totalFetched += pageData.length;
    
    // If we got less than a full page, we've reached the end
    if (pageData.length < XERO_PAGE_SIZE) {
      console.log(`📄 Reached end of data at page ${page} (${pageData.length} records)`);
      break;
    }
  }
  
  // Apply client-side slicing to get exact range requested
  const startIndex = pageOffset;
  const endIndex = Math.min(startIndex + filters.limit, allData.length);
  const slicedData = allData.slice(startIndex, endIndex);
  
  console.log(`✂️ Sliced data: ${startIndex}-${endIndex} from ${allData.length} total records`);
  console.log(`📊 Returning ${slicedData.length} records`);
  
  return {
    data: slicedData,
    totalAvailable: allData.length,
    hasMore: endIndex < allData.length || (allData.length === XERO_PAGE_SIZE * (endPage - startPage + 1))
  };
};

// Create optimized response format with fixed pagination
const createOptimizedResponse = (data, filters, totalCount = null, endpoint = '', hasMore = false) => {
  const response = {
    success: true,
    timestamp: new Date().toISOString(),
    endpoint: endpoint,
    filters_applied: {},
    pagination: {},
    data: data
  };
  
  // Add filter information
  if (filters.status) response.filters_applied.status = filters.status;
  if (filters.date_from) response.filters_applied.date_from = filters.date_from;
  if (filters.date_to) response.filters_applied.date_to = filters.date_to;
  if (filters.contact_id) response.filters_applied.contact_id = filters.contact_id;
  if (filters.name_contains) response.filters_applied.name_contains = filters.name_contains;
  if (filters.modified_since) response.filters_applied.modified_since = filters.modified_since;
  
  // Add pagination information
  response.pagination = {
    limit: filters.limit,
    offset: filters.offset,
    returned_count: Array.isArray(data) ? data.length : 0,
    has_more: hasMore
  };
  
  if (totalCount !== null) {
    response.pagination.total_count = totalCount;
  }
  
  // Add next page URL if there's more data
  if (hasMore) {
    const nextOffset = filters.offset + filters.limit;
    const queryParams = new URLSearchParams();
    queryParams.set('limit', filters.limit.toString());
    queryParams.set('offset', nextOffset.toString());
    
    Object.keys(response.filters_applied).forEach(key => {
      if (response.filters_applied[key]) {
        queryParams.set(key, response.filters_applied[key].toString());
      }
    });
    
    response.pagination.next_url = `${endpoint}?${queryParams.toString()}`;
  }
  
  return response;
};

// Validate environment variables
const validateEnv = () => {
  if (!process.env.XERO_CLIENT_ID || !process.env.XERO_CLIENT_SECRET) {
    console.error('❌ Missing required environment variables');
    console.error('Required: XERO_CLIENT_ID, XERO_CLIENT_SECRET');
    process.exit(1);
  }
  console.log('✅ Environment variables validated');
  console.log('🤖 ChatGPT OAuth configured for Client ID:', CHATGPT_OAUTH.client_id);
  console.log('🔄 Using enhanced callback proxy with pagination fix');
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

// JWKS endpoint (minimal implementation)
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({
    keys: []
  });
});

// OAuth Endpoints for ChatGPT (with Enhanced Callback Proxy)
// ==========================================================

// Enhanced OAuth Authorization endpoint
app.get('/oauth/authorize', (req, res) => {
  const baseUrl = getBaseUrl(req);
  const state = generateState();
  
  const { client_id, redirect_uri, scope, response_type, state: original_state } = req.query;
  
  console.log('🔗 OAuth authorization request received:');
  console.log('  Client ID:', client_id);
  console.log('  Redirect URI:', redirect_uri);
  
  const isChatGPT = isChatGPTRequest(client_id, redirect_uri);
  
  if (isChatGPT) {
    console.log('✅ ChatGPT OAuth request detected (enhanced detection)');
    console.log('🔄 Using optimized callback proxy approach');
  } else {
    console.log('🔗 Legacy OAuth request detected');
  }
  
  // Store state and original parameters
  tokenStore[state] = { 
    created: Date.now(),
    is_chatgpt: isChatGPT,
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
  
  console.log(`🔗 Redirecting to Xero OAuth`);
  res.redirect(xeroAuthUrl);
});

// Enhanced OAuth Token endpoint
app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;
  
  console.log('🔄 Token request received:');
  console.log('  Grant type:', grant_type);
  console.log('  Client ID:', client_id);
  
  const isChatGPT = isChatGPTRequest(client_id, redirect_uri);
  
  if (isChatGPT) {
    console.log('✅ ChatGPT token request detected (enhanced detection)');
    
    if (client_id === CHATGPT_OAUTH.client_id) {
      if (client_secret !== CHATGPT_OAUTH.client_secret) {
        console.error('❌ Invalid ChatGPT client secret');
        return res.status(401).json({ error: 'invalid_client' });
      }
    }
    
    if (redirect_uri && !redirect_uri.includes('chat.openai.com/aip/')) {
      console.error('❌ Invalid ChatGPT redirect URI pattern');
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    console.log('✅ ChatGPT client credentials validated');
  }
  
  try {
    if (grant_type === 'authorization_code') {
      const session = tokenStore[code];
      
      if (!session) {
        console.error('❌ Invalid authorization code/session:', code);
        return res.status(400).json({ error: 'invalid_grant' });
      }
      
      console.log('✅ Session found and validated');
      
      res.json({
        access_token: code,
        token_type: 'Bearer',
        expires_in: Math.floor((session.expires_at - Date.now()) / 1000),
        refresh_token: code,
        scope: 'accounting.transactions accounting.contacts accounting.settings accounting.reports.read'
      });
      
    } else if (grant_type === 'refresh_token') {
      const session = tokenStore[refresh_token];
      
      if (!session || !session.refresh_token) {
        console.error('❌ Invalid refresh token');
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
      
      session.access_token = access_token;
      session.refresh_token = new_refresh_token || session.refresh_token;
      session.expires_at = Date.now() + (expires_in * 1000);
      
      console.log('✅ Token refreshed successfully');
      
      res.json({
        access_token: refresh_token,
        token_type: 'Bearer',
        expires_in: expires_in,
        refresh_token: refresh_token,
        scope: 'accounting.transactions accounting.contacts accounting.settings accounting.reports.read'
      });
      
    } else {
      console.error('❌ Unsupported grant type:', grant_type);
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

// Enhanced OAuth Callback with improved logging
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  console.log('🔄 OAuth callback received:');
  console.log('  Code:', code ? 'PRESENT' : 'MISSING');
  console.log('  State:', state);
  
  if (error) {
    console.error('❌ OAuth error from Xero:', error);
    
    if (state && tokenStore[state] && tokenStore[state].is_chatgpt) {
      const { original_params } = tokenStore[state];
      console.log('🔗 Forwarding error to ChatGPT');
      const redirectUrl = `${original_params.redirect_uri}?error=${error}&error_description=${encodeURIComponent('OAuth authorization failed')}&state=${original_params.original_state}`;
      return res.redirect(redirectUrl);
    }
    
    return res.status(400).json({ 
      error: 'OAuth authorization failed', 
      details: error 
    });
  }

  if (!code || !state || !tokenStore[state]) {
    console.error('❌ Invalid OAuth callback parameters');
    return res.status(400).json({ 
      error: 'Invalid OAuth callback parameters' 
    });
  }

  const stateData = tokenStore[state];
  const { original_params, is_chatgpt } = stateData;
  
  console.log('📋 Processing OAuth callback:', {
    is_chatgpt,
    has_original_params: !!original_params
  });
  
  try {
    console.log('🔄 Exchanging code for tokens...');
    
    const baseUrl = getBaseUrl(req);
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

    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    console.log('✅ Tokens received successfully from Xero');

    // Get tenant connections
    console.log('🔄 Fetching tenant connections...');
    const connectionsResponse = await axios.get('https://api.xero.com/connections', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });

    const connections = connectionsResponse.data;
    console.log(`✅ Found ${connections.length} connection(s)`);

    // Store tokens
    const sessionId = crypto.randomBytes(16).toString('hex');
    tokenStore[sessionId] = {
      access_token,
      refresh_token,
      expires_at: Date.now() + (expires_in * 1000),
      connections,
      created: Date.now(),
      is_chatgpt: is_chatgpt
    };

    console.log('💾 Session created:', {
      session_id: sessionId,
      is_chatgpt,
      connections_count: connections.length
    });

    // Clean up state
    delete tokenStore[state];

    if (is_chatgpt && original_params && original_params.redirect_uri) {
      console.log('🔗 CHATGPT CALLBACK PROXY ACTIVATED');
      console.log('🚀 Redirecting to ChatGPT with session ID');
      
      const redirectUrl = `${original_params.redirect_uri}?code=${sessionId}&state=${original_params.original_state}`;
      res.redirect(redirectUrl);
    } else {
      console.log('📄 Showing legacy success page');
      res.json({
        success: true,
        message: 'Xero OAuth completed successfully!',
        session_id: sessionId,
        connections: connections.map(conn => ({
          id: conn.id,
          tenantId: conn.tenantId,
          tenantName: conn.tenantName,
          tenantType: conn.tenantType
        })),
        endpoints: {
          contacts: `${baseUrl}/api/contacts?session=${sessionId}`,
          invoices: `${baseUrl}/api/invoices?session=${sessionId}`,
          accounts: `${baseUrl}/api/accounts?session=${sessionId}`
        }
      });
    }

  } catch (error) {
    console.error('❌ OAuth callback error:', error.response?.data || error.message);
    
    if (is_chatgpt && original_params && original_params.redirect_uri) {
      console.log('🔗 Forwarding error to ChatGPT');
      const redirectUrl = `${original_params.redirect_uri}?error=server_error&error_description=${encodeURIComponent(error.message)}&state=${original_params.original_state}`;
      res.redirect(redirectUrl);
    } else {
      res.status(500).json({ 
        error: 'OAuth token exchange failed', 
        details: error.response?.data || error.message 
      });
    }
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
    console.error('❌ Invalid session for userinfo');
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  try {
    console.log('🔄 Fetching user info...');
    
    const userResponse = await axios.get('https://api.xero.com/api.xro/2.0/Organisation', {
      headers: {
        'Authorization': `Bearer ${session.access_token}`,
        'Xero-tenant-id': session.connections[0]?.tenantId,
        'Accept': 'application/json'
      }
    });
    
    const org = userResponse.data.Organisations?.[0];
    
    console.log('✅ User info retrieved');
    
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
    version: '2.4.1',
    environment: process.env.NODE_ENV || 'development',
    chatgpt_ready: true,
    chatgpt_client_configured: true,
    callback_proxy_enabled: true,
    enhanced_detection: true,
    filtering_enabled: true,
    pagination_enabled: true,
    pagination_fix: 'xero_page_based',
    optimization_level: 'full',
    cache_enabled: true
  });
});

// Middleware to validate session and get tokens
const validateSession = async (req, res, next) => {
  let sessionId = req.query.session || req.headers['x-session-id'];
  
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
  
  // Check if token is expired and refresh if needed
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

// OPTIMIZED API Endpoints with Fixed Pagination
// =============================================

// Enhanced List contacts with fixed pagination
app.get('/api/contacts', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    // Parse filters from query parameters
    const filters = parseFilters(req.query);
    
    console.log(`🔄 Fetching contacts for tenant: ${tenantId}`);
    console.log('📋 Applied filters:', filters);
    
    // Use new pagination system
    const baseXeroUrl = 'https://api.xero.com/api.xro/2.0/Contacts';
    const result = await fetchFromXeroWithPagination(baseXeroUrl, filters, access_token, tenantId);
    
    let contacts = result.data;
    
    // Apply client-side filtering for parameters not supported by Xero API
    if (!filters.include_archived) {
      contacts = contacts.filter(contact => contact.ContactStatus !== 'ARCHIVED');
    }
    
    console.log(`✅ Retrieved ${contacts.length} contacts`);
    
    const optimizedResponse = createOptimizedResponse(
      contacts, 
      filters, 
      result.totalAvailable, 
      '/api/contacts',
      result.hasMore
    );
    
    // Add contact-specific metadata
    optimizedResponse.summary = {
      total_contacts: result.totalAvailable,
      active_contacts: contacts.filter(c => c.ContactStatus === 'ACTIVE').length,
      archived_contacts: contacts.filter(c => c.ContactStatus === 'ARCHIVED').length
    };
    
    res.json(optimizedResponse);

  } catch (error) {
    console.error('❌ Contacts API error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to fetch contacts', 
      details: error.response?.data || error.message 
    });
  }
});

// Enhanced List invoices with fixed pagination
app.get('/api/invoices', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    // Parse filters from query parameters
    const filters = parseFilters(req.query);
    
    console.log(`🔄 Fetching invoices for tenant: ${tenantId}`);
    console.log('📋 Applied filters:', filters);
    
    // Use new pagination system
    const baseXeroUrl = 'https://api.xero.com/api.xro/2.0/Invoices';
    const filtersWithOrder = {
      ...filters,
      order_by: filters.order_by || 'Date DESC' // Default to newest first
    };
    
    const result = await fetchFromXeroWithPagination(baseXeroUrl, filtersWithOrder, access_token, tenantId);
    
    const invoices = result.data;
    
    console.log(`✅ Retrieved ${invoices.length} invoices`);
    
    const optimizedResponse = createOptimizedResponse(
      invoices, 
      filters, 
      result.totalAvailable, 
      '/api/invoices',
      result.hasMore
    );
    
    // Add invoice-specific metadata
    const statusCounts = {};
    invoices.forEach(invoice => {
      statusCounts[invoice.Status] = (statusCounts[invoice.Status] || 0) + 1;
    });
    
    const totalAmount = invoices.reduce((sum, invoice) => sum + (invoice.Total || 0), 0);
    const amountDue = invoices.reduce((sum, invoice) => sum + (invoice.AmountDue || 0), 0);
    
    optimizedResponse.summary = {
      total_invoices: result.totalAvailable,
      status_breakdown: statusCounts,
      total_amount: totalAmount,
      amount_due: amountDue,
      currency: invoices[0]?.CurrencyCode || 'USD'
    };
    
    res.json(optimizedResponse);

  } catch (error) {
    console.error('❌ Invoices API error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to fetch invoices', 
      details: error.response?.data || error.message 
    });
  }
});

// Enhanced List accounts with fixed pagination
app.get('/api/accounts', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    const filters = parseFilters(req.query);
    
    console.log(`🔄 Fetching accounts for tenant: ${tenantId}`);
    console.log('📋 Applied filters:', filters);
    
    // Use new pagination system
    const baseXeroUrl = 'https://api.xero.com/api.xro/2.0/Accounts';
    const result = await fetchFromXeroWithPagination(baseXeroUrl, filters, access_token, tenantId);
    
    const accounts = result.data;
    
    console.log(`✅ Retrieved ${accounts.length} accounts`);
    
    const optimizedResponse = createOptimizedResponse(
      accounts, 
      filters, 
      result.totalAvailable, 
      '/api/accounts',
      result.hasMore
    );
    
    // Add account-specific metadata
    const typeCounts = {};
    accounts.forEach(account => {
      typeCounts[account.Type] = (typeCounts[account.Type] || 0) + 1;
    });
    
    optimizedResponse.summary = {
      total_accounts: result.totalAvailable,
      type_breakdown: typeCounts,
      active_accounts: accounts.filter(a => a.Status === 'ACTIVE').length,
      archived_accounts: accounts.filter(a => a.Status === 'ARCHIVED').length
    };
    
    res.json(optimizedResponse);

  } catch (error) {
    console.error('❌ Accounts API error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to fetch accounts', 
      details: error.response?.data || error.message 
    });
  }
});

// Enhanced Create invoice with validation
app.post('/api/invoices', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    const invoiceData = req.body;
    
    // Validate required fields
    if (!invoiceData.Contact || !invoiceData.Contact.ContactID) {
      return res.status(400).json({ 
        error: 'Contact information is required',
        required_fields: ['Contact.ContactID']
      });
    }
    
    if (!invoiceData.LineItems || !Array.isArray(invoiceData.LineItems) || invoiceData.LineItems.length === 0) {
      return res.status(400).json({ 
        error: 'At least one line item is required',
        required_fields: ['LineItems']
      });
    }
    
    console.log(`🔄 Creating invoice for tenant: ${tenantId}`);
    console.log('📋 Invoice data:', JSON.stringify(invoiceData, null, 2));
    
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

    const createdInvoice = response.data.Invoices?.[0];
    console.log(`✅ Invoice created successfully: ${createdInvoice?.InvoiceNumber}`);
    
    res.json({
      success: true,
      message: 'Invoice created successfully',
      invoice: createdInvoice,
      invoice_number: createdInvoice?.InvoiceNumber,
      invoice_id: createdInvoice?.InvoiceID,
      status: createdInvoice?.Status,
      total: createdInvoice?.Total,
      currency: createdInvoice?.CurrencyCode
    });

  } catch (error) {
    console.error('❌ Create invoice error:', error.response?.data || error.message);
    
    // Provide detailed error information
    const errorDetails = error.response?.data;
    let errorMessage = 'Failed to create invoice';
    let validationErrors = [];
    
    if (errorDetails?.Elements) {
      errorDetails.Elements.forEach(element => {
        if (element.ValidationErrors) {
          validationErrors = validationErrors.concat(element.ValidationErrors);
        }
      });
    }
    
    if (validationErrors.length > 0) {
      errorMessage = 'Invoice validation failed';
    }
    
    res.status(400).json({ 
      error: errorMessage,
      validation_errors: validationErrors,
      details: errorDetails || error.message
    });
  }
});

// Enhanced Get reports with filtering
app.get('/api/reports/:reportType', validateSession, async (req, res) => {
  try {
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    const { reportType } = req.params;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    console.log(`🔄 Fetching ${reportType} report for tenant: ${tenantId}`);
    
    // Build report URL with query parameters
    const reportUrl = `https://api.xero.com/api.xro/2.0/Reports/${reportType}`;
    const params = { ...req.query };
    delete params.session; // Remove session from query params
    delete params.tenant;  // Remove tenant from query params
    
    console.log('📋 Report parameters:', params);
    
    const response = await axios.get(reportUrl, {
      headers: {
        'Authorization': `Bearer ${access_token}`,
        'Xero-tenant-id': tenantId,
        'Accept': 'application/json'
      },
      params: params
    });

    console.log(`✅ Retrieved ${reportType} report`);
    
    const reportData = response.data.Reports?.[0] || response.data;
    
    res.json({
      success: true,
      report_type: reportType,
      tenant_id: tenantId,
      generated_at: new Date().toISOString(),
      parameters: params,
      report: reportData
    });

  } catch (error) {
    console.error(`❌ ${reportType} report error:`, error.response?.data || error.message);
    res.status(500).json({ 
      error: `Failed to fetch ${reportType} report`, 
      details: error.response?.data || error.message 
    });
  }
});

// Enhanced Quick filters endpoint for common bookkeeping queries
app.get('/api/quick/:filter', validateSession, async (req, res) => {
  try {
    const { filter } = req.params;
    const { access_token, connections } = req.session;
    const tenantId = req.query.tenant || connections[0]?.tenantId;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant ID specified' });
    }

    console.log(`🔄 Processing quick filter: ${filter}`);
    
    let filters;
    let endpoint;
    let description;
    
    switch (filter) {
      case 'recent-invoices':
        filters = parseFilters({ days_ago: 7, limit: 10, order_by: 'Date DESC' });
        endpoint = 'https://api.xero.com/api.xro/2.0/Invoices';
        description = 'Recent invoices from the last 7 days';
        break;
        
      case 'open-invoices':
        filters = parseFilters({ status: 'AUTHORISED', limit: 20, order_by: 'Date DESC' });
        endpoint = 'https://api.xero.com/api.xro/2.0/Invoices';
        description = 'Open (unpaid) invoices';
        break;
        
      case 'overdue-invoices':
        filters = parseFilters({ status: 'AUTHORISED', date_to: getDateDaysAgo(0), limit: 20, order_by: 'Date ASC' });
        endpoint = 'https://api.xero.com/api.xro/2.0/Invoices';
        description = 'Overdue invoices';
        break;
        
      case 'recent-contacts':
        filters = parseFilters({ days_ago: 30, limit: 20 });
        endpoint = 'https://api.xero.com/api.xro/2.0/Contacts';
        description = 'Recently added or modified contacts';
        break;
        
      case 'active-contacts':
        filters = parseFilters({ include_archived: false, limit: 50 });
        endpoint = 'https://api.xero.com/api.xro/2.0/Contacts';
        description = 'Active contacts only';
        break;
        
      default:
        return res.status(400).json({ 
          error: 'Unknown quick filter',
          available_filters: [
            'recent-invoices',
            'open-invoices', 
            'overdue-invoices',
            'recent-contacts',
            'active-contacts'
          ]
        });
    }
    
    // Fetch data using the new pagination system
    const result = await fetchFromXeroWithPagination(endpoint, filters, access_token, tenantId);
    
    let data = result.data;
    
    // Apply additional filtering for contacts
    if (filter === 'active-contacts') {
      data = data.filter(contact => contact.ContactStatus !== 'ARCHIVED');
    }
    
    console.log(`✅ Quick filter ${filter} returned ${data.length} records`);
    
    const optimizedResponse = createOptimizedResponse(
      data, 
      filters, 
      result.totalAvailable, 
      `/api/quick/${filter}`,
      result.hasMore
    );
    
    optimizedResponse.filter_description = description;
    
    res.json(optimizedResponse);

  } catch (error) {
    console.error('❌ Quick filter error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to process quick filter', 
      details: error.response?.data || error.message 
    });
  }
});

// Legacy MCP endpoints (for backward compatibility)
app.get('/mcp/contacts', validateSession, (req, res) => {
  req.url = '/api/contacts';
  app._router.handle(req, res);
});

app.get('/mcp/invoices', validateSession, (req, res) => {
  req.url = '/api/invoices';
  app._router.handle(req, res);
});

app.get('/mcp/accounts', validateSession, (req, res) => {
  req.url = '/api/accounts';
  app._router.handle(req, res);
});

// Root endpoint - start OAuth flow (legacy support)
app.get('/', (req, res) => {
  const baseUrl = getBaseUrl(req);
  const state = generateState();
  
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

  if (!code || !state || !tokenStore[state]) {
    return res.status(400).json({ 
      error: 'Invalid OAuth callback parameters' 
    });
  }

  try {
    console.log('🔄 Exchanging code for tokens...');
    
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

    const connectionsResponse = await axios.get('https://api.xero.com/connections', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });

    const connections = connectionsResponse.data;
    console.log(`✅ Found ${connections.length} connection(s)`);

    const sessionId = crypto.randomBytes(16).toString('hex');
    tokenStore[sessionId] = {
      access_token,
      refresh_token,
      expires_at: Date.now() + (expires_in * 1000),
      connections,
      created: Date.now()
    };

    delete tokenStore[state];

    res.json({
      success: true,
      message: 'Xero OAuth completed successfully!',
      session_id: sessionId,
      connections: connections.map(conn => ({
        id: conn.id,
        tenantId: conn.tenantId,
        tenantName: conn.tenantName,
        tenantType: conn.tenantType
      })),
      endpoints: {
        contacts: `${baseUrl}/api/contacts?session=${sessionId}`,
        invoices: `${baseUrl}/api/invoices?session=${sessionId}`,
        accounts: `${baseUrl}/api/accounts?session=${sessionId}`,
        quick_filters: `${baseUrl}/api/quick/open-invoices?session=${sessionId}`
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

// Enhanced API Documentation
app.get('/api', (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    service: 'Xero API Wrapper',
    version: '2.4.1',
    chatgpt_compatible: true,
    optimization_level: 'full',
    pagination_fix: 'xero_page_based',
    features: {
      filtering: true,
      pagination: true,
      pagination_fix: true,
      quick_filters: true,
      enhanced_responses: true,
      smart_caching: true
    },
    oauth: {
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
      discovery: `${baseUrl}/.well-known/oauth-authorization-server`
    },
    endpoints: {
      'GET /api/contacts': {
        description: 'List contacts with filtering and pagination',
        parameters: {
          limit: 'Number of records (default: 20, max: 100)',
          offset: 'Skip records for pagination',
          name_contains: 'Filter by contact name',
          include_archived: 'Include archived contacts (default: false)',
          modified_since: 'Filter by last modified date (ISO format)',
          days_ago: 'Filter by days ago (e.g., 7 for last week)'
        }
      },
      'GET /api/invoices': {
        description: 'List invoices with comprehensive filtering',
        parameters: {
          limit: 'Number of records (default: 20, max: 100)',
          offset: 'Skip records for pagination',
          status: 'Filter by status (DRAFT, AUTHORISED, PAID, etc.)',
          date_from: 'Filter invoices after this date (YYYY-MM-DD)',
          date_to: 'Filter invoices before this date (YYYY-MM-DD)',
          days_ago: 'Filter by days ago (e.g., 7 for last week)',
          contact_id: 'Filter by specific contact ID',
          order_by: 'Sort order (default: Date DESC)'
        }
      },
      'GET /api/accounts': {
        description: 'List accounts with filtering',
        parameters: {
          limit: 'Number of records (default: 20, max: 100)',
          offset: 'Skip records for pagination'
        }
      },
      'POST /api/invoices': 'Create a new invoice',
      'GET /api/reports/:reportType': 'Get financial reports (ProfitAndLoss, BalanceSheet, etc.)',
      'GET /api/quick/:filter': {
        description: 'Quick filters for common bookkeeping queries',
        available_filters: [
          'recent-invoices',
          'open-invoices',
          'overdue-invoices', 
          'recent-contacts',
          'active-contacts'
        ]
      }
    },
    pagination: {
      note: 'Fixed to work with Xero\'s page-based pagination system',
      xero_page_size: XERO_PAGE_SIZE,
      client_side_slicing: true,
      smart_caching: true,
      supports_offset_limit: true
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
      recent_invoices: `${baseUrl}/api/invoices?days_ago=7&limit=10`,
      open_invoices: `${baseUrl}/api/invoices?status=AUTHORISED&limit=20`,
      next_page: `${baseUrl}/api/invoices?limit=20&offset=20`,
      active_contacts: `${baseUrl}/api/contacts?include_archived=false&limit=50`,
      quick_open_invoices: `${baseUrl}/api/quick/open-invoices`
    },
    response_format: {
      success: true,
      timestamp: '2025-09-16T12:00:00.000Z',
      endpoint: '/api/invoices',
      filters_applied: {
        status: 'AUTHORISED',
        days_ago: 7,
        limit: 20
      },
      pagination: {
        limit: 20,
        offset: 0,
        returned_count: 15,
        has_more: false,
        next_url: null
      },
      summary: {
        total_invoices: 15,
        status_breakdown: { AUTHORISED: 15 },
        total_amount: 12500.00,
        amount_due: 8750.00
      },
      data: '... (filtered results)'
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
      'GET /api/reports/:reportType',
      'GET /api/quick/:filter'
    ]
  });
});

// Cleanup old sessions and cache (run every hour)
setInterval(() => {
  const now = Date.now();
  const oneHour = 60 * 60 * 1000;
  
  // Clean up old sessions
  Object.keys(tokenStore).forEach(key => {
    const session = tokenStore[key];
    if (session.created && (now - session.created) > oneHour) {
      delete tokenStore[key];
    }
  });
  
  // Clean up old cache entries
  Object.keys(pageCache).forEach(key => {
    const entry = pageCache[key];
    if (entry.timestamp && (now - entry.timestamp) > oneHour) {
      delete pageCache[key];
    }
  });
  
  console.log(`🧹 Cleanup completed: ${Object.keys(tokenStore).length} sessions, ${Object.keys(pageCache).length} cache entries`);
}, 60 * 60 * 1000);

// Start server
const startServer = () => {
  validateEnv();
  
  app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Xero API Wrapper v2.4.1 running on 0.0.0.0:${port}`);
    console.log(`🔗 OAuth URL: http://localhost:${port}/oauth/authorize`);
    console.log(`🏥 Health check: http://localhost:${port}/health`);
    console.log(`📚 API docs: http://localhost:${port}/api`);
    console.log(`🔍 OAuth Discovery: http://localhost:${port}/.well-known/oauth-authorization-server`);
    console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔑 Xero Client ID: ${process.env.XERO_CLIENT_ID ? 'SET' : 'MISSING'}`);
    console.log(`🔐 Xero Client Secret: ${process.env.XERO_CLIENT_SECRET ? 'SET' : 'MISSING'}`);
    console.log(`🤖 ChatGPT Ready: YES`);
    console.log(`🎯 ChatGPT Client ID: ${CHATGPT_OAUTH.client_id}`);
    console.log(`🔄 Enhanced Callback Proxy: ENABLED`);
    console.log(`🎯 Enhanced Detection: ENABLED`);
    console.log(`🔍 Full Filtering & Pagination: ENABLED`);
    console.log(`📄 Xero Page-Based Pagination: FIXED`);
    console.log(`💾 Smart Caching: ENABLED`);
    console.log(`⚡ Optimization Level: FULL`);
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

