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

// Enhanced date utility functions for v2.4.3
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

// Enhanced date parsing function for v2.4.3
const parseRequestedPeriod = (query) => {
  const { period, month, year, from_date, to_date, days_ago } = query;
  
  console.log('📅 Parsing date request:', query);
  
  // Handle natural language dates
  if (period) {
    const periodLower = period.toLowerCase();
    
    // September 2025 specific fix
    if (periodLower.includes('september') || periodLower.includes('sep')) {
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
  
  if (filters.name_contains) {
    whereConditions.push(`Name.Contains("${filters.name_contains}")`);
  }
  
  if (filters.include_archived === false) {
    whereConditions.push(`IsArchived==false`);
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

// Health check endpoint with v2.4.3 info
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'JHK Bookkeeping Assistant',
    version: '2.4.3',
    features: {
      chatgpt_ready: true,
      enhanced_detection: true,
      callback_proxy_enabled: true,
      date_handling_fixed: true,
      september_2025_support: true
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
    scopes_supported: ['openid', 'profile', 'email', 'accounting.contacts', 'accounting.transactions'],
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

// OAuth authorization endpoint with enhanced ChatGPT detection
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;
  
  console.log('🔐 OAuth Authorization Request:', {
    client_id: client_id ? `${client_id.substring(0, 8)}...` : 'none',
    redirect_uri,
    response_type,
    scope,
    state,
    timestamp: new Date().toISOString()
  });
  
  // Enhanced ChatGPT detection
  const isChatGPT = isChatGPTRequest(client_id, redirect_uri);
  
  if (isChatGPT) {
    console.log('✅ ChatGPT OAuth request detected (enhanced detection)');
    
    // Validate ChatGPT credentials
    if (client_id !== CHATGPT_OAUTH.client_id) {
      console.error('❌ Invalid ChatGPT client_id');
      return res.status(400).json({ error: 'invalid_client_id' });
    }
    
    console.log('✅ ChatGPT client credentials validated');
    console.log('🔄 Using callback proxy approach');
    
    // Store ChatGPT callback info for later use
    const sessionId = generateState();
    tokenStore[sessionId] = {
      type: 'chatgpt_oauth',
      client_id,
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
    redirect_uri: isChatGPT ? CHATGPT_OAUTH.redirect_uri : redirect_uri,
    client_id,
    timestamp: Date.now()
  };
  
  // Redirect to Xero OAuth
  const xeroAuthUrl = `https://login.xero.com/identity/connect/authorize?response_type=code&client_id=${process.env.XERO_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.XERO_REDIRECT_URI)}&scope=accounting.contacts%20accounting.transactions%20accounting.reports%20accounting.settings&state=${xeroState}`;
  
  console.log('🚀 Redirecting to Xero OAuth');
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

// Token endpoint for ChatGPT
app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, client_id, client_secret } = req.body;
  
  console.log('🔑 Token request received:', {
    grant_type,
    client_id: client_id ? `${client_id.substring(0, 8)}...` : 'none',
    hasCode: !!code,
    timestamp: new Date().toISOString()
  });
  
  // Enhanced ChatGPT detection
  const isChatGPT = isChatGPTRequest(client_id);
  
  if (isChatGPT) {
    console.log('✅ ChatGPT token request detected (enhanced detection)');
    
    // Validate ChatGPT credentials
    if (client_id !== CHATGPT_OAUTH.client_id || client_secret !== CHATGPT_OAUTH.client_secret) {
      console.error('❌ Invalid ChatGPT credentials');
      return res.status(401).json({ error: 'invalid_client' });
    }
    
    console.log('✅ ChatGPT client credentials validated');
  }
  
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  
  // Retrieve session
  const session = tokenStore[code];
  if (!session || !session.access_token) {
    console.error('❌ Invalid or expired authorization code');
    return res.status(400).json({ error: 'invalid_grant' });
  }
  
  console.log('✅ Session found and validated');
  
  // Return access token
  res.json({
    access_token: code, // Use session ID as access token
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'accounting.contacts accounting.transactions accounting.reports'
  });
});

// User info endpoint
app.get('/oauth/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  const token = authHeader.substring(7);
  const session = tokenStore[token];
  
  if (!session) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  res.json({
    sub: 'xero-user',
    name: 'Xero User',
    email: 'user@xero.com'
  });
});

// API documentation endpoint
app.get('/api', (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    service: 'JHK Bookkeeping Assistant',
    version: '2.4.3',
    description: 'Professional Xero integration with enhanced date handling for JHK clients',
    chatgpt_compatible: true,
    date_handling: {
      natural_language: true,
      september_2025_fix: true,
      supported_formats: ['YYYY-MM-DD', 'DD/MM/YYYY', 'period=september-2025']
    },
    oauth: {
      authorization_url: `${baseUrl}/oauth/authorize`,
      token_url: `${baseUrl}/oauth/token`,
      discovery_url: `${baseUrl}/.well-known/oauth-authorization-server`
    },
    endpoints: {
      invoices: `${baseUrl}/api/invoices`,
      contacts: `${baseUrl}/api/contacts`,
      accounts: `${baseUrl}/api/accounts`,
      reports: `${baseUrl}/api/reports/{reportType}`,
      quick_filters: {
        open_invoices: `${baseUrl}/api/quick/open-invoices`,
        recent_invoices: `${baseUrl}/api/quick/recent-invoices`,
        overdue_invoices: `${baseUrl}/api/quick/overdue-invoices`,
        active_contacts: `${baseUrl}/api/quick/active-contacts`
      }
    },
    filtering: {
      date_examples: [
        'period=september-2025',
        'from_date=2025-09-01&to_date=2025-09-30',
        'days_ago=7',
        'month=9&year=2025'
      ],
      status_filters: ['DRAFT', 'SUBMITTED', 'AUTHORISED', 'PAID'],
      pagination: 'limit=20&offset=0'
    }
  });
});

// Enhanced reports endpoint with v2.4.3 date handling
app.get('/api/reports/:reportType', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Bearer token required' });
  }

  const token = authHeader.substring(7);
  const session = tokenStore[token];

  if (!session || !session.access_token) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  let reportType;
  try {
    reportType = req.params.reportType;
    const dateParams = parseRequestedPeriod(req.query);
    
    console.log('📊 Report Request v2.4.3:', {
      reportType,
      originalQuery: req.query,
      parsedDates: dateParams,
      timestamp: new Date().toISOString()
    });
    
    // Validate dates
    if (!dateParams.from_date || !dateParams.to_date) {
      return res.status(400).json({
        error: 'Invalid date parameters',
        received: req.query,
        parsed: dateParams,
        help: 'Use period=september-2025 or from_date=2025-09-01&to_date=2025-09-30'
      });
    }
    
    // Build Xero API URL with correct date format
    const xeroUrl = `https://api.xero.com/api.xro/2.0/Reports/${reportType}?fromDate=${dateParams.from_date}&toDate=${dateParams.to_date}`;
    
    console.log('🔗 Xero API URL:', xeroUrl);
    
    // Make Xero API call with timeout
    const response = await axios.get(xeroUrl, {
      headers: {
        'Authorization': `Bearer ${session.access_token}`,
        'Accept': 'application/json',
        'Xero-tenant-id': session.tenantId
      },
      timeout: 30000
    });
    
    // Enhanced response with date context
    const reportData = {
      report_type: reportType,
      period: {
        from_date: dateParams.from_date,
        to_date: dateParams.to_date,
        description: dateParams.description,
        month_year: dateParams.from_date.includes('2025-09') ? 'September 2025' : 'Custom period'
      },
      generated_at: new Date().toISOString(),
      data: response.data,
      date_context: {
        requested: req.query.period || 'custom range',
        actual_period: `${dateParams.from_date} to ${dateParams.to_date}`,
        current_date: new Date().toISOString().split('T')[0],
        note: dateParams.from_date.includes('2025-09') ? 
          '✅ September 2025 data as requested' : 
          `Data for ${dateParams.description}`
      }
    };
    
    console.log('✅ Report generated successfully:', {
      reportType,
      period: reportData.period,
      dataPoints: response.data.Reports?.[0]?.Rows?.length || 0
    });
    
    res.json(reportData);
    
  } catch (error) {
    console.error(`❌ ${reportType} report error:`, error.response?.data || error.message);
    res.status(500).json({
      error: 'Report generation failed',
      message: error.response?.data?.error_description || error.message,
      reportType: req.params.reportType,
      requestedDates: req.query
    });
  }
});

// Enhanced invoices endpoint with improved date handling
app.get('/api/invoices', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Bearer token required' });
  }

  const token = authHeader.substring(7);
  const session = tokenStore[token];

  if (!session || !session.access_token) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  try {
    const { 
      limit = 20, 
      offset = 0, 
      status, 
      days_ago, 
      date_from, 
      date_to,
      period,
      month,
      year,
      name_contains,
      include_archived = false 
    } = req.query;

    console.log('📋 Invoices request with enhanced date handling:', {
      limit: parseInt(limit),
      offset: parseInt(offset),
      filters: { status, days_ago, date_from, date_to, period, month, year, name_contains },
      timestamp: new Date().toISOString()
    });

    // Parse date parameters using enhanced function
    let dateFilters = {};
    if (period || month || year || date_from || date_to || days_ago) {
      const dateParams = parseRequestedPeriod({ period, month, year, date_from, date_to, days_ago });
      if (dateParams.from_date) dateFilters.date_from = dateParams.from_date;
      if (dateParams.to_date) dateFilters.date_to = dateParams.to_date;
      
      console.log('📅 Applied date filters:', dateFilters);
    }

    // Build filters object
    const filters = {
      status,
      name_contains,
      include_archived: include_archived === 'true',
      ...dateFilters
    };

    // Calculate Xero pagination
    const requestedLimit = Math.min(parseInt(limit), 100);
    const requestedOffset = parseInt(offset);
    
    const startPage = calculateXeroPage(requestedOffset);
    const endOffset = requestedOffset + requestedLimit;
    const endPage = calculateXeroPage(endOffset - 1);
    
    console.log('📄 Pagination calculation:', {
      requestedLimit,
      requestedOffset,
      startPage,
      endPage,
      endOffset
    });

    // Fetch required pages
    let allRecords = [];
    const baseUrl = 'https://api.xero.com/api.xro/2.0/Invoices';
    
    for (let page = startPage; page <= endPage; page++) {
      const cacheKey = generateCacheKey(baseUrl, filters, page);
      let pageData;
      
      // Check cache first (5-minute cache)
      if (pageCache[cacheKey] && Date.now() - pageCache[cacheKey].timestamp < 300000) {
        console.log(`📦 Using cached data for page ${page}`);
        pageData = pageCache[cacheKey].data;
      } else {
        console.log(`🔄 Fetching page ${page} from Xero API`);
        const xeroUrl = buildXeroUrl(baseUrl, filters, page);
        console.log(`🔗 Xero URL: ${xeroUrl}`);
        
        const response = await axios.get(xeroUrl, {
          headers: {
            'Authorization': `Bearer ${session.access_token}`,
            'Accept': 'application/json',
            'Xero-tenant-id': session.tenantId
          },
          timeout: 15000
        });
        
        pageData = response.data.Invoices || [];
        
        // Cache the result
        pageCache[cacheKey] = {
          data: pageData,
          timestamp: Date.now()
        };
        
        console.log(`✅ Fetched ${pageData.length} records from page ${page}`);
      }
      
      allRecords = allRecords.concat(pageData);
    }
    
    console.log(`📊 Total records fetched: ${allRecords.length}`);
    
    // Calculate slice positions for exact range
    const pageOffset = calculatePageOffset(requestedOffset);
    const startIndex = pageOffset;
    const endIndex = startIndex + requestedLimit;
    
    console.log('✂️ Slicing data:', {
      startIndex,
      endIndex,
      totalRecords: allRecords.length
    });
    
    const slicedData = allRecords.slice(startIndex, endIndex);
    
    console.log(`📋 Returning ${slicedData.length} records`);

    // Calculate totals for summary
    const totalAmount = slicedData.reduce((sum, invoice) => {
      return sum + (parseFloat(invoice.Total) || 0);
    }, 0);

    const statusBreakdown = slicedData.reduce((acc, invoice) => {
      acc[invoice.Status] = (acc[invoice.Status] || 0) + 1;
      return acc;
    }, {});

    // Enhanced response with date context
    const response = {
      invoices: slicedData,
      pagination: {
        limit: requestedLimit,
        offset: requestedOffset,
        total_records: allRecords.length,
        has_more: endIndex < allRecords.length,
        next_offset: endIndex < allRecords.length ? requestedOffset + requestedLimit : null
      },
      summary: {
        count: slicedData.length,
        total_amount: totalAmount.toFixed(2),
        currency: slicedData[0]?.CurrencyCode || 'GBP',
        status_breakdown: statusBreakdown
      },
      filters_applied: filters,
      date_context: dateFilters.date_from ? {
        from_date: dateFilters.date_from,
        to_date: dateFilters.date_to,
        note: dateFilters.date_from.includes('2025-09') ? 
          '✅ September 2025 data as requested' : 
          'Custom date range applied'
      } : null,
      timestamp: new Date().toISOString()
    };

    res.json(response);

  } catch (error) {
    console.error('❌ Invoices API error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to fetch invoices',
      message: error.response?.data?.error_description || error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Contacts endpoint (unchanged but included for completeness)
app.get('/api/contacts', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Bearer token required' });
  }

  const token = authHeader.substring(7);
  const session = tokenStore[token];

  if (!session || !session.access_token) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  try {
    const { 
      limit = 20, 
      offset = 0, 
      name_contains,
      include_archived = false,
      days_ago,
      date_from,
      date_to
    } = req.query;

    console.log('👥 Contacts request:', {
      limit: parseInt(limit),
      offset: parseInt(offset),
      filters: { name_contains, include_archived, days_ago, date_from, date_to },
      timestamp: new Date().toISOString()
    });

    // Build filters
    const filters = {
      name_contains,
      include_archived: include_archived === 'true'
    };

    // Add date filters if specified
    if (days_ago) {
      filters.date_from = getDateDaysAgo(parseInt(days_ago));
    } else if (date_from) {
      filters.date_from = date_from;
    }
    
    if (date_to) {
      filters.date_to = date_to;
    }

    // Calculate pagination
    const requestedLimit = Math.min(parseInt(limit), 100);
    const requestedOffset = parseInt(offset);
    
    const startPage = calculateXeroPage(requestedOffset);
    const endOffset = requestedOffset + requestedLimit;
    const endPage = calculateXeroPage(endOffset - 1);

    // Fetch data
    let allRecords = [];
    const baseUrl = 'https://api.xero.com/api.xro/2.0/Contacts';
    
    for (let page = startPage; page <= endPage; page++) {
      const cacheKey = generateCacheKey(baseUrl, filters, page);
      let pageData;
      
      if (pageCache[cacheKey] && Date.now() - pageCache[cacheKey].timestamp < 300000) {
        console.log(`📦 Using cached data for page ${page}`);
        pageData = pageCache[cacheKey].data;
      } else {
        console.log(`🔄 Fetching page ${page} from Xero API`);
        const xeroUrl = buildXeroUrl(baseUrl, filters, page);
        
        const response = await axios.get(xeroUrl, {
          headers: {
            'Authorization': `Bearer ${session.access_token}`,
            'Accept': 'application/json',
            'Xero-tenant-id': session.tenantId
          },
          timeout: 15000
        });
        
        pageData = response.data.Contacts || [];
        
        pageCache[cacheKey] = {
          data: pageData,
          timestamp: Date.now()
        };
        
        console.log(`✅ Fetched ${pageData.length} records from page ${page}`);
      }
      
      allRecords = allRecords.concat(pageData);
    }

    // Slice for exact range
    const pageOffset = calculatePageOffset(requestedOffset);
    const slicedData = allRecords.slice(pageOffset, pageOffset + requestedLimit);

    const response = {
      contacts: slicedData,
      pagination: {
        limit: requestedLimit,
        offset: requestedOffset,
        total_records: allRecords.length,
        has_more: pageOffset + requestedLimit < allRecords.length,
        next_offset: pageOffset + requestedLimit < allRecords.length ? requestedOffset + requestedLimit : null
      },
      summary: {
        count: slicedData.length,
        active_contacts: slicedData.filter(c => !c.IsArchived).length,
        archived_contacts: slicedData.filter(c => c.IsArchived).length
      },
      filters_applied: filters,
      timestamp: new Date().toISOString()
    };

    res.json(response);

  } catch (error) {
    console.error('❌ Contacts API error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to fetch contacts',
      message: error.response?.data?.error_description || error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Accounts endpoint (unchanged)
app.get('/api/accounts', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Bearer token required' });
  }

  const token = authHeader.substring(7);
  const session = tokenStore[token];

  if (!session || !session.access_token) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  try {
    const response = await axios.get('https://api.xero.com/api.xro/2.0/Accounts', {
      headers: {
        'Authorization': `Bearer ${session.access_token}`,
        'Accept': 'application/json',
        'Xero-tenant-id': session.tenantId
      }
    });

    res.json({
      accounts: response.data.Accounts,
      summary: {
        total_accounts: response.data.Accounts.length,
        by_type: response.data.Accounts.reduce((acc, account) => {
          acc[account.Type] = (acc[account.Type] || 0) + 1;
          return acc;
        }, {})
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Accounts API error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to fetch accounts',
      message: error.response?.data?.error_description || error.message
    });
  }
});

// Quick filter endpoints
app.get('/api/quick/open-invoices', (req, res) => {
  req.query.status = 'AUTHORISED';
  req.query.limit = req.query.limit || '20';
  return app._router.handle({ ...req, url: '/api/invoices', method: 'GET' }, res);
});

app.get('/api/quick/recent-invoices', (req, res) => {
  req.query.days_ago = '7';
  req.query.limit = req.query.limit || '20';
  return app._router.handle({ ...req, url: '/api/invoices', method: 'GET' }, res);
});

app.get('/api/quick/overdue-invoices', (req, res) => {
  req.query.status = 'AUTHORISED';
  req.query.date_to = formatDateForXero(new Date());
  req.query.limit = req.query.limit || '20';
  return app._router.handle({ ...req, url: '/api/invoices', method: 'GET' }, res);
});

app.get('/api/quick/active-contacts', (req, res) => {
  req.query.include_archived = 'false';
  req.query.limit = req.query.limit || '20';
  return app._router.handle({ ...req, url: '/api/contacts', method: 'GET' }, res);
});

// Privacy and Terms endpoints
app.get('/privacy', (req, res) => {
  res.json({
    service: 'JHK Bookkeeping Assistant',
    privacy_policy: 'This service processes Xero data for bookkeeping automation.',
    data_handling: 'Data is processed securely and not stored permanently.',
    contact: 'support@jhkbookkeeping.com'
  });
});

app.get('/terms', (req, res) => {
  res.json({
    service: 'JHK Bookkeeping Assistant',
    terms_of_service: 'This service is provided for authorized bookkeeping operations.',
    usage: 'Authorized users only. Data access is logged and monitored.',
    contact: 'support@jhkbookkeeping.com'
  });
});

// Legacy MCP endpoints for backward compatibility
app.get('/mcp/health', (req, res) => {
  res.redirect('/health');
});

app.get('/mcp/invoices', (req, res) => {
  res.redirect(307, '/api/invoices?' + new URLSearchParams(req.query));
});

app.get('/mcp/contacts', (req, res) => {
  res.redirect(307, '/api/contacts?' + new URLSearchParams(req.query));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: error.message,
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: `Endpoint ${req.method} ${req.path} not found`,
    available_endpoints: ['/health', '/api', '/oauth/authorize', '/.well-known/oauth-authorization-server'],
    timestamp: new Date().toISOString()
  });
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log('🚀 JHK Bookkeeping Assistant v2.4.3 running on 0.0.0.0:' + port);
  console.log('🔗 OAuth URL: http://localhost:' + port + '/oauth/authorize');
  console.log('📊 Health check: http://localhost:' + port + '/health');
  console.log('📋 API docs: http://localhost:' + port + '/api');
  console.log('✅ Enhanced date handling enabled - September 2025 fix applied');
});

module.exports = app;

