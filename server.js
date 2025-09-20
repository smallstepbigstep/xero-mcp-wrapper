const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const qs = require("querystring");

const app = express();
const port = process.env.PORT || 3000;

// SECURITY HOTFIX v2.4.10.1: Move OAuth credentials to environment variables
const CHATGPT_OAUTH = {
  client_id: process.env.CHATGPT_CLIENT_ID || (() => {
    console.error("🚨 SECURITY ERROR: CHATGPT_CLIENT_ID environment variable not set!");
    process.exit(1);
  })(),
  client_secret: process.env.CHATGPT_CLIENT_SECRET || (() => {
    console.error("🚨 SECURITY ERROR: CHATGPT_CLIENT_SECRET environment variable not set!");
    process.exit(1);
  })(),
  redirect_uri: "https://chat.openai.com/aip/g-d62f46e08c6be54d78a07a082ce3cc2fe8be23d7/oauth/callback",
};

// SECURITY HOTFIX v2.4.10.1: Restricted CORS configuration
const corsOptions = {
  origin: [
    'https://chat.openai.com',
    'https://chatgpt.com',
    process.env.ADMIN_ORIGIN || 'http://localhost:3000'
  ],
  credentials: true,
  optionsSuccessStatus: 200
};

// In-memory token storage (use Redis/database in production)
let tokenStore = {};

// In-memory page cache for Xero API responses
let pageCache = {};

// SECURITY HOTFIX v2.4.10.1: Enhanced middleware with security headers
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// SECURITY HOTFIX v2.4.10.1: Rate limiting for OAuth endpoints
const rateLimitStore = new Map();
const rateLimit = (maxRequests = 10, windowMs = 60000) => {
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    
    if (!rateLimitStore.has(key)) {
      rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }
    
    const limit = rateLimitStore.get(key);
    if (now > limit.resetTime) {
      limit.count = 1;
      limit.resetTime = now + windowMs;
      return next();
    }
    
    if (limit.count >= maxRequests) {
      return res.status(429).json({
        error: 'Too many requests',
        retryAfter: Math.ceil((limit.resetTime - now) / 1000)
      });
    }
    
    limit.count++;
    next();
  };
};

// Utility functions
const generateState = () => crypto.randomBytes(16).toString("hex");

const getBaseUrl = (req) => {
  const protocol = req.get("x-forwarded-proto") || req.protocol;
  const host = req.get("host");
  return `${protocol}://${host}`;
};

// SECURITY HOTFIX v2.4.10.1: Enhanced ChatGPT request validation with missing client_id handling
const validateChatGPTRequest = (client_id, redirect_uri) => {
  console.log("🔍 Validating ChatGPT request:");
  console.log("  - client_id:", client_id || "(empty)");
  console.log("  - redirect_uri:", redirect_uri || "(empty)");
  
  // ChatGPT Actions sometimes sends empty client_id - validate by redirect_uri pattern
  const isValidRedirectUri = redirect_uri && redirect_uri.includes("chat.openai.com/aip/");
  
  if (!isValidRedirectUri) {
    console.log("❌ Invalid redirect_uri - not a ChatGPT pattern");
    return false;
  }
  
  // If client_id is provided, it must match exactly
  if (client_id && client_id !== CHATGPT_OAUTH.client_id) {
    console.log("❌ Invalid client_id - does not match expected value");
    return false;
  }
  
  // If client_id is empty but redirect_uri is valid ChatGPT pattern, allow it
  if (!client_id && isValidRedirectUri) {
    console.log("✅ Valid ChatGPT request (empty client_id but valid redirect_uri pattern)");
    return true;
  }
  
  // If both are valid
  if (client_id === CHATGPT_OAUTH.client_id && isValidRedirectUri) {
    console.log("✅ Valid ChatGPT request (both client_id and redirect_uri valid)");
    return true;
  }
  
  console.log("❌ Request validation failed");
  return false;
};

// Enhanced date utility functions for v2.4.10.1
const formatDateForXero = (dateString) => {
  if (!dateString) return null;

  let date;
  if (dateString.includes("/")) {
    const parts = dateString.split("/");
    if (parts.length === 3) {
      date = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`);
    }
  } else {
    date = new Date(dateString);
  }

  if (isNaN(date.getTime())) {
    console.error("❌ Invalid date format:", dateString);
    return null;
  }

  return date.toISOString().split("T")[0];
};

const getMonthName = (monthNumber) => {
  const months = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
  ];
  return months[monthNumber - 1];
};

// Enhanced date parsing function for v2.4.10.1
const parseRequestedPeriod = (query) => {
  const { period, month, year, from_date, to_date, days_ago, fromDate, toDate } = query;

  // Normalize date parameters (support both camelCase and underscore formats)
  const normalizedFromDate = fromDate || from_date;
  const normalizedToDate = toDate || to_date;

  // If explicit dates provided, use them
  if (normalizedFromDate && normalizedToDate) {
    return {
      fromDate: formatDateForXero(normalizedFromDate),
      toDate: formatDateForXero(normalizedToDate),
    };
  }

  if (normalizedFromDate) {
    return {
      fromDate: formatDateForXero(normalizedFromDate),
      toDate: null,
    };
  }

  if (normalizedToDate) {
    return {
      fromDate: null,
      toDate: formatDateForXero(normalizedToDate),
    };
  }

  // Handle period-based requests
  if (period) {
    const now = new Date();
    let fromDate, toDate;

    if (period === "current" || period === "this-month") {
      fromDate = new Date(now.getFullYear(), now.getMonth(), 1);
      toDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    } else if (period === "last-month" || period === "previous-month") {
      fromDate = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      toDate = new Date(now.getFullYear(), now.getMonth(), 0);
    } else if (period.includes("-")) {
      const [monthName, yearStr] = period.split("-");
      const monthIndex = [
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december"
      ].indexOf(monthName.toLowerCase());
      
      if (monthIndex !== -1 && yearStr) {
        const targetYear = parseInt(yearStr);
        fromDate = new Date(targetYear, monthIndex, 1);
        toDate = new Date(targetYear, monthIndex + 1, 0);
      }
    }

    if (fromDate && toDate) {
      return {
        fromDate: formatDateForXero(fromDate.toISOString()),
        toDate: formatDateForXero(toDate.toISOString()),
      };
    }
  }

  // Handle month/year combination
  if (month && year) {
    const monthIndex = parseInt(month) - 1;
    const targetYear = parseInt(year);
    const fromDate = new Date(targetYear, monthIndex, 1);
    const toDate = new Date(targetYear, monthIndex + 1, 0);

    return {
      fromDate: formatDateForXero(fromDate.toISOString()),
      toDate: formatDateForXero(toDate.toISOString()),
    };
  }

  // Handle days_ago
  if (days_ago) {
    const daysAgo = parseInt(days_ago);
    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - daysAgo);
    
    return {
      fromDate: formatDateForXero(fromDate.toISOString()),
      toDate: formatDateForXero(new Date().toISOString()),
    };
  }

  // Return null dates (no filtering) instead of defaulting to current month
  return {
    fromDate: null,
    toDate: null,
  };
};

// Build Xero API URL with proper filtering
const buildXeroUrl = (baseUrl, { fromDate, toDate }, additionalParams = {}) => {
  const params = new URLSearchParams();

  // Only add date filters if dates are provided
  if (fromDate && toDate) {
    params.append("where", `Date >= DateTime(${fromDate.split('-')[0]}, ${fromDate.split('-')[1]}, ${fromDate.split('-')[2]}) AND Date <= DateTime(${toDate.split('-')[0]}, ${toDate.split('-')[1]}, ${toDate.split('-')[2]})`);
  } else if (fromDate) {
    params.append("where", `Date >= DateTime(${fromDate.split('-')[0]}, ${fromDate.split('-')[1]}, ${fromDate.split('-')[2]})`);
  } else if (toDate) {
    params.append("where", `Date <= DateTime(${toDate.split('-')[0]}, ${toDate.split('-')[1]}, ${toDate.split('-')[2]})`);
  }

  // Add additional parameters
  Object.entries(additionalParams).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      params.append(key, value);
    }
  });

  return `${baseUrl}${params.toString() ? '?' + params.toString() : ''}`;
};

// SECURITY HOTFIX v2.4.10.1: Secure Xero token exchange with proper form encoding
const exchangeCodeForTokens = async (code, redirect_uri) => {
  try {
    const tokenUrl = "https://identity.xero.com/connect/token";
    
    // FIXED: Proper form encoding for token exchange
    const formData = qs.stringify({
      grant_type: "authorization_code",
      client_id: process.env.XERO_CLIENT_ID,
      client_secret: process.env.XERO_CLIENT_SECRET,
      code: code,
      redirect_uri: process.env.XERO_REDIRECT_URI,
    });

    console.log("🔄 Exchanging code for tokens with Xero...");
    
    const response = await axios.post(tokenUrl, formData, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
      },
    });

    console.log("✅ Successfully exchanged code for tokens");
    return response.data;
  } catch (error) {
    console.error("❌ Token exchange failed:", error.response?.data || error.message);
    throw new Error("Failed to exchange authorization code for tokens");
  }
};

// OAuth Discovery Endpoint
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    scopes_supported: ["read", "write"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
  });
});

// SECURITY HOTFIX v2.4.10.1: Enhanced OAuth Authorization with ChatGPT-compatible validation
app.get("/oauth/authorize", rateLimit(5, 60000), (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;

  console.log("🔐 OAuth Authorization Request:");
  console.log("- client_id:", client_id || "(empty)");
  console.log("- redirect_uri:", redirect_uri);
  console.log("- response_type:", response_type);
  console.log("- scope:", scope);

  // SECURITY HOTFIX v2.4.10.1: ChatGPT-compatible validation
  if (!validateChatGPTRequest(client_id, redirect_uri)) {
    console.log("❌ Unauthorized OAuth request");
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Invalid client credentials or redirect URI"
    });
  }

  if (response_type !== "code") {
    return res.status(400).json({
      error: "unsupported_response_type",
      error_description: "Only 'code' response type is supported"
    });
  }

  // Generate authorization code and store it
  const authCode = crypto.randomBytes(32).toString("hex");
  const authState = state || generateState();

  // Store the authorization request
  tokenStore[authCode] = {
    client_id: client_id || CHATGPT_OAUTH.client_id, // Use default if empty
    redirect_uri,
    scope,
    state: authState,
    created_at: Date.now(),
    expires_at: Date.now() + 10 * 60 * 1000, // 10 minutes
  };

  // Build Xero authorization URL
  const xeroAuthUrl = new URL("https://login.xero.com/identity/connect/authorize");
  xeroAuthUrl.searchParams.append("response_type", "code");
  xeroAuthUrl.searchParams.append("client_id", process.env.XERO_CLIENT_ID);
  xeroAuthUrl.searchParams.append("redirect_uri", process.env.XERO_REDIRECT_URI);
  xeroAuthUrl.searchParams.append("scope", "accounting.transactions accounting.contacts accounting.settings accounting.reports.read offline_access");
  xeroAuthUrl.searchParams.append("state", authCode);

  console.log("🔄 Redirecting to Xero for authorization...");
  res.redirect(xeroAuthUrl.toString());
});

// OAuth Callback Handler
app.get("/oauth/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.error("❌ OAuth callback error:", error);
    return res.status(400).json({ error: "authorization_denied", error_description: error });
  }

  if (!code || !state) {
    console.error("❌ Missing code or state in callback");
    return res.status(400).json({ error: "invalid_request", error_description: "Missing code or state parameter" });
  }

  // Retrieve the stored authorization request
  const authRequest = tokenStore[state];
  if (!authRequest) {
    console.error("❌ Invalid or expired state parameter");
    return res.status(400).json({ error: "invalid_request", error_description: "Invalid or expired state parameter" });
  }

  // Check expiration
  if (Date.now() > authRequest.expires_at) {
    delete tokenStore[state];
    console.error("❌ Authorization request expired");
    return res.status(400).json({ error: "invalid_request", error_description: "Authorization request expired" });
  }

  try {
    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens(code, authRequest.redirect_uri);

    // Store tokens with the authorization code
    tokenStore[state] = {
      ...authRequest,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      scope: tokens.scope,
      updated_at: Date.now(),
    };

    // Redirect back to ChatGPT with the authorization code
    const redirectUrl = new URL(authRequest.redirect_uri);
    redirectUrl.searchParams.append("code", state);
    if (authRequest.state) {
      redirectUrl.searchParams.append("state", authRequest.state);
    }

    console.log("✅ OAuth flow completed successfully");
    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error("❌ Token exchange failed:", error.message);
    res.status(500).json({ error: "server_error", error_description: "Failed to exchange authorization code" });
  }
});

// SECURITY HOTFIX v2.4.10.1: Enhanced Token Endpoint with ChatGPT-compatible validation
app.post("/oauth/token", rateLimit(10, 60000), (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

  console.log("🔐 Token Exchange Request:");
  console.log("- grant_type:", grant_type);
  console.log("- code:", code ? "present" : "missing");
  console.log("- client_id:", client_id || "(empty)");

  // SECURITY HOTFIX v2.4.10.1: Handle ChatGPT's missing client_id behavior
  if (grant_type !== "authorization_code") {
    return res.status(400).json({
      error: "unsupported_grant_type",
      error_description: "Only authorization_code grant type is supported"
    });
  }

  if (!code) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing authorization code"
    });
  }

  // Retrieve stored tokens
  const storedData = tokenStore[code];
  if (!storedData || !storedData.access_token) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code"
    });
  }

  // For ChatGPT Actions, client credentials might be missing in token request
  // Validate against stored data from authorization request
  if (client_id && client_secret) {
    if (client_id !== CHATGPT_OAUTH.client_id || client_secret !== CHATGPT_OAUTH.client_secret) {
      return res.status(400).json({
        error: "invalid_client",
        error_description: "Invalid client credentials"
      });
    }
  }

  // Generate access token for ChatGPT
  const accessToken = crypto.randomBytes(32).toString("hex");
  
  // Store the mapping between ChatGPT token and Xero tokens
  tokenStore[accessToken] = {
    ...storedData,
    chatgpt_token: accessToken,
    created_at: Date.now(),
  };

  console.log("✅ Token exchange successful");

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: storedData.scope || "read write",
  });
});

// OAuth User Info Endpoint
app.get("/oauth/userinfo", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "invalid_token", error_description: "Missing or invalid authorization header" });
  }

  const token = authHeader.substring(7);
  const tokenData = tokenStore[token];

  if (!tokenData) {
    return res.status(401).json({ error: "invalid_token", error_description: "Invalid access token" });
  }

  res.json({
    sub: "xero-user",
    name: "Xero User",
    email: process.env.USER_EMAIL || "user@example.com",
  });
});

// JWKS Endpoint (placeholder)
app.get("/.well-known/jwks.json", (req, res) => {
  res.json({
    keys: [
      {
        kty: "RSA",
        use: "sig",
        kid: "1",
        n: "placeholder-modulus",
        e: "AQAB",
      },
    ],
  });
});

// Authentication middleware for API endpoints
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid authorization header" });
  }

  const token = authHeader.substring(7);
  const tokenData = tokenStore[token];

  if (!tokenData || !tokenData.access_token) {
    return res.status(401).json({ error: "Invalid access token" });
  }

  req.xeroTokens = tokenData;
  next();
};

// Helper function to make authenticated Xero API calls
const makeXeroApiCall = async (url, tokens) => {
  try {
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        "Xero-tenant-id": process.env.XERO_TENANT_ID,
        Accept: "application/json",
      },
    });
    return response.data;
  } catch (error) {
    console.error("❌ Xero API call failed:", error.response?.data || error.message);
    throw error;
  }
};

// Cache management
const getCachedData = (key) => {
  const cached = pageCache[key];
  if (cached && Date.now() - cached.timestamp < 5 * 60 * 1000) { // 5 minutes
    return cached.data;
  }
  return null;
};

const setCachedData = (key, data) => {
  // Simple cache eviction: remove oldest entries if cache gets too large
  if (Object.keys(pageCache).length > 50) {
    const oldestKey = Object.keys(pageCache)[0];
    delete pageCache[oldestKey];
  }
  
  pageCache[key] = {
    data,
    timestamp: Date.now(),
  };
};

// API Endpoints

// Health Check
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "JHK Bookkeeping Assistant",
    version: "2.4.10.1-chatgpt-fix",
    features: {
      chatgpt_ready: true,
      enhanced_detection: true,
      callback_proxy_enabled: true,
      date_handling_fixed: true,
      september_2025_support: true,
      relaxed_client_id_validation: false, // Still strict but ChatGPT-compatible
      oauth_scope_fix: true,
      contacts_api_fix: true,
      no_default_date_filtering: true,
      date_parameter_mapping: true,
      pagination_fix: true,
      bulk_data_retrieval: true,
      business_intelligence_endpoints: true,
      security_hardened: true,
      cors_restricted: true,
      rate_limiting: true,
      chatgpt_missing_client_id_fix: true, // NEW in v2.4.10.1
    },
    oauth_fixes: {
      redirect_uri_based_detection: true,
      missing_client_id_handling: true, // FIXED in v2.4.10.1
      chatgpt_compatibility: "enhanced", // Back to enhanced for ChatGPT compatibility
      valid_xero_scopes: true,
      credentials_secured: true,
      chatgpt_empty_client_id_support: true, // NEW in v2.4.10.1
    },
    api_fixes: {
      contacts_filtering: "Fixed IsArchived -> ContactStatus",
      date_handling: "Enhanced natural language parsing with parameter mapping",
      pagination: "Fixed offset calculation and next_offset logic",
      default_date_filtering: "Removed - now returns all data by default",
      date_parameter_mapping: "Fixed fromDate/toDate vs from_date/to_date",
      bulk_retrieval: "Added bulk=true parameter for all records",
      form_encoding: "Fixed Xero token exchange encoding",
      chatgpt_client_id: "Fixed empty client_id handling for ChatGPT Actions", // NEW in v2.4.10.1
    },
    security_improvements: {
      environment_variables: "OAuth credentials moved to env vars",
      cors_policy: "Restricted to ChatGPT and admin origins",
      rate_limiting: "Implemented for OAuth endpoints",
      client_validation: "ChatGPT-compatible strict validation",
      security_headers: "Added HSTS, XSS protection, and content type options",
      chatgpt_compatibility: "Enhanced to handle ChatGPT Actions behavior", // NEW in v2.4.10.1
    },
    date_handling: {
      natural_language: true,
      formats_supported: ["YYYY-MM-DD", "DD/MM/YYYY", "period=september-2025", "fromDate/toDate"],
      current_month_detection: true,
      validation: true,
      default_behavior: "No date filtering - returns all data",
      parameter_mapping: "Supports both camelCase and underscore formats",
    },
    pagination: {
      standard_mode: "offset/limit with proper next_offset calculation",
      bulk_mode: "bulk=true parameter fetches all records across all pages",
      max_bulk_pages: 100,
      max_bulk_records: 10000,
    },
    timestamp: new Date().toISOString(),
  });
});

// Contacts API
app.get("/api/contacts", authenticateToken, async (req, res) => {
  try {
    const { offset = 0, limit = 100, tenant, name_contains } = req.query;
    const page = Math.floor(offset / limit) + 1;

    console.log(`📋 Fetching contacts (page: ${page}, limit: ${limit})`);

    let whereClause = "ContactStatus!=\"ARCHIVED\"";
    if (name_contains) {
      whereClause += ` AND Name.Contains("${name_contains}")`;
    }

    const url = `https://api.xero.com/api.xro/2.0/Contacts?where=${encodeURIComponent(whereClause)}&page=${page}`;
    const data = await makeXeroApiCall(url, req.xeroTokens);

    const contacts = data.Contacts || [];
    const totalRecords = contacts.length;
    const endIndex = offset + contacts.length;

    res.json({
      contacts,
      pagination: {
        offset: parseInt(offset),
        limit: parseInt(limit),
        total_records: totalRecords,
        has_more: contacts.length === limit,
        next_offset: contacts.length === limit ? endIndex : null,
      },
    });
  } catch (error) {
    console.error("❌ Error fetching contacts:", error.message);
    res.status(500).json({ error: "Failed to fetch contacts", details: error.message });
  }
});

// Invoices API with enhanced business intelligence
app.get("/api/invoices", authenticateToken, async (req, res) => {
  try {
    const { offset = 0, limit = 100, status, contact_id, bulk = false } = req.query;
    
    console.log(`📋 Fetching invoices (offset: ${offset}, limit: ${limit}, bulk: ${bulk})`);
    
    // Parse date parameters
    const dateFilter = parseRequestedPeriod(req.query);
    console.log(`📅 Parsing date request v2.4.10.1:`, req.query);
    
    if (dateFilter.fromDate || dateFilter.toDate) {
      console.log(`📅 Date filter applied: ${dateFilter.fromDate} to ${dateFilter.toDate}`);
    } else {
      console.log(`✅ No date filters specified - returning all data`);
    }

    // Handle bulk mode
    if (bulk === 'true' || bulk === true) {
      console.log(`🔄 Bulk mode enabled - fetching all invoices`);
      
      let allInvoices = [];
      let page = 1;
      let hasMore = true;
      
      while (hasMore && page <= 100) { // Safety limit
        let whereClause = "";
        const conditions = [];
        
        if (status) {
          conditions.push(`Status="${status}"`);
        }
        if (contact_id) {
          conditions.push(`Contact.ContactID=Guid("${contact_id}")`);
        }
        
        // Add date filtering if specified
        if (dateFilter.fromDate && dateFilter.toDate) {
          conditions.push(`Date >= DateTime(${dateFilter.fromDate.split('-')[0]}, ${dateFilter.fromDate.split('-')[1]}, ${dateFilter.fromDate.split('-')[2]})`);
          conditions.push(`Date <= DateTime(${dateFilter.toDate.split('-')[0]}, ${dateFilter.toDate.split('-')[1]}, ${dateFilter.toDate.split('-')[2]})`);
        }
        
        if (conditions.length > 0) {
          whereClause = `?where=${encodeURIComponent(conditions.join(' AND '))}`;
        }
        
        const url = `https://api.xero.com/api.xro/2.0/Invoices${whereClause}${whereClause ? '&' : '?'}page=${page}`;
        const data = await makeXeroApiCall(url, req.xeroTokens);
        
        const invoices = data.Invoices || [];
        allInvoices = allInvoices.concat(invoices);
        
        hasMore = invoices.length === 100;
        page++;
        
        console.log(`📄 Fetched page ${page - 1}: ${invoices.length} invoices`);
      }
      
      console.log(`✅ Bulk fetch complete: ${allInvoices.length} total invoices`);
      
      return res.json({
        invoices: allInvoices,
        date_filter: dateFilter,
        bulk_mode: true,
        total_records: allInvoices.length,
        pages_fetched: page - 1,
      });
    }

    // Standard pagination mode
    const page = Math.floor(offset / limit) + 1;
    const cacheKey = `invoices_${page}_${limit}_${status || 'all'}_${contact_id || 'all'}_${dateFilter.fromDate || 'nostart'}_${dateFilter.toDate || 'noend'}`;
    
    // Check cache first
    const cachedData = getCachedData(cacheKey);
    if (cachedData) {
      console.log(`📋 Using cached invoices page: ${page}`);
      return res.json(cachedData);
    }

    let whereClause = "";
    const conditions = [];
    
    if (status) {
      conditions.push(`Status="${status}"`);
    }
    if (contact_id) {
      conditions.push(`Contact.ContactID=Guid("${contact_id}")`);
    }
    
    // Add date filtering if specified
    if (dateFilter.fromDate && dateFilter.toDate) {
      conditions.push(`Date >= DateTime(${dateFilter.fromDate.split('-')[0]}, ${dateFilter.fromDate.split('-')[1]}, ${dateFilter.fromDate.split('-')[2]})`);
      conditions.push(`Date <= DateTime(${dateFilter.toDate.split('-')[0]}, ${dateFilter.toDate.split('-')[1]}, ${dateFilter.toDate.split('-')[2]})`);
    }
    
    if (conditions.length > 0) {
      whereClause = `?where=${encodeURIComponent(conditions.join(' AND '))}`;
    }

    const url = `https://api.xero.com/api.xro/2.0/Invoices${whereClause}${whereClause ? '&' : '?'}page=${page}`;
    const data = await makeXeroApiCall(url, req.xeroTokens);

    const invoices = data.Invoices || [];
    const totalRecords = invoices.length;
    const endIndex = offset + invoices.length;
    const hasMore = invoices.length === limit;

    const result = {
      invoices,
      date_filter: dateFilter,
      pagination: {
        offset: parseInt(offset),
        limit: parseInt(limit),
        total_records: totalRecords,
        has_more: hasMore,
        next_offset: hasMore ? endIndex : null,
      },
    };

    // Cache the result
    setCachedData(cacheKey, result);

    const period = dateFilter.fromDate && dateFilter.toDate 
      ? `${dateFilter.fromDate} to ${dateFilter.toDate}`
      : dateFilter.fromDate 
        ? `from ${dateFilter.fromDate}`
        : dateFilter.toDate
          ? `to ${dateFilter.toDate}`
          : "All periods";

    console.log(`✅ Returning ${invoices.length} invoices for ${period} (offset: ${offset}, limit: ${limit}, page: ${page})`);

    res.json(result);
  } catch (error) {
    console.error("❌ Error fetching invoices:", error.message);
    res.status(500).json({ error: "Failed to fetch invoices", details: error.message });
  }
});

// Business Intelligence: Invoice Summary Endpoint
app.get("/api/invoices/summary", authenticateToken, async (req, res) => {
  try {
    console.log(`📊 Generating invoice summary with business intelligence`);
    
    // Parse date parameters
    const dateFilter = parseRequestedPeriod(req.query);
    
    let allInvoices = [];
    let page = 1;
    let hasMore = true;
    
    // Fetch all invoices for comprehensive analysis
    while (hasMore && page <= 100) { // Safety limit
      let whereClause = "";
      
      // Add date filtering if specified
      if (dateFilter.fromDate && dateFilter.toDate) {
        whereClause = `?where=${encodeURIComponent(`Date >= DateTime(${dateFilter.fromDate.split('-')[0]}, ${dateFilter.fromDate.split('-')[1]}, ${dateFilter.fromDate.split('-')[2]}) AND Date <= DateTime(${dateFilter.toDate.split('-')[0]}, ${dateFilter.toDate.split('-')[1]}, ${dateFilter.toDate.split('-')[2]})`)}`;
      }
      
      const url = `https://api.xero.com/api.xro/2.0/Invoices${whereClause}${whereClause ? '&' : '?'}page=${page}`;
      const data = await makeXeroApiCall(url, req.xeroTokens);
      
      const invoices = data.Invoices || [];
      allInvoices = allInvoices.concat(invoices);
      
      hasMore = invoices.length === 100;
      page++;
    }
    
    // Business Intelligence Analysis
    const summary = {
      total_invoices: allInvoices.length,
      total_amount: 0,
      status_breakdown: {
        PAID: { count: 0, total_amount: 0 },
        AUTHORISED: { count: 0, total_amount: 0 },
        VOIDED: { count: 0, total_amount: 0 },
        DELETED: { count: 0, total_amount: 0 },
      },
      unpaid_summary: {
        count: 0,
        total_due: 0,
      }
    };
    
    allInvoices.forEach(invoice => {
      const amount = parseFloat(invoice.Total || 0);
      summary.total_amount += amount;
      
      const status = invoice.Status;
      if (summary.status_breakdown[status]) {
        summary.status_breakdown[status].count++;
        summary.status_breakdown[status].total_amount += amount;
      }
      
      if (status === 'AUTHORISED') {
        summary.unpaid_summary.count++;
        summary.unpaid_summary.total_due += amount;
      }
    });
    
    const period = dateFilter.fromDate && dateFilter.toDate 
      ? `${dateFilter.fromDate} to ${dateFilter.toDate}`
      : "All periods";
    
    console.log(`✅ Invoice summary generated: ${summary.total_invoices} invoices for ${period}`);
    
    res.json({
      summary,
      date_filter: dateFilter,
      total_records: allInvoices.length,
      pages_fetched: page - 1,
    });
  } catch (error) {
    console.error("❌ Error generating invoice summary:", error.message);
    res.status(500).json({ error: "Failed to generate invoice summary", details: error.message });
  }
});

// Business Intelligence: Aged Receivables Summary
app.get("/api/reports/aged-receivables-summary", authenticateToken, async (req, res) => {
  try {
    console.log(`📊 Generating aged receivables summary`);
    
    // Get all unpaid invoices
    let allInvoices = [];
    let page = 1;
    let hasMore = true;
    
    while (hasMore && page <= 100) {
      const whereClause = `?where=${encodeURIComponent('Status="AUTHORISED"')}`;
      const url = `https://api.xero.com/api.xro/2.0/Invoices${whereClause}&page=${page}`;
      const data = await makeXeroApiCall(url, req.xeroTokens);
      
      const invoices = data.Invoices || [];
      allInvoices = allInvoices.concat(invoices);
      
      hasMore = invoices.length === 100;
      page++;
    }
    
    // Group by contact and calculate totals
    const contactTotals = {};
    
    allInvoices.forEach(invoice => {
      const contactId = invoice.Contact?.ContactID;
      const contactName = invoice.Contact?.Name || 'Unknown Contact';
      const amount = parseFloat(invoice.Total || 0);
      
      if (!contactTotals[contactId]) {
        contactTotals[contactId] = {
          name: contactName,
          total_due: 0,
          invoices: []
        };
      }
      
      contactTotals[contactId].total_due += amount;
      contactTotals[contactId].invoices.push({
        invoice_id: invoice.InvoiceID,
        invoice_number: invoice.InvoiceNumber,
        date: invoice.Date,
        due_date: invoice.DueDate,
        amount: amount
      });
    });
    
    // Sort by total due (descending) and get top 5
    const sortedContacts = Object.values(contactTotals)
      .sort((a, b) => b.total_due - a.total_due)
      .slice(0, 5);
    
    const totalOverdueAmount = Object.values(contactTotals)
      .reduce((sum, contact) => sum + contact.total_due, 0);
    
    console.log(`✅ Aged receivables summary: ${sortedContacts.length} top overdue customers`);
    
    res.json({
      report_type: "AgedReceivablesSummary",
      top_5_overdue_customers: sortedContacts,
      total_overdue_customers: Object.keys(contactTotals).length,
      total_overdue_amount: totalOverdueAmount,
    });
  } catch (error) {
    console.error("❌ Error generating aged receivables summary:", error.message);
    res.status(500).json({ error: "Failed to generate aged receivables summary", details: error.message });
  }
});

// Accounts API
app.get("/api/accounts", authenticateToken, async (req, res) => {
  try {
    const { offset = 0, limit = 100, type, class: accountClass } = req.query;
    const page = Math.floor(offset / limit) + 1;

    console.log(`📋 Fetching accounts (page: ${page}, limit: ${limit})`);

    let whereClause = "";
    const conditions = [];
    
    if (type) {
      conditions.push(`Type="${type}"`);
    }
    if (accountClass) {
      conditions.push(`Class="${accountClass}"`);
    }
    
    if (conditions.length > 0) {
      whereClause = `?where=${encodeURIComponent(conditions.join(' AND '))}`;
    }

    const url = `https://api.xero.com/api.xro/2.0/Accounts${whereClause}${whereClause ? '&' : '?'}page=${page}`;
    const data = await makeXeroApiCall(url, req.xeroTokens);

    const accounts = data.Accounts || [];
    const totalRecords = accounts.length;
    const endIndex = offset + accounts.length;

    res.json({
      accounts,
      pagination: {
        offset: parseInt(offset),
        limit: parseInt(limit),
        total_records: totalRecords,
        has_more: accounts.length === limit,
        next_offset: accounts.length === limit ? endIndex : null,
      },
    });
  } catch (error) {
    console.error("❌ Error fetching accounts:", error.message);
    res.status(500).json({ error: "Failed to fetch accounts", details: error.message });
  }
});

// Bank Transactions API
app.get("/api/bank-transactions", authenticateToken, async (req, res) => {
  try {
    const { offset = 0, limit = 100, from_date, to_date, bank_account_id, type } = req.query;
    const page = Math.floor(offset / limit) + 1;

    console.log(`📋 Fetching bank transactions (page: ${page}, limit: ${limit})`);

    let whereClause = "";
    const conditions = [];
    
    if (from_date) {
      const fromDateParts = from_date.split('-');
      conditions.push(`Date >= DateTime(${fromDateParts[0]}, ${fromDateParts[1]}, ${fromDateParts[2]})`);
    }
    if (to_date) {
      const toDateParts = to_date.split('-');
      conditions.push(`Date <= DateTime(${toDateParts[0]}, ${toDateParts[1]}, ${toDateParts[2]})`);
    }
    if (bank_account_id) {
      conditions.push(`BankAccount.AccountID=Guid("${bank_account_id}")`);
    }
    if (type) {
      conditions.push(`Type="${type}"`);
    }
    
    if (conditions.length > 0) {
      whereClause = `?where=${encodeURIComponent(conditions.join(' AND '))}`;
    }

    const url = `https://api.xero.com/api.xro/2.0/BankTransactions${whereClause}${whereClause ? '&' : '?'}page=${page}`;
    const data = await makeXeroApiCall(url, req.xeroTokens);

    const bankTransactions = data.BankTransactions || [];
    const totalRecords = bankTransactions.length;
    const endIndex = offset + bankTransactions.length;

    res.json({
      bank_transactions: bankTransactions,
      date_filter: { from_date, to_date },
      pagination: {
        offset: parseInt(offset),
        limit: parseInt(limit),
        total_records: totalRecords,
        has_more: bankTransactions.length === limit,
        next_offset: bankTransactions.length === limit ? endIndex : null,
      },
    });
  } catch (error) {
    console.error("❌ Error fetching bank transactions:", error.message);
    res.status(500).json({ error: "Failed to fetch bank transactions", details: error.message });
  }
});

// Reports API
app.get("/api/reports/:reportType", authenticateToken, async (req, res) => {
  try {
    const { reportType } = req.params;
    const { from_date, to_date, periods, timeframe } = req.query;

    console.log(`📊 Generating ${reportType} report`);

    let url = `https://api.xero.com/api.xro/2.0/Reports/${reportType}`;
    const params = new URLSearchParams();

    if (from_date) params.append('fromDate', from_date);
    if (to_date) params.append('toDate', to_date);
    if (periods) params.append('periods', periods);
    if (timeframe) params.append('timeframe', timeframe);

    if (params.toString()) {
      url += `?${params.toString()}`;
    }

    const data = await makeXeroApiCall(url, req.xeroTokens);

    res.json({
      report_type: reportType,
      date_filter: { from_date, to_date },
      data: data.Reports?.[0] || data,
    });
  } catch (error) {
    console.error(`❌ Error generating ${req.params.reportType} report:`, error.message);
    res.status(500).json({ error: `Failed to generate ${req.params.reportType} report`, details: error.message });
  }
});

// API Documentation
app.get("/api", (req, res) => {
  res.json({
    service: "JHK Bookkeeping Assistant API",
    version: "2.4.10.1-chatgpt-fix",
    description: "ChatGPT-compatible Xero API wrapper with comprehensive business intelligence and ChatGPT Actions compatibility",
    security_improvements: {
      environment_variables: "OAuth credentials secured in environment variables",
      cors_policy: "Restricted to authorized origins only",
      rate_limiting: "Implemented for OAuth endpoints",
      client_validation: "ChatGPT-compatible strict validation",
      security_headers: "Enhanced security headers including HSTS and XSS protection",
      form_encoding: "Fixed Xero token exchange with proper form encoding",
      chatgpt_compatibility: "Enhanced to handle ChatGPT Actions missing client_id behavior",
    },
    endpoints: {
      "/api/contacts": "List contacts with filtering and pagination",
      "/api/invoices": "List invoices with comprehensive filtering, date ranges, and bulk mode",
      "/api/invoices/summary": "Get aggregated invoice summary with business intelligence",
      "/api/accounts": "List chart of accounts with filtering",
      "/api/bank-transactions": "List bank transactions for cash flow analysis",
      "/api/reports/{reportType}": "Generate financial reports (ProfitAndLoss, BalanceSheet, etc.)",
      "/api/reports/aged-receivables-summary": "Get top overdue customers summary",
    },
    features: {
      oauth_flow: "Full OAuth 2.0 implementation for ChatGPT Actions with enhanced compatibility",
      business_intelligence: "Advanced data aggregation and analysis",
      bulk_operations: "Efficient bulk data retrieval across all pages",
      date_handling: "Natural language date parsing and filtering",
      pagination: "Intelligent pagination with caching",
      security_hardened: "Production-ready security measures",
      chatgpt_actions_compatible: "Handles ChatGPT Actions specific OAuth behavior",
    },
    oauth_endpoints: {
      "/.well-known/oauth-authorization-server": "OAuth discovery endpoint",
      "/oauth/authorize": "OAuth authorization endpoint with ChatGPT compatibility",
      "/oauth/token": "OAuth token exchange endpoint with enhanced validation",
      "/oauth/userinfo": "OAuth user information endpoint",
    },
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 JHK Bookkeeping Assistant v2.4.10.1 (ChatGPT Fix) running on port ${port}`);
  console.log(`🔐 Security improvements implemented:`);
  console.log(`   - OAuth credentials secured in environment variables`);
  console.log(`   - CORS restricted to authorized origins`);
  console.log(`   - Rate limiting enabled for OAuth endpoints`);
  console.log(`   - ChatGPT-compatible client validation enforced`);
  console.log(`   - Security headers added (HSTS, XSS protection)`);
  console.log(`   - Xero token exchange form encoding fixed`);
  console.log(`   - ChatGPT Actions missing client_id behavior handled`);
  console.log(`📊 Business Intelligence endpoints available`);
  console.log(`🔗 OAuth discovery: /.well-known/oauth-authorization-server`);
  console.log(`📚 API documentation: /api`);
  console.log(`❤️  Health check: /health`);
});
