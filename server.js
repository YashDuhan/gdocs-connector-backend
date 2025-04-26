require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// Determine if running in production (Vercel) or development
const isProduction = process.env.NODE_ENV === 'production';
const FRONTEND_URL = isProduction 
  ? process.env.FRONTEND_URL || 'https://dataviz-frontend.vercel.app' 
  : 'http://localhost:3000';

// Additional allowed origins for development and testing
const ALLOWED_ORIGINS = [
  FRONTEND_URL,
  'http://localhost:3000',
  'https://dataviz-frontend.vercel.app'
];

// Dynamic frontend URL based on request origin
const getFrontendUrl = (req) => {
  const origin = req.headers.origin;
  // If request comes from one of our allowed origins, use that as the frontend URL
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    return origin;
  }
  // Otherwise fall back to the configured FRONTEND_URL
  return FRONTEND_URL;
};

// Path for storing tokens
const TOKEN_PATH = path.join(__dirname, 'tokens.json');

// Middleware
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Handle preflight OPTIONS requests
app.options('*', cors());

// Add CORS headers to all responses
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  } else {
    res.header('Access-Control-Allow-Origin', FRONTEND_URL);
  }
  
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  next();
});

// Determine base URL for the backend (for OAuth callback)
const getBaseUrl = (req) => {
  if (isProduction) {
    // Use X-Forwarded-Host header on Vercel or fallback to a configured URL
    const host = req.headers['x-forwarded-host'] || process.env.VERCEL_URL;
    return host ? `https://${host}` : process.env.BACKEND_URL || 'https://your-backend-app.vercel.app';
  }
  return `http://localhost:${PORT}`;
};

// OAuth2 setup - dynamic redirect URI based on environment
const getRedirectUri = (req) => {
  return process.env.REDIRECT_URI || `${getBaseUrl(req)}/auth/google/callback`;
};

// Create OAuth client - will be initialized per-request
const createOAuthClient = (req) => {
  const redirectUri = getRedirectUri(req);
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    redirectUri
  );
};

// Scopes for Google Docs access
const SCOPES = [
  'https://www.googleapis.com/auth/documents.readonly',
  'https://www.googleapis.com/auth/drive.readonly'
];

// Store tokens globally (in a real app, you'd use a database)
let googleTokens = null;

// Load tokens from file if available (only works in development)
try {
  if (!isProduction && fs.existsSync(TOKEN_PATH)) {
    const tokenData = fs.readFileSync(TOKEN_PATH, 'utf8');
    googleTokens = JSON.parse(tokenData);
    console.log('Loaded tokens from file');
  } else {
    console.log('No saved tokens found or running in production');
  }
} catch (error) {
  console.error('Error loading tokens from file:', error.message);
}

// Function to save tokens to file (only in development)
function saveTokens(tokens) {
  try {
    // In production (serverless), we can't rely on file storage
    if (isProduction) {
      console.log('Running in production, skipping token file save');
      return;
    }
    
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
    console.log('Tokens saved to file');
  } catch (error) {
    console.error('Error saving tokens to file:', error.message);
  }
}

// Authentication middleware to get token from either:
// 1. From the authorization header (Bearer token)
// 2. From the global googleTokens variable
// This allows us to support both frontend-managed tokens and backend-managed tokens
const authMiddleware = async (req, res, next) => {
  try {
    // Check for Authorization header first
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      // Use the token from the Authorization header
      const token = authHeader.substring(7); // Remove 'Bearer ' prefix
      
      if (!token) {
        console.log('Empty bearer token');
        return useGlobalToken();
      }
      
      // Create OAuth client and set credentials
      const auth = createOAuthClient(req);
      auth.setCredentials({ access_token: token });
      
      // Set auth client on request
      req.auth = auth;
      return next();
    } else {
      // No Authorization header, use global token
      return useGlobalToken();
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    return useGlobalToken();
  }
  
  // Helper function to use global token if available
  function useGlobalToken() {
    if (!googleTokens) {
      // No global token available
      return res.status(401).json({ 
        error: 'Authentication required', 
        redirectUrl: '/auth/google?origin=frontend'
      });
    }
    
    // Create OAuth client with the global token
    const auth = createOAuthClient(req);
    auth.setCredentials(googleTokens);
    req.auth = auth;
    next();
  }
};

// Token refresh helper function
async function getAuthClientWithRefresh(req) {
  // If auth was already set by middleware, use it
  if (req.auth) {
    return req.auth;
  }
  
  const auth = createOAuthClient(req);
  
  if (!googleTokens) {
    return null;
  }
  
  // Set the credentials
  auth.setCredentials(googleTokens);
  
  // Check if the access token is expired or about to expire (within 5 minutes)
  const now = Date.now();
  const expiryDate = googleTokens.expiry_date;
  
  if (expiryDate && now >= expiryDate - 5 * 60 * 1000) {
    try {
      console.log('Token expired or about to expire, refreshing...');
      // This will use the refresh token to get a new access token
      const { credentials } = await auth.refreshAccessToken();
      googleTokens = credentials;
      auth.setCredentials(googleTokens);
      
      // Save the refreshed tokens to file
      saveTokens(googleTokens);
      
      console.log('Token refreshed successfully');
    } catch (error) {
      console.error('Error refreshing token:', error.message);
      // If refresh fails, we'll continue with the existing token
      // It might still work, or the API call will fail and the user will need to re-auth
    }
  }
  
  return auth;
}

// Routes
app.get('/', (req, res) => {
  res.send(`
    <h1>Google Docs Direct Integration</h1>
    <p>A simple API for directly accessing Google Docs data.</p>
    <a href="/auth/google">Connect Google Docs</a>
  `);
});

// OAuth routes
app.get('/auth/google', (req, res) => {
  // Add origin query param to track where the request came from
  const origin = req.query.origin || 'backend';
  
  const oauth2Client = createOAuthClient(req);
  const redirectUri = getRedirectUri(req);
  console.log(`Starting OAuth flow with redirect URI: ${redirectUri}`);
  
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
    prompt: 'consent select_account',
    state: origin // Pass through the origin to the callback
  });
  res.redirect(authUrl);
});

// Send token to frontend route
app.get('/auth/token', (req, res) => {
  if (!googleTokens) {
    return res.status(401).json({ 
      error: 'Not authenticated', 
      redirectUrl: '/auth/google?origin=frontend' 
    });
  }
  
  // Send only necessary token info to frontend
  res.json({
    access_token: googleTokens.access_token,
    refresh_token: googleTokens.refresh_token,
    expiry_date: googleTokens.expiry_date
  });
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;
  const origin = state || 'backend';
  
  if (!code) {
    console.error('No code provided in callback');
    return res.status(400).send('Authentication failed: No authorization code provided');
  }
  
  try {
    console.log('Exchanging authorization code for tokens...');
    
    // Exchange code for tokens
    const oauth2Client = createOAuthClient(req);
    const { tokens } = await oauth2Client.getToken(code);
    
    console.log('Token exchange successful:', {
      tokenType: tokens.token_type,
      expiryDate: tokens.expiry_date,
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      scope: tokens.scope
    });
    
    oauth2Client.setCredentials(tokens);
    
    // Store tokens globally
    googleTokens = tokens;
    
    // Save tokens to file for persistence
    saveTokens(tokens);
    
    if (origin === 'frontend') {
      // For frontend auth, include token in the redirect URL as a parameter
      const tokenInfo = encodeURIComponent(JSON.stringify({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expiry_date: tokens.expiry_date
      }));
      
      // Use the dynamic frontend URL based on the request origin
      const frontendUrl = getFrontendUrl(req);
      console.log(`Redirecting to frontend URL: ${frontendUrl}/sources`);
      
      return res.redirect(`${frontendUrl}/sources?auth=success&token=${tokenInfo}`);
    }
    
    // Standard backend flow
    res.redirect('/gdocs');
  } catch (error) {
    console.error('Error during OAuth callback:');
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    if (error.response) {
      console.error('OAuth error response:', {
        status: error.response.status,
        statusText: error.response.statusText,
        data: error.response.data
      });
    }
    
    res.status(500).send(`Authentication failed: ${error.message}`);
  }
});

// Check auth status endpoint for frontend
app.get('/api/auth/status', (req, res) => {
  res.json({
    authenticated: !!googleTokens,
    tokenExpiry: googleTokens ? googleTokens.expiry_date : null
  });
});

// Add a logout/clear tokens endpoint
app.get('/auth/logout', (req, res) => {
  googleTokens = null;
  
  // Remove tokens file if in development
  try {
    if (!isProduction && fs.existsSync(TOKEN_PATH)) {
      fs.unlinkSync(TOKEN_PATH);
      console.log('Tokens file deleted');
    }
  } catch (error) {
    console.error('Error deleting tokens file:', error.message);
  }
  
  res.json({ message: 'Logged out successfully' });
});

// Google Docs API routes
app.get('/gdocs', authMiddleware, async (req, res) => {
  try {
    // Auth client is already set by middleware
    const auth = req.auth;
    
    // Initialize Drive API to get docs list
    const drive = google.drive({ version: 'v3', auth });
    
    console.log('Initialized Google APIs, fetching Google Docs');
    
    // Get list of Google Docs
    const response = await drive.files.list({
      q: "mimeType='application/vnd.google-apps.document'",
      fields: 'files(id, name)',
      pageSize: 10
    });
    
    console.log(`Found ${response.data.files.length} Google Docs`);
    const files = response.data.files;
    
    // Return JSON for frontend compatibility
    return res.json(files.map(file => ({
      id: file.id,
      name: file.name
    })));
  } catch (error) {
    console.error('Error in /gdocs endpoint:');
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    if (error.response) {
      console.error('Google API error response:', {
        status: error.response.status,
        statusText: error.response.statusText,
        data: error.response.data
      });
    }
    
    // Return a more helpful error message
    res.status(500).json({ 
      error: 'Failed to access Google Docs', 
      details: error.message,
      solution: 'Try authenticating again at /auth/google'
    });
  }
});

app.get('/gdocs/:docsId', authMiddleware, async (req, res) => {
  if (!googleTokens) {
    return res.redirect(`/auth/google?origin=backend&next=gdocs/${req.params.docsId}`);
  }
  
  const docsId = req.params.docsId;
  
  try {
    // Get auth client with token refresh
    const auth = await getAuthClientWithRefresh(req);
    
    if (!auth) {
      return res.redirect(`/auth/google?origin=backend&next=gdocs/${req.params.docsId}`);
    }
    
    // Initialize Docs API
    const docs = google.docs({ version: 'v1', auth });
    
    // Get document information
    const document = await docs.documents.get({
      documentId: docsId
    });
    
    // Process the document content
    const documentData = document.data;
    const title = documentData.title;
    
    // Extract text content from the document
    let textContent = '';
    
    if (documentData.body && documentData.body.content) {
      documentData.body.content.forEach(element => {
        if (element.paragraph) {
          element.paragraph.elements.forEach(paraElement => {
            if (paraElement.textRun && paraElement.textRun.content) {
              textContent += paraElement.textRun.content;
            }
          });
        }
      });
    }
    
    // Return JSON response with document data
    res.json({
      id: docsId,
      title: title,
      content: textContent,
      documentData: documentData
    });
  } catch (error) {
    console.error('Error accessing document data:', error);
    res.status(500).json({ 
      error: 'Error accessing document data', 
      details: error.message 
    });
  }
});

// API JSON endpoint for document
app.get('/api/gdocs/:docsId', authMiddleware, async (req, res) => {
  const docsId = req.params.docsId;
  
  try {
    // Auth client is already set by middleware
    const auth = req.auth;
    
    // Initialize Docs API
    const docs = google.docs({ version: 'v1', auth });
    
    // Get document information
    const document = await docs.documents.get({
      documentId: docsId
    });
    
    // Return the complete document data
    res.json(document.data);
  } catch (error) {
    console.error('Error accessing document data:', error);
    res.status(500).json({ 
      error: 'Error accessing document data', 
      details: error.message 
    });
  }
});

// Start server (only in development - not needed in serverless)
if (!isProduction) {
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

// For serverless deployment
module.exports = app; 
