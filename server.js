// server.js - Simplified API Key Management Server
const express = require('express');
const morgan = require('morgan');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const fs = require('fs');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(cors());

// Serve static files from the public directory
app.use(express.static('public'));

// Create database directory if it doesn't exist
const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}

// Helper class for key generation 
class KeyManager {
  // Generate a secure license key
  static generateLicenseKey(name) {
    const timestamp = Date.now().toString();
    const randomPart = crypto.randomBytes(16).toString('hex');
    const namePart = name.replace(/\s+/g, '').toLowerCase();
    
    return crypto
      .createHash('sha256')
      .update(`${timestamp}|${randomPart}|${namePart}`)
      .digest('hex');
  }
}

// SQLite database connection
const dbPath = path.join(dbDir, 'apikeys.db');
let db;

// Initialize database and create tables if they don't exist
async function initializeDatabase() {
  db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  // Create simplified apikeys table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS apikeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      isActive INTEGER DEFAULT 1,
      createdAt TEXT DEFAULT (datetime('now')),
      expiresAt TEXT,
      usageCount INTEGER DEFAULT 0,
      lastUsed TEXT,
      usageLimit INTEGER DEFAULT 0
    );
  `);
  
  console.log('Database initialized with simplified schema');
}

// Middleware to verify API key
const verifyApiKey = async (req, res, next) => {
  const apiKey = req.headers["x-api-key"] || req.query.key;

  if (!apiKey) {
    return res.status(401).json({ error: "API key is required" });
  }

  try {
    // Get API key data
    const keyData = await db.get("SELECT * FROM apikeys WHERE key = ?", [apiKey]);

    if (!keyData) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    if (!keyData.isActive) {
      return res.status(403).json({ error: "API key is inactive" });
    }

    if (keyData.expiresAt && new Date(keyData.expiresAt) < new Date()) {
      return res.status(403).json({ error: "API key has expired" });
    }

    // Check usage limit
    if (keyData.usageLimit > 0 && keyData.usageCount >= keyData.usageLimit) {
      return res.status(403).json({
        error: "Usage limit exceeded for this API key",
        usageLimit: keyData.usageLimit,
        currentUsage: keyData.usageCount,
      });
    }

    // Update usage statistics for the API key
    await db.run(
      'UPDATE apikeys SET usageCount = usageCount + 1, lastUsed = datetime("now") WHERE id = ?',
      [keyData.id]
    );

    // Add key data to request
    req.apiKeyData = keyData;
    next();
  } catch (error) {
    console.error('API key verification error:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      details: error.message 
    });
  }
};

// Admin routes for managing API keys
const adminRouter = express.Router();

// Create a new API key
adminRouter.post('/keys', async (req, res) => {
  try {
    const { name, expiresAt, usageLimit } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const key = KeyManager.generateLicenseKey(name);
    
    // Insert the new API key
    const result = await db.run(
      `INSERT INTO apikeys (key, name, expiresAt, usageLimit) VALUES (?, ?, ?, ?)`,
      [key, name, expiresAt, usageLimit || 0]
    );
    
    const keyId = result.lastID;
    
    // Get the created API key
    const newKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    res.status(201).json(newKey);
  } catch (error) {
    console.error('Error creating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all API keys
adminRouter.get('/keys', async (req, res) => {
  try {
    const keys = await db.all('SELECT * FROM apikeys ORDER BY createdAt DESC');
    res.json(keys);
  } catch (error) {
    console.error('Error fetching API keys:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get a single API key
adminRouter.get('/keys/:id', async (req, res) => {
  try {
    const key = await db.get('SELECT * FROM apikeys WHERE id = ?', [req.params.id]);
    
    if (!key) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    res.json(key);
  } catch (error) {
    console.error('Error fetching API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update an API key
adminRouter.put('/keys/:id', async (req, res) => {
  try {
    const { name, isActive, expiresAt, usageLimit } = req.body;
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Update the API key
    await db.run(
      `UPDATE apikeys 
       SET name = ?, isActive = ?, expiresAt = ?, usageLimit = ?
       WHERE id = ?`,
      [
        name || existingKey.name,
        isActive !== undefined ? isActive : existingKey.isActive,
        expiresAt || existingKey.expiresAt,
        usageLimit !== undefined ? usageLimit : existingKey.usageLimit,
        keyId
      ]
    );
    
    // Get the updated API key
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error updating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset usage count for an API key
adminRouter.post('/keys/:id/reset-usage', async (req, res) => {
  try {
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Reset usage count
    await db.run('UPDATE apikeys SET usageCount = 0 WHERE id = ?', [keyId]);
    
    // Get the updated API key
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error resetting usage count:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete an API key
adminRouter.delete('/keys/:id', async (req, res) => {
  try {
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Delete the key
    await db.run('DELETE FROM apikeys WHERE id = ?', [keyId]);
    
    res.status(204).end();
  } catch (error) {
    console.error('Error deleting API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Rate limiter for API endpoints
const apiRateLimiter = new Map();

// Middleware to limit API request rates
function rateLimiterMiddleware(req, res, next) {
  const clientIP = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  if (apiRateLimiter.has(clientIP)) {
    const requests = apiRateLimiter.get(clientIP);
    
    // Remove requests older than 1 minute
    const recentRequests = requests.filter(time => now - time < 60000);
    
    // Add current request
    recentRequests.push(now);
    apiRateLimiter.set(clientIP, recentRequests);
    
    // Limit to 60 requests per minute
    if (recentRequests.length > 60) {
      return res.status(429).json({ 
        error: 'Too many requests. Please try again later.',
        retryAfter: 60 // seconds
      });
    }
  } else {
    // First time request from this IP
    apiRateLimiter.set(clientIP, [now]);
  }
  
  next();
}

// Periodic cleanup of rate limiter
setInterval(() => {
  const now = Date.now();
  
  for (const [ip, times] of apiRateLimiter.entries()) {
    const recentRequests = times.filter(time => now - time < 600000); // 10 minutes
    
    if (recentRequests.length === 0) {
      apiRateLimiter.delete(ip);
    } else {
      apiRateLimiter.set(ip, recentRequests);
    }
  }
}, 300000); // Run every 5 minutes

// Apply rate limiting to admin routes
app.use('/admin', rateLimiterMiddleware);

// Register admin routes
app.use('/admin', adminRouter);

// API routes that require API key authentication
const apiRouter = express.Router();
apiRouter.use(verifyApiKey);

// Sample protected API endpoint
apiRouter.get('/data', (req, res) => {
  res.json({ 
    message: 'You have access to protected data',
    keyDetails: {
      name: req.apiKeyData.name,
      usageCount: req.apiKeyData.usageCount,
      usageLimit: req.apiKeyData.usageLimit,
      remainingUsage: req.apiKeyData.usageLimit > 0 
        ? req.apiKeyData.usageLimit - req.apiKeyData.usageCount 
        : 'Unlimited'
    }
  });
});

// Register API routes
app.use('/api', apiRouter);

// Verify API key endpoint
app.get('/verify', verifyApiKey, (req, res) => {
  res.json({ 
    valid: true,
    message: 'API key is valid',
    keyDetails: {
      name: req.apiKeyData.name,
      expiresAt: req.apiKeyData.expiresAt,
      usageCount: req.apiKeyData.usageCount,
      usageLimit: req.apiKeyData.usageLimit
    }
  });
});

// Serve the main HTML file for any unhandled routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

let server;

// Initialize server after database is ready
initializeDatabase()
  .then(() => {
    server = app.listen(PORT, HOST, () => {
      console.log(`Server running on ${HOST}:${PORT}`);
      console.log('Environment:', process.env.NODE_ENV || 'development');
      console.log('Database Path:', dbPath);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  try {
    if (db) {
      await db.close();
      console.log('Database connection closed');
    }
    if (server) {
      server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
      });
    } else {
      process.exit(0); 
    }
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
});

// Export key components for potential use in other modules
module.exports = {
  app,
  KeyManager,
  verifyApiKey,
  db
};