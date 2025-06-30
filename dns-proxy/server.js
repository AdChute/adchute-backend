const dns2 = require('dns2');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

// Configuration
const DNS_PORT = process.env.DNS_PORT || 53;
const AUTH_PORT = process.env.AUTH_PORT || 8080;
const PIHOLE_DNS = process.env.PIHOLE_DNS || '198.211.101.7';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const MONGODB_URI = process.env.MONGODB_URI;

// User schema for subscription validation (matching main API schema)
const userSchema = new mongoose.Schema({
  email: String,
  subscription_status: String,
  subscription_end_date: Date,
  trial_expires_at: Date
});

const User = mongoose.model('User', userSchema);

// Connect to MongoDB with error handling
if (MONGODB_URI) {
  console.log('Connecting to MongoDB...');
  mongoose.connect(MONGODB_URI)
    .then(() => {
      console.log('Connected to MongoDB successfully');
    })
    .catch(err => {
      console.error('MongoDB connection error:', err);
      process.exit(1);
    });
  
  // Handle MongoDB connection events
  mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
  });
  
  mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected');
  });
  
  mongoose.connection.on('reconnected', () => {
    console.log('MongoDB reconnected');
  });
} else {
  console.error('MONGODB_URI environment variable is required');
  process.exit(1);
}

// In-memory cache for authorized users (TTL: 5 minutes)
const authorizedUsers = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// DNS query statistics
const queryStats = new Map();

/**
 * Validate user subscription status
 */
async function validateUserSubscription(userId) {
  try {
    const user = await User.findById(userId);
    if (!user) {
      console.log(`User not found: ${userId}`);
      return false;
    }

    const now = new Date();
    console.log(`Validating user ${userId}: status=${user.subscription_status}, trial_expires=${user.trial_expires_at}`);
    
    // Check if user has active subscription
    if (user.subscription_status === 'active' && user.subscription_end_date > now) {
      console.log(`User ${userId} has active subscription`);
      return true;
    }
    
    // Check if user is in trial period
    if (user.subscription_status === 'trial' && user.trial_expires_at > now) {
      console.log(`User ${userId} has valid trial`);
      return true;
    }
    
    console.log(`User ${userId} subscription expired or invalid`);
    return false;
  } catch (error) {
    console.error('Error validating user subscription:', error);
    return false;
  }
}

/**
 * Check if user is authorized (with caching)
 */
async function isUserAuthorized(userId) {
  const cached = authorizedUsers.get(userId);
  if (cached && Date.now() < cached.expiry) {
    return cached.authorized;
  }

  const authorized = await validateUserSubscription(userId);
  authorizedUsers.set(userId, {
    authorized,
    expiry: Date.now() + CACHE_TTL
  });

  return authorized;
}

/**
 * Extract user ID from DNS query
 * We'll use a custom header or subdomain approach
 */
function extractUserFromQuery(query) {
  // Method 1: Subdomain approach - user123.dns.adchute.org
  const domain = query.questions?.[0]?.name || '';
  const userMatch = domain.match(/^user(\w+)\.dns\.adchute\.org$/);
  if (userMatch) {
    return userMatch[1];
  }

  // Method 2: TXT record approach for authentication
  if (query.questions?.[0]?.type === dns2.Packet.TYPE.TXT && 
      domain.startsWith('auth.')) {
    const authDomain = domain.replace('auth.', '');
    const userMatch = authDomain.match(/^user(\w+)\.dns\.adchute\.org$/);
    if (userMatch) {
      return userMatch[1];
    }
  }

  return null;
}

/**
 * Forward DNS query to PiHole
 */
async function forwardToUpstream(query) {
  return new Promise((resolve, reject) => {
    const client = new dns2({
      nameServers: [PIHOLE_DNS],
      timeout: 5000
    });

    client.resolveA(query.questions[0].name, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

/**
 * Create DNS server
 */
const server = dns2.createServer({
  udp: true,
  tcp: true,
  handle: async (request, send, rinfo) => {
    const query = request;
    const clientIP = rinfo.address;
    
    console.log(`DNS Query from ${clientIP}: ${query.questions?.[0]?.name}`);

    try {
      // Extract user ID from query
      const userId = extractUserFromQuery(query);
      
      if (!userId) {
        console.log(`Unauthorized DNS query from ${clientIP}: No user ID found`);
        // Send NXDOMAIN response for unauthorized queries
        const response = dns2.Packet.createResponseFromRequest(request);
        response.header.rcode = dns2.Packet.RCODE.NXDOMAIN;
        return send(response);
      }

      // Check if user is authorized
      const authorized = await isUserAuthorized(userId);
      
      if (!authorized) {
        console.log(`Unauthorized DNS query from ${clientIP}: User ${userId} not authorized`);
        // Send NXDOMAIN for unauthorized users
        const response = dns2.Packet.createResponseFromRequest(request);
        response.header.rcode = dns2.Packet.RCODE.NXDOMAIN;
        return send(response);
      }

      // Update query statistics
      const stats = queryStats.get(userId) || { count: 0, lastQuery: null };
      stats.count++;
      stats.lastQuery = new Date();
      queryStats.set(userId, stats);

      // Forward to PiHole - create upstream client
      const upstream = new dns2({
        nameServers: [PIHOLE_DNS],
        timeout: 5000
      });

      // Forward the original query to PiHole
      upstream.query(query.questions[0].name, query.questions[0].type)
        .then(result => {
          console.log(`Forwarded query for user ${userId}: ${query.questions[0].name}`);
          
          // Create response from upstream result
          const response = dns2.Packet.createResponseFromRequest(request);
          response.answers = result.answers;
          response.authorities = result.authorities;
          response.additionals = result.additionals;
          
          send(response);
        })
        .catch(error => {
          console.error(`Error forwarding query for user ${userId}:`, error);
          const response = dns2.Packet.createResponseFromRequest(request);
          response.header.rcode = dns2.Packet.RCODE.SERVFAIL;
          send(response);
        });

    } catch (error) {
      console.error('DNS Server Error:', error);
      const response = dns2.Packet.createResponseFromRequest(request);
      response.header.rcode = dns2.Packet.RCODE.SERVFAIL;
      send(response);
    }
  }
});

/**
 * Express server for authentication and management
 */
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Get user's DNS subdomain
app.get('/api/dns/subdomain/:userId', async (req, res) => {
  const { userId } = req.params;
  
  try {
    const authorized = await isUserAuthorized(userId);
    if (!authorized) {
      return res.status(403).json({ error: 'User not authorized' });
    }

    res.json({
      subdomain: `user${userId}.dns.adchute.org`,
      dnsServer: process.env.DNS_PROXY_HOST || '198.211.101.7',
      instructions: 'Use this subdomain as your DNS server'
    });
  } catch (error) {
    console.error('Error getting DNS subdomain:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's query statistics
app.get('/api/dns/stats/:userId', (req, res) => {
  const { userId } = req.params;
  const stats = queryStats.get(userId) || { count: 0, lastQuery: null };
  
  res.json({
    userId,
    queryCount: stats.count,
    lastQuery: stats.lastQuery,
    authorized: authorizedUsers.get(userId)?.authorized || false
  });
});

// Validate JWT token and return user info for DNS access
app.post('/api/dns/authorize', async (req, res) => {
  const { token } = req.body;
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    
    const authorized = await isUserAuthorized(userId);
    
    res.json({
      userId,
      authorized,
      subdomain: authorized ? `user${userId}.dns.adchute.org` : null,
      dnsServer: authorized ? process.env.DNS_PROXY_HOST : null
    });
  } catch (error) {
    console.error('Token validation error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// DNS over HTTPS endpoint (RFC 8484)
app.get('/dns-query', async (req, res) => {
  const dnsParam = req.query.dns;
  
  if (!dnsParam) {
    return res.status(400).json({ error: 'Missing dns parameter' });
  }
  
  try {
    // Extract user ID from the Host header (e.g., user123.dns.adchute.org)
    const host = req.get('Host') || '';
    const userMatch = host.match(/^user(\w+)\.dns\.adchute\.org/);
    
    if (!userMatch) {
      return res.status(400).json({ error: 'Invalid subdomain format' });
    }
    
    const userId = userMatch[1];
    const authorized = await isUserAuthorized(userId);
    
    if (!authorized) {
      return res.status(403).json({ error: 'User not authorized' });
    }
    
    // Decode base64 DNS query
    const dnsQuery = Buffer.from(dnsParam, 'base64url');
    
    // Parse DNS query using dns2
    const query = dns2.Packet.parse(dnsQuery);
    
    // Update query statistics
    const stats = queryStats.get(userId) || { count: 0, lastQuery: null };
    stats.count++;
    stats.lastQuery = new Date().toISOString();
    queryStats.set(userId, stats);
    
    console.log(`DoH DNS Query from user ${userId}:`, 
      query.questions?.[0]?.name || 'unknown',
      query.questions?.[0]?.type || 'unknown'
    );
    
    // Forward to Pi-hole DNS server
    const response = await new Promise((resolve, reject) => {
      const client = dns2.createUDPSocket();
      
      // Set timeout
      const timeout = setTimeout(() => {
        client.close();
        reject(new Error('DNS query timeout'));
      }, 5000);
      
      client.on('response', (response) => {
        clearTimeout(timeout);
        client.close();
        resolve(response);
      });
      
      client.on('error', (error) => {
        clearTimeout(timeout);
        client.close();
        reject(error);
      });
      
      // Send query to Pi-hole
      client.send(query, 53, PIHOLE_DNS);
    });
    
    // Return DNS response as binary data with proper headers
    res.set('Content-Type', 'application/dns-message');
    res.set('Cache-Control', 'max-age=300'); // Cache for 5 minutes
    res.send(response.toBuffer());
    
  } catch (error) {
    console.error('DoH DNS query error:', error);
    res.status(500).json({ error: 'DNS query failed' });
  }
});

app.post('/dns-query', async (req, res) => {
  // POST version of DNS over HTTPS
  try {
    // Extract user ID from the Host header
    const host = req.get('Host') || '';
    const userMatch = host.match(/^user(\w+)\.dns\.adchute\.org/);
    
    if (!userMatch) {
      return res.status(400).json({ error: 'Invalid subdomain format' });
    }
    
    const userId = userMatch[1];
    const authorized = await isUserAuthorized(userId);
    
    if (!authorized) {
      return res.status(403).json({ error: 'User not authorized' });
    }
    
    // Parse DNS query from request body
    const dnsQuery = req.body;
    const query = dns2.Packet.parse(dnsQuery);
    
    // Update query statistics
    const stats = queryStats.get(userId) || { count: 0, lastQuery: null };
    stats.count++;
    stats.lastQuery = new Date().toISOString();
    queryStats.set(userId, stats);
    
    console.log(`DoH POST DNS Query from user ${userId}:`, 
      query.questions?.[0]?.name || 'unknown',
      query.questions?.[0]?.type || 'unknown'
    );
    
    // Forward to Pi-hole DNS server
    const response = await new Promise((resolve, reject) => {
      const client = dns2.createUDPSocket();
      
      const timeout = setTimeout(() => {
        client.close();
        reject(new Error('DNS query timeout'));
      }, 5000);
      
      client.on('response', (response) => {
        clearTimeout(timeout);
        client.close();
        resolve(response);
      });
      
      client.on('error', (error) => {
        clearTimeout(timeout);
        client.close();
        reject(error);
      });
      
      client.send(query, 53, PIHOLE_DNS);
    });
    
    // Return DNS response
    res.set('Content-Type', 'application/dns-message');
    res.set('Cache-Control', 'max-age=300');
    res.send(response.toBuffer());
    
  } catch (error) {
    console.error('DoH POST DNS query error:', error);
    res.status(500).json({ error: 'DNS query failed' });
  }
});

// Start servers
console.log('Starting DNS proxy server...');

// Start Express server first
const httpServer = app.listen(AUTH_PORT, '0.0.0.0', () => {
  console.log(`Auth API Server listening on port ${AUTH_PORT}`);
});

// Start DNS server
server.listen({
  udp: { port: DNS_PORT, address: '0.0.0.0' },
  tcp: { port: DNS_PORT, address: '0.0.0.0' }
}, () => {
  console.log(`DNS Proxy Server listening on port ${DNS_PORT}`);
  console.log('All servers started successfully');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  httpServer.close(() => {
    console.log('HTTP server closed');
    server.close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down gracefully...');
  httpServer.close(() => {
    console.log('HTTP server closed');
    server.close();
    process.exit(0);
  });
});