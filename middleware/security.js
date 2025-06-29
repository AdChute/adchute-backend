const rateLimit = require('express-rate-limit');
const AuditLog = require('../models/AuditLog');

const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: async (req, res) => {
      if (req.user) {
        await AuditLog.logFailure(
          req.user._id,
          'RATE_LIMIT_EXCEEDED',
          `Rate limit exceeded: ${message}`,
          req
        );
      }
      
      res.status(429).json({ error: message });
    }
  });
};

const apiLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  100, // requests per window
  'Too many API requests, please try again later'
);

const authLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  5, // login attempts per window
  'Too many authentication attempts, please try again later'
);

const dnsLimiter = createRateLimiter(
  60 * 1000, // 1 minute
  10, // DNS requests per minute
  'Too many DNS requests, please slow down'
);

const strictAuthLimiter = createRateLimiter(
  60 * 60 * 1000, // 1 hour
  3, // failed attempts per hour
  'Account temporarily locked due to suspicious activity'
);

const auditLogMiddleware = (action) => {
  return async (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
      if (req.user && res.statusCode < 400) {
        AuditLog.logAction(
          req.user._id,
          action,
          {
            endpoint: req.originalUrl,
            method: req.method,
            response_status: res.statusCode
          },
          req
        ).catch(console.error);
      } else if (req.user && res.statusCode >= 400) {
        AuditLog.logFailure(
          req.user._id,
          action,
          `HTTP ${res.statusCode}: ${req.originalUrl}`,
          req
        ).catch(console.error);
      }
      
      originalSend.call(this, data);
    };
    
    next();
  };
};

const suspiciousActivityDetector = async (req, res, next) => {
  if (!req.user) return next();
  
  try {
    const recentLogs = await AuditLog.find({
      user_id: req.user._id,
      timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // Last hour
    }).sort({ timestamp: -1 }).limit(20);
    
    const failedAttempts = recentLogs.filter(log => !log.success).length;
    const uniqueIPs = new Set(recentLogs.map(log => log.ip_address)).size;
    const rapidRequests = recentLogs.filter(log => 
      log.timestamp > new Date(Date.now() - 5 * 60 * 1000) // Last 5 minutes
    ).length;
    
    let suspiciousActivity = false;
    let reason = '';
    
    if (failedAttempts >= 5) {
      suspiciousActivity = true;
      reason = 'Multiple failed attempts';
    } else if (uniqueIPs >= 3) {
      suspiciousActivity = true;
      reason = 'Multiple IP addresses';
    } else if (rapidRequests >= 30) {
      suspiciousActivity = true;
      reason = 'Rapid request pattern';
    }
    
    if (suspiciousActivity) {
      await AuditLog.logAction(
        req.user._id,
        'SUSPICIOUS_ACTIVITY',
        {
          reason,
          failed_attempts: failedAttempts,
          unique_ips: uniqueIPs,
          rapid_requests: rapidRequests,
          endpoint: req.originalUrl
        },
        req
      );
      
      console.warn(`Suspicious activity detected for user ${req.user._id}: ${reason}`);
    }
    
    next();
  } catch (error) {
    console.error('Error in suspicious activity detector:', error);
    next();
  }
};

const ipWhitelist = (whitelist = []) => {
  return (req, res, next) => {
    if (whitelist.length === 0) return next();
    
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (!whitelist.includes(clientIP)) {
      return res.status(403).json({ 
        error: 'Access denied from this IP address' 
      });
    }
    
    next();
  };
};

const requireHTTPS = (req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure && req.get('x-forwarded-proto') !== 'https') {
    return res.status(403).json({ 
      error: 'HTTPS required' 
    });
  }
  next();
};

module.exports = {
  apiLimiter,
  authLimiter,
  dnsLimiter,
  strictAuthLimiter,
  auditLogMiddleware,
  suspiciousActivityDetector,
  ipWhitelist,
  requireHTTPS
};