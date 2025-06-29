const express = require('express');
const { authenticateToken, requireActiveSubscription } = require('../middleware/auth');
const DnsServer = require('../models/DnsServer');
const User = require('../models/User');

const router = express.Router();

router.get('/server', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check subscription status
    const now = new Date();
    let hasAccess = false;
    let accessType = 'none';

    if (user.subscriptionStatus === 'active' && user.subscriptionEndDate > now) {
      hasAccess = true;
      accessType = 'subscription';
    } else if (user.subscriptionStatus === 'trial' && user.trialEndDate > now) {
      hasAccess = true;
      accessType = 'trial';
    }

    if (!hasAccess) {
      return res.status(403).json({ 
        error: 'Access denied: Active subscription required',
        subscriptionStatus: user.subscriptionStatus,
        hasAccess: false
      });
    }

    // For now, return the authenticated DNS proxy configuration
    // In the future, this could load balance between multiple DNS servers
    const dnsConfig = {
      dns_server: {
        ip: process.env.DNS_PROXY_HOST || 'dns.adchute.org',
        subdomain: `user${user._id}.dns.adchute.org`,
        port: 53,
        region: 'nyc',
        status: 'active'
      },
      user_config: {
        userId: user._id,
        accessType,
        subscriptionEndDate: user.subscriptionEndDate,
        trialEndDate: user.trialEndDate
      },
      message: 'Authenticated DNS access configured'
    };

    res.json(dnsConfig);

  } catch (error) {
    console.error('Get DNS server error:', error);
    res.status(500).json({ error: 'Failed to get DNS configuration' });
  }
});

router.post('/release', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    if (!user.dns_server_assigned) {
      return res.json({ message: 'No DNS server assigned to release' });
    }

    const dnsServer = await DnsServer.findById(user.dns_server_assigned);
    if (dnsServer) {
      dnsServer.releaseUser();
      await dnsServer.save();
    }

    user.dns_server_assigned = null;
    await user.save();

    res.json({ message: 'DNS server released successfully' });

  } catch (error) {
    console.error('Release DNS server error:', error);
    res.status(500).json({ error: 'Failed to release DNS server' });
  }
});

// Validate access for DNS proxy (called without auth token, uses userId)
router.post('/validate-access', async (req, res) => {
  try {
    const { userId, dnsQuery, clientIp } = req.body;

    if (!userId) {
      return res.json({ 
        allowed: false, 
        reason: 'User ID required' 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.json({ 
        allowed: false, 
        reason: 'User not found' 
      });
    }

    // Check subscription status
    const now = new Date();
    let hasAccess = false;
    let accessType = 'none';

    if (user.subscriptionStatus === 'active' && user.subscriptionEndDate > now) {
      hasAccess = true;
      accessType = 'subscription';
    } else if (user.subscriptionStatus === 'trial' && user.trialEndDate > now) {
      hasAccess = true;
      accessType = 'trial';
    }

    // Log the validation attempt for monitoring
    console.log(`DNS access validation: User ${userId}, Query: ${dnsQuery}, Access: ${hasAccess}, Type: ${accessType}`);

    res.json({
      allowed: hasAccess,
      reason: hasAccess ? 'Access granted' : 'Subscription required',
      user_id: userId,
      access_type: accessType,
      subscription_status: user.subscriptionStatus,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Validate DNS access error:', error);
    res.status(500).json({ 
      allowed: false, 
      reason: 'Validation failed' 
    });
  }
});

router.get('/servers/status', authenticateToken, async (req, res) => {
  try {
    const servers = await DnsServer.find({}, {
      server_ip: 1,
      region: 1,
      status: 1,
      active_users: 1,
      capacity: 1,
      performance_metrics: 1,
      last_health_check: 1
    });

    const summary = {
      total_servers: servers.length,
      active_servers: servers.filter(s => s.status === 'active').length,
      total_capacity: servers.reduce((sum, s) => sum + s.capacity, 0),
      total_active_users: servers.reduce((sum, s) => sum + s.active_users, 0)
    };

    res.json({
      summary,
      servers: servers.map(server => ({
        region: server.region,
        status: server.status,
        usage_percentage: Math.round((server.active_users / server.capacity) * 100),
        performance: server.performance_metrics,
        last_health_check: server.last_health_check
      }))
    });

  } catch (error) {
    console.error('Get server status error:', error);
    res.status(500).json({ error: 'Failed to fetch server status' });
  }
});

module.exports = router;