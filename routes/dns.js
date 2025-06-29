const express = require('express');
const { authenticateToken, requireActiveSubscription } = require('../middleware/auth');
const DnsServer = require('../models/DnsServer');
const User = require('../models/User');

const router = express.Router();

router.get('/server', authenticateToken, requireActiveSubscription, async (req, res) => {
  try {
    const user = req.user;

    if (user.dns_server_assigned) {
      const dnsServer = await DnsServer.findById(user.dns_server_assigned);
      if (dnsServer && dnsServer.status === 'active') {
        return res.json({
          dns_server: {
            ip: dnsServer.server_ip,
            region: dnsServer.region,
            status: dnsServer.status,
            performance: dnsServer.performance_metrics
          }
        });
      }
    }

    const availableServer = await DnsServer.findOne({
      status: 'active',
      $expr: { $lt: ['$active_users', '$capacity'] }
    }).sort({ active_users: 1 });

    if (!availableServer) {
      return res.status(503).json({ 
        error: 'No DNS servers available at the moment. Please try again later.' 
      });
    }

    if (user.dns_server_assigned) {
      const oldServer = await DnsServer.findById(user.dns_server_assigned);
      if (oldServer) {
        oldServer.releaseUser();
        await oldServer.save();
      }
    }

    availableServer.assignUser();
    await availableServer.save();

    user.dns_server_assigned = availableServer._id;
    await user.save();

    res.json({
      dns_server: {
        ip: availableServer.server_ip,
        region: availableServer.region,
        status: availableServer.status,
        performance: availableServer.performance_metrics
      },
      message: 'DNS server assigned successfully'
    });

  } catch (error) {
    console.error('Get DNS server error:', error);
    res.status(500).json({ error: 'Failed to assign DNS server' });
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

router.get('/validate-access', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { client_ip } = req.query;

    const isActive = user.isSubscriptionActive();
    
    if (!isActive) {
      return res.status(403).json({ 
        allowed: false, 
        reason: 'Subscription not active',
        subscription_status: user.subscription_status
      });
    }

    if (!user.dns_server_assigned) {
      return res.status(403).json({ 
        allowed: false, 
        reason: 'No DNS server assigned' 
      });
    }

    const dnsServer = await DnsServer.findById(user.dns_server_assigned);
    if (!dnsServer || dnsServer.status !== 'active') {
      return res.status(503).json({ 
        allowed: false, 
        reason: 'Assigned DNS server not available' 
      });
    }

    res.json({
      allowed: true,
      dns_server: dnsServer.server_ip,
      user_id: user._id,
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