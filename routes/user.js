const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const User = require('../models/User');
const Subscription = require('../models/Subscription');

const router = express.Router();

router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('dns_server_assigned')
      .select('-password -refresh_tokens');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const subscription = await Subscription.findOne({ user_id: user._id });

    res.json({
      user: {
        id: user._id,
        email: user.email,
        subscription_status: user.subscription_status,
        trial_expires_at: user.trial_expires_at,
        dns_server: user.dns_server_assigned ? {
          ip: user.dns_server_assigned.server_ip,
          region: user.dns_server_assigned.region,
          status: user.dns_server_assigned.status
        } : null,
        created_at: user.created_at,
        last_login: user.last_login,
        is_email_verified: user.is_email_verified
      },
      subscription: subscription ? {
        plan_type: subscription.plan_type,
        status: subscription.status,
        current_period_end: subscription.current_period_end,
        cancel_at_period_end: subscription.cancel_at_period_end
      } : null
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

router.get('/subscription-status', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const subscription = await Subscription.findOne({ user_id: user._id });

    const isActive = user.isSubscriptionActive();
    
    res.json({
      is_active: isActive,
      subscription_status: user.subscription_status,
      trial_expires_at: user.trial_expires_at,
      subscription: subscription ? {
        plan_type: subscription.plan_type,
        status: subscription.status,
        current_period_start: subscription.current_period_start,
        current_period_end: subscription.current_period_end,
        cancel_at_period_end: subscription.cancel_at_period_end,
        price: subscription.price,
        currency: subscription.currency
      } : null,
      dns_access_allowed: isActive
    });

  } catch (error) {
    console.error('Get subscription status error:', error);
    res.status(500).json({ error: 'Failed to fetch subscription status' });
  }
});

router.delete('/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;

    await Subscription.deleteMany({ user_id: userId });
    
    if (req.user.dns_server_assigned) {
      const DnsServer = require('../models/DnsServer');
      const dnsServer = await DnsServer.findById(req.user.dns_server_assigned);
      if (dnsServer) {
        dnsServer.releaseUser();
        await dnsServer.save();
      }
    }

    await User.findByIdAndDelete(userId);

    res.json({ message: 'Account deleted successfully' });

  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

module.exports = router;