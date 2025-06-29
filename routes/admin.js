const express = require('express');
const User = require('../models/User');

const router = express.Router();

// Temporary endpoint to extend trial for testing
router.post('/extend-trial/:email', async (req, res) => {
  try {
    const { email } = req.params;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Extend trial by 30 days
    user.trial_expires_at = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await user.save();

    res.json({
      message: 'Trial extended successfully',
      user: {
        email: user.email,
        subscription_status: user.subscription_status,
        trial_expires_at: user.trial_expires_at,
        isActive: user.isSubscriptionActive()
      }
    });

  } catch (error) {
    console.error('Extend trial error:', error);
    res.status(500).json({ error: 'Failed to extend trial' });
  }
});

module.exports = router;