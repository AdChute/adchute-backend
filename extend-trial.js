const mongoose = require('mongoose');
const User = require('./models/User');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/adchute';

async function extendTrial() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');

    const user = await User.findOne({ email: 'ben.m.ross08@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }

    console.log('Current user:', {
      email: user.email,
      subscription_status: user.subscription_status,
      trial_expires_at: user.trial_expires_at
    });

    // Extend trial by 30 days
    user.trial_expires_at = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await user.save();

    console.log('Trial extended:', {
      email: user.email,
      subscription_status: user.subscription_status,
      trial_expires_at: user.trial_expires_at,
      isActive: user.isSubscriptionActive()
    });

  } catch (error) {
    console.error('Error:', error);
  } finally {
    await mongoose.disconnect();
  }
}

extendTrial();