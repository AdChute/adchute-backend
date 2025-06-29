const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  subscription_status: {
    type: String,
    enum: ['active', 'inactive', 'trial', 'cancelled'],
    default: 'trial'
  },
  dns_server_assigned: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'DnsServer',
    default: null
  },
  trial_expires_at: {
    type: Date,
    default: () => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days trial
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  last_login: {
    type: Date
  },
  is_email_verified: {
    type: Boolean,
    default: false
  },
  refresh_tokens: [{
    token: String,
    created_at: { type: Date, default: Date.now },
    expires_at: Date
  }]
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const saltRounds = 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.isSubscriptionActive = function() {
  if (this.subscription_status === 'active') return true;
  if (this.subscription_status === 'trial' && this.trial_expires_at > new Date()) return true;
  return false;
};

userSchema.methods.addRefreshToken = function(token, expiresAt) {
  this.refresh_tokens = this.refresh_tokens.filter(t => t.expires_at > new Date());
  
  this.refresh_tokens.push({
    token,
    expires_at: expiresAt
  });
  
  if (this.refresh_tokens.length > 5) {
    this.refresh_tokens = this.refresh_tokens.slice(-5);
  }
};

userSchema.methods.removeRefreshToken = function(token) {
  this.refresh_tokens = this.refresh_tokens.filter(t => t.token !== token);
};

module.exports = mongoose.model('User', userSchema);