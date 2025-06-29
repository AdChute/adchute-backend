const mongoose = require('mongoose');

const subscriptionSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  stripe_subscription_id: {
    type: String,
    required: true
  },
  stripe_customer_id: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'past_due', 'cancelled', 'unpaid', 'incomplete'],
    required: true
  },
  plan_type: {
    type: String,
    enum: ['basic', 'premium', 'family'],
    required: true
  },
  price: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    default: 'usd'
  },
  current_period_start: {
    type: Date,
    required: true
  },
  current_period_end: {
    type: Date,
    required: true
  },
  cancel_at_period_end: {
    type: Boolean,
    default: false
  },
  metadata: {
    type: Map,
    of: String
  }
}, {
  timestamps: true
});

subscriptionSchema.index({ user_id: 1 });
subscriptionSchema.index({ stripe_subscription_id: 1 }, { unique: true });
subscriptionSchema.index({ status: 1 });

subscriptionSchema.methods.isActive = function() {
  return this.status === 'active' && this.current_period_end > new Date();
};

module.exports = mongoose.model('Subscription', subscriptionSchema);