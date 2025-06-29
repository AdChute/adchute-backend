const mongoose = require('mongoose');

const dnsServerSchema = new mongoose.Schema({
  server_ip: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function(ip) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip);
      },
      message: 'Invalid IP address format'
    }
  },
  region: {
    type: String,
    required: true,
    enum: ['nyc', 'sfo', 'ams', 'sgp', 'lon', 'fra', 'tor', 'blr', 'syd']
  },
  capacity: {
    type: Number,
    required: true,
    min: 1
  },
  active_users: {
    type: Number,
    default: 0,
    min: 0
  },
  status: {
    type: String,
    enum: ['active', 'maintenance', 'offline'],
    default: 'active'
  },
  pihole_admin_token: {
    type: String,
    required: true
  },
  performance_metrics: {
    avg_response_time: { type: Number, default: 0 },
    queries_per_hour: { type: Number, default: 0 },
    blocked_percentage: { type: Number, default: 0 },
    uptime_percentage: { type: Number, default: 100 }
  },
  last_health_check: {
    type: Date,
    default: Date.now
  },
  created_at: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

dnsServerSchema.index({ region: 1, status: 1 });
dnsServerSchema.index({ active_users: 1 });

dnsServerSchema.methods.hasCapacity = function() {
  return this.active_users < this.capacity && this.status === 'active';
};

dnsServerSchema.methods.assignUser = function() {
  if (this.hasCapacity()) {
    this.active_users += 1;
    return true;
  }
  return false;
};

dnsServerSchema.methods.releaseUser = function() {
  if (this.active_users > 0) {
    this.active_users -= 1;
    return true;
  }
  return false;
};

module.exports = mongoose.model('DnsServer', dnsServerSchema);