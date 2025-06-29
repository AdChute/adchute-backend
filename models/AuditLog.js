const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: [
      'LOGIN',
      'LOGOUT',
      'REGISTER',
      'PASSWORD_CHANGE',
      'DNS_SERVER_ASSIGNED',
      'DNS_SERVER_RELEASED',
      'SUBSCRIPTION_UPDATED',
      'ACCOUNT_DELETED',
      'TOKEN_REFRESH',
      'FAILED_LOGIN',
      'SUSPICIOUS_ACTIVITY'
    ]
  },
  details: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  },
  ip_address: {
    type: String,
    required: true
  },
  user_agent: {
    type: String
  },
  success: {
    type: Boolean,
    default: true
  },
  error_message: {
    type: String
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

auditLogSchema.index({ user_id: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ ip_address: 1, timestamp: -1 });
auditLogSchema.index({ timestamp: -1 });

auditLogSchema.statics.logAction = async function(userId, action, details = {}, req = null) {
  try {
    const logEntry = new this({
      user_id: userId,
      action,
      details,
      ip_address: req ? (req.ip || req.connection.remoteAddress || 'unknown') : 'system',
      user_agent: req ? req.get('User-Agent') : 'system',
      success: true
    });
    
    await logEntry.save();
    return logEntry;
  } catch (error) {
    console.error('Failed to create audit log:', error);
  }
};

auditLogSchema.statics.logFailure = async function(userId, action, errorMessage, req = null) {
  try {
    const logEntry = new this({
      user_id: userId,
      action,
      ip_address: req ? (req.ip || req.connection.remoteAddress || 'unknown') : 'system',
      user_agent: req ? req.get('User-Agent') : 'system',
      success: false,
      error_message: errorMessage
    });
    
    await logEntry.save();
    return logEntry;
  } catch (error) {
    console.error('Failed to create audit log:', error);
  }
};

module.exports = mongoose.model('AuditLog', auditLogSchema);