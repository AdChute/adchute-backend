const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { generateTokens, verifyRefreshToken, authenticateToken } = require('../middleware/auth');
const { auditLogMiddleware, suspiciousActivityDetector } = require('../middleware/security');

const router = express.Router();

const validateRegistration = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
];

const validateLogin = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
];

router.post('/register', validateRegistration, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    const user = new User({
      email,
      password,
      subscription_status: 'trial'
    });

    await user.save();

    const { accessToken, refreshToken } = generateTokens(user._id);
    
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    user.addRefreshToken(refreshToken, refreshExpiresAt);
    await user.save();

    await AuditLog.logAction(user._id, 'REGISTER', { email }, req);

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user._id,
        email: user.email,
        subscription_status: user.subscription_status,
        trial_expires_at: user.trial_expires_at
      },
      accessToken,
      refreshToken
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', validateLogin, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email }).populate('dns_server_assigned');
    if (!user) {
      await AuditLog.logFailure(null, 'FAILED_LOGIN', `Login attempt with non-existent email: ${email}`, req);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      await AuditLog.logFailure(user._id, 'FAILED_LOGIN', 'Invalid password', req);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    user.last_login = new Date();
    await user.save();

    const { accessToken, refreshToken } = generateTokens(user._id);
    
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    user.addRefreshToken(refreshToken, refreshExpiresAt);
    await user.save();

    await AuditLog.logAction(user._id, 'LOGIN', { email }, req);

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        email: user.email,
        subscription_status: user.subscription_status,
        trial_expires_at: user.trial_expires_at,
        dns_server: user.dns_server_assigned ? user.dns_server_assigned.server_ip : null
      },
      accessToken,
      refreshToken
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }

    const decoded = verifyRefreshToken(refreshToken);
    
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    const tokenExists = user.refresh_tokens.some(t => 
      t.token === refreshToken && t.expires_at > new Date()
    );

    if (!tokenExists) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);
    
    user.removeRefreshToken(refreshToken);
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    user.addRefreshToken(newRefreshToken, refreshExpiresAt);
    await user.save();

    res.json({
      accessToken,
      refreshToken: newRefreshToken
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({ error: 'Token refresh failed' });
  }
});

router.post('/logout', authenticateToken, auditLogMiddleware('LOGOUT'), async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken) {
      req.user.removeRefreshToken(refreshToken);
      await req.user.save();
    }

    await AuditLog.logAction(req.user._id, 'LOGOUT', {}, req);

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

router.get('/verify', authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: {
      id: req.user._id,
      email: req.user.email,
      subscription_status: req.user.subscription_status,
      trial_expires_at: req.user.trial_expires_at
    }
  });
});

module.exports = router;