const express = require('express');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

// GET /api/dashboard — protected route
router.get('/', authMiddleware, (req, res) => {
  const securityTips = [
    { id: 1, tip: 'Use strong, unique passwords for every account.', category: 'Passwords' },
    { id: 2, tip: 'Enable two-factor authentication (2FA) wherever possible.', category: '2FA' },
    { id: 3, tip: 'Never share your JWT token or session cookie with anyone.', category: 'Tokens' },
    { id: 4, tip: 'Rotate your secrets and API keys regularly.', category: 'Secrets' },
    { id: 5, tip: 'Always use HTTPS — never transmit credentials over HTTP.', category: 'Transport' },
    { id: 6, tip: 'Log and monitor all authentication events in production.', category: 'Monitoring' },
  ];

  res.json({
    success: true,
    message: `Welcome back, ${req.user.name}!`,
    user: req.user,
    securityTips,
    serverTime: new Date().toISOString(),
  });
});

module.exports = router;
