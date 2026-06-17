const express = require('express');
const router = express.Router();

// Auth routes removed — no accounts required
router.get('/me', (req, res) => res.json({ id:'guest', username:'Spider', role:'user' }));

module.exports = router;
