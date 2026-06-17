const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../db');

const ADMIN_EMAIL = 'maposacourage41@gmail.com';

const generateToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' });

// Auto-promote admin email helper
const ensureAdmin = async (email, userId) => {
  if (email.toLowerCase() === ADMIN_EMAIL) {
    await db.execute({ sql: "UPDATE users SET role='admin' WHERE id=?", args: [userId] });
  }
};

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ message: 'All fields are required' });

    const exists = await db.execute({
      sql: 'SELECT id FROM users WHERE email = ? OR username = ?',
      args: [email.toLowerCase(), username]
    });
    if (exists.rows.length > 0)
      return res.status(400).json({ message: 'Email or username already taken' });

    const id = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute({
      sql: `INSERT INTO users (id, username, email, password, is_verified) VALUES (?, ?, ?, ?, 1)`,
      args: [id, username, email.toLowerCase(), hashedPassword]
    });

    await ensureAdmin(email, id);
    const updated = await db.execute({ sql: 'SELECT * FROM users WHERE id=?', args: [id] });
    const u = updated.rows[0];
    const token = generateToken(id);
    res.status(201).json({
      token,
      user: { id: u.id, username: u.username, email: u.email, role: u.role, avatar: u.avatar }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email.toLowerCase()] });

    if (result.rows.length === 0)
      return res.status(401).json({ message: 'Invalid email or password' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid email or password' });

    await ensureAdmin(email, user.id);
    const updated = await db.execute({ sql: 'SELECT * FROM users WHERE id=?', args: [user.id] });
    const u = updated.rows[0];
    const token = generateToken(u.id);
    res.json({
      token,
      user: { id: u.id, username: u.username, email: u.email, role: u.role, avatar: u.avatar }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/auth/me — verify token & return current user
const { protect } = require('../middleware/auth');
router.get('/me', protect, (req, res) => {
  res.json(req.user);
});

// POST /api/auth/send-otp (for password reset only)
const { sendOTP } = require('../utils/email');
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

router.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const result = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email.toLowerCase()] });

    if (result.rows.length === 0)
      return res.status(404).json({ message: 'No account with that email' });

    const user = result.rows[0];
    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    await db.execute({
      sql: 'UPDATE users SET otp_code = ?, otp_expires = ? WHERE id = ?',
      args: [otp, otpExpires, user.id]
    });

    await sendOTP(email, user.username, otp);
    res.json({ message: 'OTP sent!', userId: user.id });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/auth/reset-password
router.post('/reset-password', async (req, res) => {
  try {
    const { userId, otp, newPassword } = req.body;
    const result = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [userId] });

    if (result.rows.length === 0) return res.status(404).json({ message: 'User not found' });
    const user = result.rows[0];

    if (!user.otp_code || user.otp_code !== otp || new Date() > new Date(user.otp_expires))
      return res.status(400).json({ message: 'Invalid or expired OTP' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.execute({
      sql: 'UPDATE users SET password = ?, otp_code = NULL, otp_expires = NULL WHERE id = ?',
      args: [hashedPassword, userId]
    });

    res.json({ message: 'Password reset successful!' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
