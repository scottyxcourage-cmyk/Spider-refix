// Auth middleware — open access (no accounts)
const protect = (req, res, next) => {
  req.user = { id: 'guest', username: 'Spider', role: 'user' };
  next();
};

const adminOnly = (req, res, next) => next();

module.exports = { protect, adminOnly };
