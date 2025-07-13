const express = require('express');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const session = require('express-session');
const path = require('path');
const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/mathportal', { useNewUrlParser: true, useUnifiedTopology: true });

// User model
const User = mongoose.model('User', { name: String, email: String, password: String });

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key', // Change to a secure random string
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set secure: true in production with HTTPS
}));

// Global authentication middleware: Protect all routes except login/signup
app.use((req, res, next) => {
  const publicPaths = ['/login.html', '/signup.html', '/login', '/signup']; // Allow these without login
  if (publicPaths.includes(req.path) || req.path.startsWith('/static/')) { // Optional: if you have unprotected static assets
    return next();
  }
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
});

// Serve static files from 'public' folder (now protected by the middleware above)
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.send('User already exists. <a href="/signup.html">Try again</a>');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashedPassword });
  await user.save();
  res.redirect('/login.html');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.user = { email: user.email }; // Set session
    res.redirect('/'); // Redirect to main portal after login
  } else {
    res.send('Invalid credentials. <a href="/login.html">Try again</a>');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// Optional: Protected download route (if you have PDFs)
app.get('/download/:category/:test', (req, res) => {
  const filePath = path.join(__dirname, 'public', req.params.category, `${req.params.test}.pdf`);
  res.download(filePath);
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
