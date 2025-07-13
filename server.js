const express = require('express');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const session = require('express-session');
const path = require('path');
const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/mathportal', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User model
const User = mongoose.model('User', { name: String, email: String, password: String });

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Global auth middleware
app.use((req, res, next) => {
  console.log(`Request to: ${req.path}, Session user: ${req.session.user ? 'Yes' : 'No'}`);
  const publicPaths = ['/login.html', '/signup.html', '/login', '/signup'];
  if (publicPaths.includes(req.path)) {
    return next();
  }
  if (!req.session.user) {
    console.log(`Redirecting to login from ${req.path}`);
    return res.redirect('/login.html');
  }
  next();
});

// Serve static files (protected)
app.use(express.static(path.join(__dirname, 'public'))));

// Routes (same as before)
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
  console.log('User signed up:', email);
  res.redirect('/login.html');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.user = { email: user.email };
    console.log('Login successful:', email);
    res.redirect('/');
  } else {
    console.log('Login failed for:', email);
    res.send('Invalid credentials. <a href="/login.html">Try again</a>');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
