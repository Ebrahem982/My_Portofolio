// app.js
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost/complaints_db', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB', err));

// Define schema for complaints
const complaintSchema = new mongoose.Schema({
  type: String,
  description: String,
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  status: String,
  response: String
});
const Complaint = mongoose.model('Complaint', complaintSchema);

// Define schema for users
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String // 'employee', 'student', 'official'
});
const User = mongoose.model('User', userSchema);

// Middleware to authenticate user using JWT token
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Access denied. No token provided.');

  jwt.verify(token, 'secretkey', (err, user) => {
    if (err) return res.status(403).send('Invalid token.');
    req.user = user;
    next();
  });
}

// API endpoint for user login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).send('Invalid username or password.');

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Invalid username or password.');

  const token = jwt.sign({ username: user.username, role: user.role }, 'secretkey', { expiresIn: '1h' });
  res.send(token);
});

// API endpoint for submitting a complaint
app.post('/complaints', authenticateToken, async (req, res) => {
  const { type, description } = req.body;
  const complaint = new Complaint({ type, description, user: req.user._id, status: 'pending' });
  await complaint.save();
  res.send(complaint);
});

// API endpoint for retrieving complaints based on user role
app.get('/complaints', authenticateToken, async (req, res) => {
  const { role } = req.user;
  let complaints;
  if (role === 'official') {
    complaints = await Complaint.find();
  } else {
    complaints = await Complaint.find({ user: req.user._id });
  }
  res.send(complaints);
});

// Serve static files
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
