require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const app = express();
app.use(express.json());

app.use(cors({
  origin: '*', // allow all origins
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
console.log('yes updated')


mongoose.connect(process.env.MONGO_URI).then(() => console.log('MongoDB connected'));
const user = await User.findOne({ username: "sri" });
console.log(user);


app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  console.log(username, password )
  const hash = await bcrypt.hash(password, 10);
  try {
    await new User({ username, password: hash }).save();
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    res.status(400).json({ error: 'Username exists' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});


app.get('/home', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ message: 'Welcome', user: decoded.id });
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
});


app.listen(5000, () => {
  console.log("Server started on port 5000");
});

