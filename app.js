import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from './models/User.js'; // Make sure this file also uses ESM

dotenv.config();

const app = express();
app.use(express.json());

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

mongoose.connect(process.env.MONGO_URI).then(async () => {
  console.log('MongoDB connected');

  const user = await User.findOne({ username: "sri" });
  console.log(user);
}).catch(err => {
  console.error('MongoDB connection error:', err);
});


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
  if (!user) return res.status(400).json({ error: 'Invalid credentials 1' });
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






// ✅ Accessible from outside:
app.listen(5000, '0.0.0.0');


