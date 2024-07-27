const express = require("express");
const jwt = require("jsonwebtoken");
const { json } = require("body-parser");
const bcrypt = require("bcryptjs");

const app = express();
app.use(json());

const users = []; // In-memory user storage (for demonstration purposes)
const ACCESS_TOKEN_SECRET = "your_secret_key"; // In a real app, use environment variables

// Function to generate a JWT
function generateAccessToken(user) {
  return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: "1h" });
}

// Register route to add users
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send("Username and password are required");
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.status(201).send("User registered");
});

// Login route to authenticate users and provide a JWT
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send("Invalid credentials");
  }
  const accessToken = generateAccessToken({ username: user.username });
  res.json({ accessToken });
});

// Middleware to authenticate the token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Protected route
app.get("/protected", authenticateToken, (req, res) => {
  res.send("This is a protected route");
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
