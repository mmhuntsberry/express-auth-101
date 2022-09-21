const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

app.use(express.json());

// Our secret token, this should be in .env file and gitignored
const accessTokenSecret = "youraccesstokensecret";

// Mock users
const users = [
  {
    username: "john",
    password: "password123admin",
  },
  {
    username: "anna",
    password: "password123member",
  },
];

// Our data
const books = [
  {
    author: "Chinua Achebe",
    country: "Nigeria",
    language: "English",
    pages: 209,
    title: "Things Fall Apart",
    year: 1958,
  },
  {
    author: "Hans Christian Andersen",
    country: "Denmark",
    language: "Danish",
    pages: 784,
    title: "Fairy tales",
    year: 1836,
  },
  {
    author: "Dante Alighieri",
    country: "Italy",
    language: "Italian",
    pages: 928,
    title: "The Divine Comedy",
    year: 1315,
  },
];

// Our function to authenticate a user
const authenticateJWT = (req, res, next) => {
  // Get token
  const authHeader = req.headers.authorization;
  // If exists split on the space and grab token
  if (authHeader) {
    const token = authHeader.split(" ")[1];

    // verify token and secret create a user object
    jwt.verify(token, accessTokenSecret, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Require user to be authenticated to access books
app.get("/books", authenticateJWT, (req, res) => {
  res.json(books);
});

// Get request to see our users
app.get("/users", (req, res) => {
  res.json(users);
});

// Signup Flow
app.post("/signup", async (req, res) => {
  // Hash our password
  const hashedPassword = await bcrypt.hash(req.body.password, 10);

  // Add our the user to DB replacing plain text pass with hashed pass
  users.push({
    ...req.body,
    password: hashedPassword,
  });

  // Show user
  res.json(users[users.length - 1]);
});

// Login flow
app.post("/login", async (req, res) => {
  // Read username and password from request body
  const { username, password } = req.body;

  // Filter user from the users array by username
  const user = users.find((u) => {
    return u.username === username;
  });

  // Check if passwords match
  const hashedPassword = await bcrypt.compare(req.body.password, user.password);

  // If a match, sign the token
  if (hashedPassword) {
    // Generate an access token
    const accessToken = jwt.sign(
      { username: user.username },
      accessTokenSecret
    );

    // Send back to client
    res.json({
      accessToken,
    });
  } else {
    res.send("Username or password incorrect");
  }
});

app.listen(5000, () => {
  console.log("Authentication service started on port 3000");
});
