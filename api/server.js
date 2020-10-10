const express = require("express");
const db = require("../users/user-scheme");
const bcrypt = require("bcryptjs");
const auth = require("../auth/auth");
const session = require("express-session");
const server = express();

const sessionConfig = {
  name: "cookieName",
  secret: process.env.SECRET || "Some secret warning", // 
  resave: false,
  saveUninitialized: process.env.SEND_COOKIES || true,
  cookie: {
    maxAge: 60 * 60 * 1000, // Lasts for 1 hour
    secure: process.env.USE_SECURE_COOKIES || false,
    httpOnly: true,
  },
};

server.use(express.json());
server.use(session(sessionConfig));

server.get("/", (req, res) => {
  res
    .status(200)
    .json({ message: "Welcome to Authentication and Testing server!" });
});

server.get("/users", auth, (req, res) => {
  db.find().then((rep) => {
    res.status(200).json({ data: rep });
  });
});

server.post("/register", (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 4); // hashing 4x - 
  const newUser = {
    username: req.body.username,
    password: hash,
  };

  db.addUser(newUser)
    .then((rep) => {
      res.status(201).json({ data: rep });
    })
    .catch((err) => {
      res.status(500).json({ message: `Server error! ${err}` });
    });
});

server.post("/login", (req, res) => {
  db.findByUsername(req.body.username)
    .then((user) => {
      if (user && bcrypt.compareSync(req.body.password, user[0].password)) { // stored hash as opposed to string
        req.session.login = true;
        req.session.userId = user[0].id;
        res.status(200).json({ message: "Login Successful!" });
      } else {
        res.status(400).json({ message: "Login Failed!" });
      }
    })
    .catch((err) => {
      res.status(500).json({ message: `Server Error! ${err}` });
    });
});

module.exports = server;
