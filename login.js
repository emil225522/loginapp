const mysql = require("mysql");
const express = require("express");
const session = require("express-session");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const connection = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  port: "3307",
  password: "password",
  database: "nodelogin",
});

const SECRET = "secret";

const app = express();

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(cookieParser());

connection.connect(function (err) {
  if (err) throw err;
  console.log("Connected!");
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "static")));

app.get("/", function (request, response) {
  // Render login template
  response.sendFile(path.join(__dirname + "/login.html"));
});

app.get("/create-user", function (request, response) {
  // Render login template
  response.sendFile(path.join(__dirname + "/create.html"));
});

app.post("/create", async (req, res) => {
  console.log(req.body);
  const { username, password, email } = req.body;
  const saltRounds = 10;
  console.log("password", password);
  const passwordHash = await bcrypt.hash(password, saltRounds);
  const sql =
    "INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)";
  const values = [username, passwordHash, email];
  connection.query(sql, values, (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: "Error creating user" });
    } else {
      res.status(201).json({ message: "User created successfully" });
    }
  });
});

// http://localhost:3000/auth
app.post("/auth", async function (request, response) {
  // Capture the input fields
  let username = request.body.username;
  let password = request.body.password;
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);
  // Ensure the input fields exists and are not empty
  console.log("password", password);
  if (username && passwordHash) {
    // Execute SQL query that'll select the account from the database based on the specified username and password
    connection.query(
      "SELECT * FROM accounts WHERE username = ?",
      [username],
      async function (error, results, fields) {
        console.log("results", results);

        // If there is an issue with the query, output the error
        if (error) console.log("error");
        // If the account exists
        if (results?.length > 0) {
          // Authenticate the user
          console.log(await bcrypt.compare(password, results[0].password));
          if (await bcrypt.compare(password, results[0].password)) {
            request.session.loggedin = true;
            request.session.username = username;
            // Redirect to home page
            const userForToken = {
              username: results[0].username,
              id: results[0].id,
            };

            const token = jwt.sign(userForToken, SECRET, { expiresIn: 2 * 60 });
            response.cookie("loginToken", token);
            response.redirect("/home");
          } else {
            response.send("Incorrect Username and/or Password!");
          }
        } else {
          response.send("Incorrect Username and/or Password!");
        }
        response.end();
      }
    );
  } else {
    response.send("Please enter Username and Password!");
    response.end();
  }
});

app.post("/create", function (request, response) {
  // Capture the input fields
  let username = request.body.username;
  let password = request.body.password;
  // Ensure the input fields exists and are not empty
  if (username && password) {
    // Execute SQL query that'll select the account from the database based on the specified username and password
    connection.query(
      "SELECT * FROM accounts WHERE username = ? AND password = ?",
      [username, password],
      function (error, results, fields) {
        // If there is an issue with the query, output the error
        if (error) console.log("error");
        // If the account exists
        if (results.length > 0) {
          // Authenticate the user
          request.session.loggedin = true;
          request.session.username = username;
          // Redirect to home page
          response.redirect("/home");
        } else {
          response.send("Incorrect Username and/or Password!");
        }
        response.end();
      }
    );
  } else {
    response.send("Please enter Username and Password!");
    response.end();
  }
});

// http://localhost:3000/home
app.get("/home", function (request, response) {
  // If the user is loggedin
  if (request.cookies["loginToken"]) {
    try {
      if (jwt.verify(request.cookies["loginToken"], SECRET)) {
        // Output username
        response.send("Welcome back, " + request.session.username + "!");
      }
    } catch (error) {
      console.error(error);
      response.send("forbidden");
    }
  } else {
    // Not logged in
    response.send("Please login to view this page!");
  }
  response.end();
});

function getPosts(callback) {
  connection.query("SELECT * FROM userposts", function (error, results) {
    console.log("results", results);

    if (error) {
      throw err;
    }
    console.log(results);
    posts = results;

    return callback(results);
  });
}

let posts;
getPosts(function (result) {
  posts = result;
});

app.get("/posts", function (request, response) {
  // If the user is loggedin
  if (
    request.session.loggedin ||
    (request.cookies["loginToken"] &&
      jwt.verify(request.cookies["loginToken"], SECRET))
  ) {
    response.send(posts);
  } else {
    // Not logged in
    response.send("Please login to view this page!");
  }
  response.end();
});

app.listen(3000);
console.log("app running on 3000");
