require("./utils");

require("dotenv").config();
const express = require("express");

// Session management
const session = require("express-session");
const MongoStore = require("connect-mongo");

// Hash passwords using BCrypt
const bcrypt = require("bcrypt");
const saltRounds = 12;

const database = include("databaseConnection");
const db_utils = include("database/db_utils");
const db_users = include("database/users");
const success = db_utils.printMySQLVersion();

//reference of the express module
const app = express();

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour

/* secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.set("view engine", "ejs");

// parse application/json
app.use(express.urlencoded({ extended: false }));
const port = process.env.PORT || 3000;

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.3lizggb.mongodb.net/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (!isValidSession(req)) {
    req.session.destroy();
    res.redirect("/login");
    return;
  } else {
    next();
  }
}

// root path
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.render("index");
  } else {
    res.render("loggedIn", { username: req.session.username });
  }
});

app.get("/createTables", async (req, res) => {
  const create_tables = include("database/create_tables");

  var success = create_tables.createTables();
  if (success) {
    res.render("successMessage", { message: "Created tables." });
  } else {
    res.render("errorMessage", { error: "Failed to create tables." });
  }
});

// Sign up page
app.get("/signup", (req, res) => {
  const errorMessage = req.query.errorMessage;
  res.render("signup", { errorMessage: errorMessage });
});

// Sign up processing
app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  var errorMessage = "";
  // Check if username or password is empty
  var results = await db_users.getUser({
    user: username,
    hashedPassword: password,
  });

  if (results) {
    if (results.length == 1) {
      errorMessage =
        "User name: " + username + " is already taken. Please try another one.";
      return res.redirect(
        "/signup?duplicatedUser=1&errorMessage=" + errorMessage
      );
    }
  }

  if (!username || !password) {
    if (!username && !password) {
      errorMessage = "Please provide a username and password.";
      return res.redirect(
        "/signup?missingusernameandpassword=1&errorMessage=" + errorMessage
      );
    } else if (!password) {
      errorMessage = "Please provide a password.";
      return res.redirect(
        "/signup?missingpassword=1&errorMessage=" + errorMessage
      );
    } else if (!username) {
      errorMessage = "Please provide a username.";
      return res.redirect(
        "/signup?missingusername=1&errorMessage=" + errorMessage
      );
    }
  }

  var hashedPassword = bcrypt.hashSync(password, saltRounds);

  var success = await db_users.createUser({
    user: username,
    hashedPassword: hashedPassword,
  });

  if (success) {
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime; //Session lasts 1 hour

    res.redirect("/members");
    return;
  } else {
    res.redirect("/signup");
  }
});

app.use("/members", sessionValidation);

app.get("/members", (req, res) => {
  const imageNames = ["cat1.jpg", "cat2.jpg", "cat3.jpg"];
  const ramdomIndex = Math.floor(Math.random() * imageNames.length);
  const randomImage = imageNames[ramdomIndex];
  res.render("members", {
    image: randomImage,
    username: req.session.username,
  });
});

// Login in page
app.get("/login", (req, res) => {
  if (isValidSession(req)) {
    res.redirect("/members");
    return;
  } else {
    var errorMessage = req.session.errorMessage;
    req.session.errorMessage = null;
    res.render("login", { errorMessage: errorMessage });
  }
});

// Loging in
app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  var results = await db_users.getUser({
    user: username,
    hashedPassword: password,
  });

  if (results) {
    if (results.length == 1) {
      //there should only be 1 user in the db that matches
      if (bcrypt.compareSync(password, results[0].password)) {
        req.session.authenticated = true;
        req.session.user_type = results[0].type;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime; //Session lasts 1 hour

        res.redirect("/members");
        return;
      } else {
        req.session.errorMessage = "Username or password not matched";
        return res.redirect("/login");
      }
    } else {
      req.session.errorMessage = "User not found";
      return res.redirect("/login");
    }
  }

  console.log("user not found");

  //user and password combination not found
  res.redirect("/login");
});

app.get("/loggedIn", sessionValidation, (req, res) => {
  res.render("loggedIn", { username: req.session.username });
});

// Log out
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Serve static files
app.use(express.static(__dirname + "/public"));

//  Catch all other routes and 404s
app.get("*", (req, res) => {
  res.status(404);
  // res.send("Page not found - 404");
  res.render("404");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
