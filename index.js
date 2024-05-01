/*
* COMP2537 Assignment 1
* Calvin Lee, Set 2B
*/

require("./utils.js");
require('dotenv').config();


const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const saltRounds = 12;

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/public"));

// db secret info
const expireTime = 1000 * 60 * 60;    // 1000 ms/s * 60 s/min * 60 min/hr
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv:/${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true&w=majority&appName=comp2537`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}
run().catch(console.dir);

var {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');
var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false, 
  resave: true
}));

// 1. home page - displays links for signup/login if user is not logged in,
// or a welcome message if logged in
app.get('/', (req, res) => {
  // if user is not logged in: display this
  if (!req.session.authentication) {
    res.send(
      `<a href="/signup"><button>Sign up</button></a><br/>` + 
      `<a href="/login"><button>Log in</button></a>`
    );
  }
  // if user is logged in: redirect to memebers
  else {
    res.redirect(`/members`);
  };
});

// 2. Sign up page - form for user to sign up
app.get('/signup', (req, res) => {
  res.send(
    `<p>Create a new user</p>` +
    `<form method="post" action="/signupSubmit">` +
    `<input type="text" placeholder="name" name="name" required/><br/>` +
    `<input type="email" placeholder="email" name="email" required/><br/>` +
    `<input type="password" placeholder="password" name="password" required/><br/>` +
    `<input type="submit" value="Submit"/>` +
    `</form>`
  );
});

// post method to handle signup submission
app.post('/signupSubmit', async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var pw = req.body.password;   // maybe change password to require min length?

  const schema = Joi.object({
    name:   Joi.string().alphanum().max(20).required(),
    email:  Joi.string().email({minDomainSegments: 2, tlds: { allow: ['com', 'org', 'net']}}).required(),
    pw:     Joi.string().max(20).required()
  });

  const validationResult = schema.validate({name, email, pw});

  // if name is empty
  if (validationResult.error != null) {
    if (!name) {
      res.send(
        `<p>Name is required.</p><br/><a href="/signup">Try again</a>`
      );
    }
    else if (!email) {
      res.send(
        `<p>Email is required.</p><br/><a href="/signup">Try again</a>`
      );
    }
    else if (!pw) {
      res.send(
        `<p>Password is required.</p><br/><a href="/signup">Try again</a>`
      );
    }
  }
  
  // add name, email. and bcrypted hashed password as user to db
  // then create a session and redirect user to /members page
  var hashedPw = await bcrypt.hash(pw, saltRounds);
  await userCollection.insertOne({username: name, email: email, password: hashedPw});

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
  return;
});

// 3. Log in page - user can log in with email and password
app.get('/login', (req, res) => {
  res.send(
    `<p>log in</p>` + 
    `<form method="post" action="/loginSubmit">` +
    `<input type="text" placeholder="email" name="email" required/><br/>` +
    `<input type="password" placeholder="password" name="password" required/><br/>` +
    `<input type="submit" value="Login"/>` +
    `</form>`
  );
});

app.post('/loginSubmit', async (req, res) => {
  // check user against mongo db, use Joi to validate input
  // if email is found, check that the pw matches the bcrypted pw
  // store user's name in session if matches found, log the user in and redirect to /members
  // if login fails send an appropriate message (ex. user and pw not found)
  //    provide a link back to try again
  var email = req.body.email;
  var pw = req.body.password;

  const schema = Joi.object({
    email:  Joi.string().email({minDomainSegments: 2, tlds: { allow: ['com', 'org', 'net']}}).required(),
    pw:     Joi.string().max(20).required()
  });
  const validationResult = schema.validate({email, pw});
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection.find({email: email}).project({username: 1, password: 1, _id: 1}).toArray();

	if (result.length != 1) {
		// email not found
		res.send(
      `<p>That email was not found.</p>` +
      `<a href="/login">Try again</a>`
    );
	}
	if (await bcrypt.compare(pw, result[0].password)) {
		// correct password
		req.session.authenticated = true;
		req.session.name = result[0].username;
		req.session.cookie.maxAge = expireTime;
		res.redirect('/members');
		return;
	}
	else {
		// incorrect password
		res.send(
      `<p>That password is incorrect.</p>` +
      `<a href="/login">Try again</a>`
    );
	}
});

app.get('/members', (req, res) => {
  // if user has a valid session:
  //    say hello and name of user
  //    have a link that can log the user out (ends session and redirects to /)
  // display a random image from selection of 3 images, stored in the /public folder of server
  if (req.session.authenticated) {
    var rnd = Math.floor(Math.random() * 3) + 1;
    var html =
      `<h1>Hello, ${req.session.name}!</h1><br/><br/>` +
      `<img src="/${rnd.toString()}.jpg"><br/>` +
      `<a href="/logout"><button>Sign out</button></a>`

    res.send(html);
  }
  // if user has no session:
  //    redirect to home page
  else {
    res.redirect(`/`);
    return;
  }

  // temporary
  // res.send(`<h1>member page woo</h1>`);
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect(`/`);
  return;
});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

app.get('*', (req, res) => {
  res.status(404);
  res.send(`<h1>Four oh four. Something went wrong! Maybe you went somewhere that doesn't exist.<h1>`);
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});


/*
mongodb+srv://calvinnleeee:7Mwkq0g5d1oyuqSj@comp2537.cepl0em.mongodb.net/?retryWrites=true&w=majority&appName=comp2537

const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "mongodb+srv://calvinnleeee:7Mwkq0g5d1oyuqSj@comp2537.cepl0em.mongodb.net/?retryWrites=true&w=majority&appName=comp2537";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}
run().catch(console.dir);

*/