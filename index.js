require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');

const saltRounds = 12;
const app = express();
const port = 3000;

const expireTime = 1 * 60 * 60 * 1000; // 1 hour in milliseconds

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// MongoDB
const MongoClient = require('mongodb').MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`;
const database = new MongoClient(atlasURI);
const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        var html = `
            <form action='/signup' method='get'>
                <button>Sign up</button>
            </form>
            <form action='/login' method='get'>
                <button>Log in</button>
            </form>
        `;
        res.send(html);
    }
    else {
        var html = `
            <h1>Hello, ${req.session.name}!</h1>
            <form action='/members' method='get'>
                <button>Go to Members Area</button>
            </form>
            <form action='/logout' method='get'>
                <button>Logout</button>
            </form>
        `;
        res.send(html);
    }
});

app.get('/signup', (req, res) => {
    var html = `
        <h2>create user</h2>
        <form action='/signupSubmit' method='post'>
            <input name='name' type='text' placeholder='name'><br>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `;
    res.send(html);
});

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    if (!name) {
        res.send(`
            <p>Name is required.</p>
            <a href='/signup'>Try again</a>
        `);
        return;
    }
    if (!email) {
        res.send(`
            <p>Email is required.</p>
            <a href='/signup'>Try again</a>
        `);
        return;
    }
    if (!password) {
        res.send(`
            <p>Password is required.</p>
            <a href='/signup'>Try again</a>
        `);
        return;
    }

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(40).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/signup');
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    var html = `
        <h2>log in</h2>
        <form action='/loginSubmit' method='post'>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `;
    res.send(html);
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().max(40).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(`
            <p>Invalid email/password combination.</p>
            <a href='/login'>Try again</a>
        `);
        return;
    }

    const result = await userCollection.find({ email: email })
        .project({ name: 1, email: 1, password: 1, _id: 1 })
        .toArray();

    if (result.length != 1) {
        console.log("user not found");
        res.send(`
            <p>Invalid email/password combination.</p>
            <a href='/login'>Try again</a>
        `);
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.send(`
            <p>Invalid email/password combination.</p>
            <a href='/login'>Try again</a>
        `);
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const randomImage = Math.floor(Math.random() * 3) + 1;
    const imageName = `cat${randomImage}.jpg`;

    var html = `
        <h1>Hello, ${req.session.name}.</h1>
        <img src='/${imageName}' style='width:300px;'><br><br>
        <form action='/logout' method='get'>
            <button>Sign out</button>
        </form>
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});