require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();
const port = 3000;

// Middleware
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_secret_key_here',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
app.set('view options', { layout: 'layout' });
app.engine('hbs', require('hbs').__express);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/myapp', {
});
// User Model`
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    notes: [{ type: String }]
});

// Hash the password before saving the user
userSchema.pre('save', async function (next) {
    if (this.isModified('password') || this.isNew) {
        try {
            const hashedPassword = await bcrypt.hash(this.password, 10);
            this.password = hashedPassword;
            next();
        } catch (error) {
            next(error);
        }
    } else {
        next();
    }
});

const User = mongoose.model('User', userSchema);

// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Routes
app.get('/', (req, res) => {
    res.redirect(req.session.userId ? '/notes' : '/login');
});

app.get('/login', (req, res) => {
    res.render('login', { error: req.session.error });
    delete req.session.error;
});

app.get('/register', (req, res) => {
    res.render('register', { error: req.session.error });
    delete req.session.error;
});

app.post('/register', [
    body('username').isLength({ min: 5 }).withMessage('Username must be at least 5 characters long'),
    body('password').isLength({ min: 5 }).withMessage('Password must be at least 5 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.session.error = errors.array().map(err => err.msg).join(', ');
        return res.redirect('/register');
    }
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            username: req.body.username,
            password: hashedPassword,
            notes: []
        });
        await user.save();
        res.redirect('/login');
    } catch (error) {
        req.session.error = 'Username already exists';
        res.redirect('/register');
    }
});

app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (user && await bcrypt.compare(req.body.password, user.password)) {
            req.session.userId = user._id;
            res.redirect('/notes');
        } else {
            req.session.error = 'Invalid credentials';
            res.redirect('/login');
        }
    } catch (error) {
        req.session.error = 'An error occurred';
        res.redirect('/login');
    }
});

app.get('/notes', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render('notes', { 
            username: user.username,
            notes: user.notes,
            error: req.session.error
        });
        delete req.session.error;
    } catch (error) {
        req.session.error = 'Error fetching notes';
        res.redirect('/notes');
    }
});

app.post('/notes', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        user.notes.push(req.body.note);
        await user.save();
        res.redirect('/notes');
    } catch (error) {
        req.session.error = 'Error saving note';
        res.redirect('/notes');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
