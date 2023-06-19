const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require("dotenv").config();
const router = express.Router();
const jwt = require('jsonwebtoken');
const json = require('express');
const cookieParser = require('cookie-parser');
var url = require('url');

const pool = require('../database.js')

const postIdFunction = require('../postIdFunction');
const bcrypt = require('bcrypt');
const saltRounds = 13;

router.use(bodyParser.urlencoded({ extended: true }));
router.use(cookieParser());
router.use(json());

router.use(express.static(__dirname + '/public'));

pool.connect();

router.get('/user/new', (req, res) => {
    res.render('signup');
})

// Create new user, check user exists, hash password, postgres serial creates user_id
router.post('/user/new', (req, res) => {
    let emailSignup = req.body.email.toLowerCase();
    let passwordSignup = req.body.password;
    let confirmPassword = req.body.confirmPassword;
    pool.query('SELECT email FROM users', (err, result) => {
        if (!err) {
            let registeredUsersEmails = result.rows;
            let userCheck = registeredUsersEmails.some(e => e.email === emailSignup)
            if (!userCheck && passwordSignup == confirmPassword) {
                console.log("Entered email not in database so this is new user and confirm email matches.");
                bcrypt.hash(passwordSignup, saltRounds).then(function (hash) {
                    pool.query(
                        "INSERT INTO users (email, password) VALUES ($1, $2)", [emailSignup, hash]
                    )
                    console.log(hash);
                });
                res.redirect('/user/login');
            } else if (passwordSignup != confirmPassword) {
                console.log("Password fields don't match.");
            } else if (userCheck && passwordSignup == confirmPassword) {
                console.log("User email already in database. Please log in with password.")
                res.redirect('/user/login');
            }
        }
    });
})

router.get('/user/login', (req, res) => {
    res.render('login');
})

// Login user, check user exists, verify hashed password, create jwt session with token in cookies
router.post('/user/login', (req, res) => {
    let emailLogin = req.body.email.toLowerCase();
    let passwordLogin = req.body.password;
    pool.query('SELECT * FROM users', (err, result) => {
        if (!err) {
            let registeredUser = result.rows;
            let userCheck = registeredUser.some(e => e.email === emailLogin)
            if (userCheck) {
                // NEW DATA SET SO THE COMPARISON IS UNBAIS
                pool.query('SELECT * FROM users', (err, result) => {
                    if (!err) {
                        let fields = result.rows;
                        fields.map((item) => {
                            if (item.email == emailLogin && bcrypt.compare(passwordLogin, item.password)) {
                                let user = { email: emailLogin };
                                let accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '2h' });
                                // Hold this refresh token. Maybe want to use it.
                                // let refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '24h' });
                                // Token is saved in DB
                                // pool.query('UPDATE users SET access_token=$1 WHERE email=$2', [accessToken, item.email])
                                res.cookie('session_id', item.user_id, { maxAge: 2 * 60 * 60 * 1000, httpOnly: true })
                                res.cookie('access_token', accessToken, { httpOnly: true })
                                res.redirect('/posts');
                            }
                        })
                    }
                });
            } else {
                res.render('signup');
                console.log("Email not registered. Please sign up.")
            }
        }
    });
});

const verifyToken = (req, res, next) => {
    const accessToken = req.cookies.access_token;
    if (!accessToken) {
        return res.status(401).json("A token is required for authentication");
    }
    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.status(403).send("Please register or log in to access Pepper.");
        }
        req.user = user
        next();
    })
};
router.use(verifyToken);

// Log out user, delete cookies for session_id and jwt
router.get('/user/:userId/logout', (req, res) => {
    res.cookie('session_id', null, { httpOnly: true })
    res.cookie('access_token', null, { httpOnly: true })
    res.render('logout');
})

// Show all posts
router.get('/posts', (req, res) => {
    pool.query('SELECT * FROM posts', (err, result) => {
        if (!err) {
            let sessionIdCookies = req.cookies.session_id;
            let linkToLogout = `/user/userId${sessionIdCookies}/logout`
            let linkToUserPosts = `/user/userId${sessionIdCookies}/posts`
            let linkToUserAccount = `/user/userId${sessionIdCookies}/account`
            res.render('posts', {
                jobPosts: result.rows,
                logout: linkToLogout,
                userPosts: linkToUserPosts,
                userAccount: linkToUserAccount,
            });
        }
    });
})

// Show only posts of logged in user
router.get('/user/:userId/posts', (req, res) => {
    let sessionIdCookies = req.cookies.session_id;
    let linkToLogout = `/user/userId${sessionIdCookies}/logout`;
    let linkToUserPosts = `/user/userId${sessionIdCookies}/posts`;
    let linkToUserAccount = `/user/userId${sessionIdCookies}/account`;
    let linkToCreatePost = `/user/userId${sessionIdCookies}/posts/new`;

    pool.query('SELECT * FROM posts WHERE user_id_fk=$1', [sessionIdCookies], (err, result) => {
        if (!err) {
            console.log('Connected to Posts table.')
        }
        res.render('userdashboardPosts', {
            jobPosts: result.rows,
            logout: linkToLogout,
            userPosts: linkToUserPosts,
            userAccount: linkToUserAccount,
            newPost: linkToCreatePost
        });
    });
});

// Show user dashboard account
router.get('/user/:userId/account', (req, res) => {
    let sessionIdCookies = req.cookies.session_id;
    let linkToLogout = `/user/userId${sessionIdCookies}/logout`
    let linkToUserPosts = `/user/userId${sessionIdCookies}/posts`
    let linkToUserAccount = `/user/userId${sessionIdCookies}/account`
    res.render('userdashboardAccount', {
        logout: linkToLogout,
        userPosts: linkToUserPosts,
        userAccount: linkToUserAccount,
    });
});

// User updates password
router.post('/user/:userId/account/update', (req, res) => {
    let emailUpdate = req.body.emailUpdate;
    let passwordUpdate = req.body.passwordUpdate;
    let newPasswordUpdate = req.body.newPasswordUpdate;
    pool.query('SELECT * FROM users WHERE email=$1', [emailUpdate], (err, result) => {
        if (!err) {
            let userUpdate = result.rows;
            userUpdate.map(item => {
                let hash = item.password;
                let sessionIdCookies = req.cookies.session_id;
                let userSessionUpdate = item.user_id
                if (sessionIdCookies == userSessionUpdate && bcrypt.compare(passwordUpdate, hash)) {
                    bcrypt.hash(newPasswordUpdate, saltRounds).then(function (hash) {
                        pool.query('UPDATE users SET password=$1 WHERE email=$2', [hash, emailUpdate])
                        let sessionIdCookies = req.cookies.session_id;
                        res.redirect(`/user/userId${sessionIdCookies}/logout`);
                    });
                }
            });
        }
    })
})

// User deactivates account
router.post('/user/:userId/account/deactvate', (req, res) => {
    let emailDeactivate = req.body.emailDeactivate;
    let passwordDeactivate = req.body.passwordDeactivate;
    pool.query('SELECT * FROM users WHERE email=$1', [emailDeactivate], (err, result) => {
        if (!err) {
            let userDeactivate = result.rows;
            userDeactivate.map(item => {
                let hash = item.password;
                if (bcrypt.compare(passwordDeactivate, hash)) {
                    let sessionIdCookies = req.cookies.session_id;
                    pool.query('DELETE FROM posts WHERE user_id_fk=$1', [sessionIdCookies], (err, result) => {
                        if (!err) {
                            pool.query('DELETE FROM users WHERE password=$1', [hash], (err, result) => {
                                if (!err) {
                                    res.redirect(`/user/userId${sessionIdCookies}/logout`);
                                }
                            })
                        }
                    })
                }
            });
        }
    })
})

// User deletes a post
router.get('/user/:userId/:postId', (req, res) => {
    let postIdQuery = req.params.postId;
    console.log(postIdQuery);
    pool.query('DELETE FROM posts WHERE post_id=$1', [postIdQuery], (err, result) => {
        if (!err) {
            let userId = req.cookies.session_id;
            res.redirect(`/user/userId${userId}/posts`);
        }
    })
});

// New post form
router.get('/user/:userId/posts/new', (req, res) => {
    res.render('newPost');
})

// Create a new post
router.post('/user/:userId/posts/new', (req, res) => {
    let timestamp = new Date();
    let postTitle = req.body.postTitle;
    let postContent = req.body.postContent;
    let cityCountry = req.body.cityCountry;
    let hiringContact = req.body.hiringContact;
    let postId = postIdFunction;
    let userId = req.cookies.session_id;
    pool.query(
        "INSERT INTO posts (timestamp, post_title, post_content, city_country, hiring_contact, post_id, user_id_fk) VALUES ($1, $2, $3, $4, $5, $6, $7) returning *", [timestamp, postTitle, postContent, cityCountry, hiringContact, postId, userId]
    )

    res.redirect(`/user/uderId${userId}/posts`);
})

module.exports = router;