const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('node:crypto');
const db = require('../db');

const router = express.Router();

passport.use(new LocalStrategy((username, password, cb) => {
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return cb(err)
    if (!row) return cb(null, false, { message: 'incorrect username or password' });

    crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', (err, hashedPass) => {
      if (err) return cb(err)
      if (!crypto.timingSafeEqual(row.hashed_password, hashedPass))
        return cb(null, false, { message: 'incorrect username or password' });

      return cb(null, row);
    })
  })
}));

passport.serializeUser((user, done) => process.nextTick(() => done(null, user)))
passport.deserializeUser((user, done) => process.nextTick(() => done(null, user)))

router.get('/login', (req, res) => {
  res.render('login');
})

router.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' }))

router.post('/logout', (req, res, next) => {
  req.logOut(err => {
    if (err) next(err)
    res.redirect('/');
  })
})

router.get('/signup', (req, res) => res.render('signup'));

router.post('/signup', (req, res, next) => {
  const salt = crypto.randomBytes(16);
  crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', (err, hashedPass) => {
    if (err) return next(err)
    db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
      req.body.username,
      hashedPass,
      salt
    ], function (err) {
      if (err) return next(err)
      const user = {
        id: this.lastID,
        username: req.body.username
      }
      req.logIn(user, (err) => {
        if (err) return next(err)
        res.redirect('/')
      })
    })
  })
})

module.exports = router