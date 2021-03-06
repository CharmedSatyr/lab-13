'use strict';

const express = require('express');
const authRouter = express.Router();

const User = require('./users-model.js');
const auth = require('./middleware.js');
const oauth = require('./oauth/google.js');

authRouter.get('/', (req, res, next) => {
  res.status(200).send('Server up...');
});

authRouter.post('/signup', (req, res, next) => {
  let user = new User(req.body);
  user
    .save()
    .then(user => {
      req.token = user.generateToken();
      req.user = user;
      res.set('token', req.token);
      res.cookie('auth', req.token);
      res.send(req.token);
    })
    .catch(next);
});

authRouter.post('/signin', auth, (req, res, next) => {
  res.cookie('auth', req.token);
  res.send(req.token);
});

authRouter.get('/oauth', (req, res, next) => {
  oauth
    .authorize(req)
    .then(token => {
      res.status(200).send(token);
    })
    .catch(next);
});

// This route creates a permanent access key
authRouter.post('/key', auth, (req, res, next) => {
  res.cookie('auth', req.token);
  res.status(200).send(req.token);
});

module.exports = authRouter;
