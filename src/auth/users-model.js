'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const users = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  role: { type: String, default: 'user', enum: ['admin', 'editor', 'user'] },
});

users.pre('save', function(next) {
  bcrypt
    .hash(this.password, 10)
    .then(hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch(console.error);
});

users.statics.createFromOauth = function(email) {
  if (!email) {
    return Promise.reject('Validation Error');
  }

  return (
    this.findOne({ email })
      .then(user => {
        if (!user) {
          throw new Error('User Not Found');
        }
        console.log('Welcome Back', user.username);
        return user;
      })
      // eslint-disable-next-line
      .catch(error => {
        console.log('Creating new user');
        let username = email;
        let password = 'none';
        return this.create({ username, password, email });
      })
  );
};

users.statics.authenticateKey = function(token) {
  const parsedKey = jwt.verify(token, process.env.SECRET);
  console.log('parsedKey:', parsedKey);
  let { id } = parsedKey;
  // Sends back user and key rather than only user
  return this.findById(id)
    .then(user => ({ user, key: parsedKey }))
    .catch(error => {
      throw error;
    });
};

users.statics.authenticateBearer = function(token) {
  const parsedToken = jwt.verify(token, process.env.SECRET);
  console.log('parsedToken:', parsedToken);
  let { id } = parsedToken;
  return this.findById(id)
    .then(user => user)
    .catch(error => {
      throw error;
    });
};

users.statics.authenticateBasic = function(auth) {
  let query = { username: auth.username };
  return this.findOne(query)
    .then(user => user && user.comparePassword(auth.password))
    .catch(error => {
      throw error;
    });
};

users.methods.comparePassword = function(password) {
  return bcrypt.compare(password, this.password).then(valid => (valid ? this : null));
};

users.methods.generateToken = function() {
  const token = {
    id: this._id,
    role: this.role,
  };
  return jwt.sign(token, process.env.SECRET, { expiresIn: '15m' });
};

// Delete the `Issued At` and `Expires` claims and do not include `expiresIn` option
users.methods.refreshKey = function(key) {
  const refreshed = Object.assign({}, key);
  if (refreshed.iat) {
    delete refreshed.iat;
  }
  if (refreshed.exp) {
    delete refreshed.exp;
  }
  return jwt.sign(refreshed, process.env.SECRET);
};

module.exports = mongoose.model('users', users);
