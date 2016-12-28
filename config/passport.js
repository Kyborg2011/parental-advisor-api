// config/passport.js
var config = require('./nconfig');

var crypto = require('crypto');
var bcrypt = require('bcrypt-nodejs');
var sms = require('../app/controllers/sms');

// load authentication strategies
var BasicStrategy = require('passport-http').BasicStrategy;
var LocalStrategy = require('passport-local').Strategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;

// load up models
var User = require('../app/models/user');
var Client = require('../app/models/client');
var AccessToken = require('../app/models/accesstoken');
var RefreshToken = require('../app/models/refreshtoken');

module.exports = function(passport) {
    // Basic authentication pop-up
    passport.use(new BasicStrategy(
        function(username, password, done) {
            Client.findOne({
                clientId: username
            }, function(err, client) {
                if (err) {
                    return done(err);
                }
                if (!client) {
                    return done(null, false);
                }
                if (client.clientSecret != password) {
                    return done(null, false);
                }

                return done(null, client);
            });
        }
    ));

    // Check clientId + clientSecret for existence
    passport.use(new ClientPasswordStrategy(
        function(clientId, clientSecret, done) {
            Client.findOne({
                clientId: clientId
            }, function(err, client) {
                if (err) {
                    return done(err);
                }
                if (!client) {
                    return done(null, false);
                }
                if (client.clientSecret != clientSecret) {
                    return done(null, false);
                }

                return done(null, client);
            });
        }
    ));

    // Check access token
    passport.use(new BearerStrategy(
        function(accessToken, done) {
            AccessToken.findOne({
                token: accessToken
            }, function(err, token) {
                if (err) {
                    return done(err);
                }
                if (!token) {
                    return done(null, false);
                }

                if (Math.round((Date.now() - token.created) / 1000) > config.get('security:tokenLife')) {
                    AccessToken.remove({
                        token: accessToken
                    }, function(err) {
                        if (err) return done(err);
                    });
                    return done(null, false, {
                        message: 'Token expired'
                    });
                }

                User.findById(token.userId, function(err, user) {
                    if (err) {
                        return done(err);
                    }
                    if (!user) {
                        return done(null, false, {
                            message: 'Unknown user'
                        });
                    }

                    var info = {
                        scope: '*'
                    }
                    done(null, user, info);
                });
            });
        }
    ));

    // Sign Up
    passport.use('local-signup', new LocalStrategy({
            // by default, local strategy uses username and password, we will override with email
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true
        },
        function(req, email, password, done) {

            // asynchronous
            // User.findOne wont fire unless data is sent back
            process.nextTick(function() {

                User.findOne({
                    'local.email': email
                }, function(err, user) {

                    if (err)
                        return done(err);

                    if (user) {
                        return done(null, false);
                    } else {

                        // New user creation
                        var newUser = new User();
                        newUser.local.email = email;
                        newUser.local.password = newUser.generateHash(password);
                        newUser.local.full_name = req.body.full_name;
                        newUser.local.phone = req.body.phone;
                        newUser.local.active = 0;

                        const buf = crypto.randomBytes(3);
                        var cryptoString = buf.toString('hex');
                        var hash = bcrypt.hashSync(cryptoString, bcrypt.genSaltSync(8), null);
                        sms("Verification code: " + cryptoString, newUser.local.phone);

                        newUser.local.activation_code = hash;

                        newUser.save(function(err) {
                            if (err)
                                throw err;
                            return done(null, newUser);
                        });
                    }
                });
            });
    }));
};
