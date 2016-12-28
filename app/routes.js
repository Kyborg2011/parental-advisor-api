// app/routes.js

var oauth2 = require('./oauth2.js');
var crypto = require('crypto');
var bcrypt = require('bcrypt-nodejs');
var mongoose = require('mongoose');

// Models
var UserModel = require('./models/user');
var StateModel = require('./models/state');
var ObjectModel = require('./models/object');
var ClientModel = require('./models/client');
var AccessTokenModel = require('./models/accesstoken');
var RefreshTokenModel = require('./models/refreshtoken');
var sms = require('./controllers/sms');
var firebase = require('./controllers/firebase');

module.exports = function(app, passport) {

    // RESTful API status page
    app.get('/api', passport.authenticate('bearer', { session: false }), function(req, res) {
        res.status(200);
        return res.send('API status: ok');
    });

    // User login (getting of access token)
    app.post('/oauth/token', oauth2.token);

    // User signup
    // Linking with Google or Facebook
    app.post('/api/users', passport.authenticate('local-signup', { session: false }),
    function(req, res) {
        res.status(200);
        res.send({ signup: "success" });
    });

    // Activate new user
    app.post('/api/users/activate', function(req, res, next) {

        UserModel.findOne({
            'local.email': req.body.email
        }, function(err, userObj) {

            if (userObj != null) {
                if (bcrypt.compareSync(req.body.code, userObj.local.activation_code)) {
                    userObj.local.active = 1;
                    userObj.save();
                    return res.status(200).send(userObj);
                } else {
                    return res.status(200).send({error: "Invalid code"});
                }
            } else {
                return res.status(200).send({error: "E-mail doesn't exist"});
            }

        });
    });

    // Password recovery
    app.post('/api/users/recovery', function(req, res, next) {

        UserModel.findOne({
            'local.email': req.body.email
        }, function(err, userObj) {
            if (userObj != null) {
                const buf = crypto.randomBytes(6);
                var cryptoString = buf.toString('hex');
                var hash = bcrypt.hashSync(cryptoString, bcrypt.genSaltSync(8), null);

                sms("New password: " + cryptoString, userObj.local.phone);
                userObj.local.password = hash;
                userObj.save();

                return res.status(200).send(userObj);
            } else {
                return res.status(200).send({error: "E-mail doesn't exist"});
            }
        });
    });

    // Set user's Firebase refresh token
    app.post('/api/users/save_firebase_token', passport.authenticate('bearer', { session: false }),
        function(req, res, next) {
        var firebaseToken = req.body.firebase_token;
        if (firebaseToken != null) {
            req.user.local.firebase_token = firebaseToken;
            req.user.save();
            return res.status(200).send(req.user.local);
        } else {
            return res.status(200).send({ error: "No firebase token passed" });
        }
    });

    // Monitoring objects API
    // Create object
    app.post('/api/objects', passport.authenticate('bearer', { session: false }),
        function(req, res, next) {

        ObjectModel.findOne({
            phone: req.body.phone
        }, function(err, monitoringObj) {
            if (monitoringObj != null) {
                return res.status(200).send({error: "Phone already exists"});
            } else {
                var newObject = new ObjectModel();
                newObject.active = 0;
                newObject.phone = req.body.phone;
                newObject.full_name = req.body.full_name;
                newObject.user_id = req.user.userId;

                const buf = crypto.randomBytes(3);
                var cryptoString = buf.toString('hex');
                var hash = bcrypt.hashSync(cryptoString, bcrypt.genSaltSync(8), null);
                sms("Your code: " + cryptoString, newObject.phone);

                newObject.activation_code = hash;

                newObject.save(function(err) {
                    if (err)
                        throw err;
                });

                res.status(200).send(newObject);
            }
        });
    });

    // Register device
    app.post('/api/objects/register_device', function(req, res, next) {

        ObjectModel.findOne({
            phone: req.body.phone
        }, function(err, monitoringObj) {
            if (monitoringObj == null) {
                return res.status(200).send({error: "Invalid phone number"});
            } else {

                if (req.body.code != undefined) {
                    if (bcrypt.compareSync(req.body.code, monitoringObj.activation_code)) {
                        monitoringObj.active = 1;
                        monitoringObj.operation_system = req.body.os;
                        monitoringObj.imei = req.body.imei;
                        monitoringObj.firebase_token = req.body.firebase_token;
                        monitoringObj.save();
                        return res.status(200).send(monitoringObj);
                    } else {
                        return res.status(200).send({error: "Invalid code"});
                    }
                }

                UserModel.findOne({ _id: monitoringObj.user_id }, function(err, user) {
                    if (user != null) {
                        var userPhone = user.local.phone;

                        const buf = crypto.randomBytes(3);
                        var cryptoString = buf.toString('hex');
                        var hash = bcrypt.hashSync(cryptoString, bcrypt.genSaltSync(8), null);
                        sms("Your code: " + cryptoString, userPhone);

                        monitoringObj.activation_code = hash;
                        monitoringObj.save(function(err) {
                            if (err)
                                throw err;
                        });

                        res.status(200).send(monitoringObj);
                    }
                });

            }
        });
    });

    // Activate object
    app.post('/api/objects/activate', passport.authenticate('bearer', { session: false }),
        function(req, res, next) {

        ObjectModel.findOne({
            phone: req.body.phone
        }, function(err, monitoringObj) {
            if (monitoringObj != null) {
                if (monitoringObj.user_id != req.user.userId) {
                    return res.status(200).send({error: "It's not your object"});
                } else {
                    if (bcrypt.compareSync(req.body.code, monitoringObj.activation_code)) {
                        monitoringObj.active = 1;
                        monitoringObj.save();
                        return res.status(200).send(monitoringObj);
                    } else {
                        return res.status(200).send({error: "Invalid code"});
                    }
                }
            } else {
                return res.status(200).send({error: "Phone number don't exist"});
            }
        });
    });

    // Get all objects with last state
    app.get('/api/objects', passport.authenticate('bearer', { session: false }),
        function(req, res, next) {
        ObjectModel.find({
            user_id: req.user.userId
        })
        .populate({
            path: 'states',
            options: {
                limit: 1,
                sort: {
                    timestamp: -1
                }
            }
        })
        .exec(function (err, objects) {
            if (err) res.status(200).send({error: err});

            res.status(200).send(objects);
        });
    });

    // Get single object with all of object's states
    app.get('/api/objects/:id', passport.authenticate('bearer', { session: false }),
        function(req, res, next) {

        ObjectModel.findOne({ _id: req.params.id})
        .populate({
            path: 'states',
            options: {
                sort: {
                    timestamp: -1
                }
            }
        })
        .exec(function (err, object) {
            if (err) res.status(200).send({error: err});
            if (object == null) {
                res.status(200).send({error: "Incorrect id"});
            }
            if (object != null && object.user_id != req.user.userId) {
                res.status(200).send({error: "You haven't access"});
            }

            return res.status(200).send(object);
        });

    });

    // Delete object
    app.delete('/api/objects/:id', passport.authenticate('bearer', { session: false }),
        function(req, res, next) {

        ObjectModel.findOne({ _id: req.params.id})
        .exec(function (err, object) {
            if (err) res.status(200).send({error: err});
            if (object == null) {
                return res.status(200).send({error: "Incorrect id"});
            }
            if (object != null && object.user_id != req.user.userId) {
                return res.status(200).send({error: "You haven't access"});
            }

            object.remove();
            return res.status(200).send({ result: "Object has deleted successfully" });
        });

    });

    // Update object
    app.put('/api/objects/:id', passport.authenticate('bearer', { session: false }),
        function(req, res, next) {

        ObjectModel.findOne({ _id: req.params.id})
        .exec(function (err, object) {
            if (err) res.status(200).send({error: err});
            if (object == null) {
                return res.status(200).send({error: "Incorrect id"});
            }
            if (object != null && object.user_id != req.user.userId) {
                return res.status(200).send({error: "You haven't access"});
            }

            if (req.body.full_name != undefined) {
                object.full_name = req.body.full_name;
            }
            object.save();
            return res.status(200).send({ result: "Object has updated successfully" });
        });

    });

    // New object state
    app.post('/api/states', function(req, res, next) {

        ObjectModel.findOne({
            phone: req.body.phone,
            active: 1
        }, function(err, monitoringObj) {
            if (monitoringObj != null) {

                var newStateObject = new StateModel();
                newStateObject.lat = req.body.lat;
                newStateObject.lng = req.body.lng;
                newStateObject.battery_level = req.body.battery_level;
                newStateObject.object = monitoringObj._id;
                newStateObject.save(function(err) {
                    if (err)
                        throw err;
                });

                monitoringObj.states.push(newStateObject);
                monitoringObj.save();

                // Send push notification to User
                firebase(newStateObject, monitoringObj.user_id);

                res.status(200).send(newStateObject);
            } else {
                res.status(200).send({error: "Object with this phone number don't exist"});
            }
        });

    });

    // User logout
    app.get('/api/logout', function(req, res) {
        req.logout();
        res.redirect('/api');
    });
};

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated())
        return next();
    res.redirect('/');
}
