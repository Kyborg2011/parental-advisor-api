// server.js

var config   = require('./config/nconfig');
var express  = require('express');
var app      = express();
var port     = config.get("port");
var mongoose = require('mongoose');

var passport = require('passport');
var flash    = require('connect-flash');
var morgan       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var session      = require('express-session');

mongoose.connect(config.get("mongoose:uri"));

var oauth2 = require('./app/oauth2.js');

require('./config/passport')(passport);

app.use(morgan('dev'));
app.use(bodyParser());
app.set('view engine', 'ejs');
app.use(passport.initialize());

require('./app/routes.js')(app, passport);

app.listen(port);
console.log('RESTful API is started on port ' + port);
