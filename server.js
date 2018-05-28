var express = require('express');
var app = express();
var passport   = require('passport');
var session    = require('express-session');
var bodyParser = require('body-parser');
var env = require('dotenv').load();
var exphbs = require('express-handlebars')




//For BodyParser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


//For Handlebars
app.set('views', './views')
app.engine('hbs', exphbs({
    extname: '.hbs'
}));
app.set('view engine', '.hbs');


app.get('/', function(req, res) {
 
    res.send('Welcome to Passport with Sequelize');
 
});


// For Passport
 
app.use(session({ secret: 'keyboard cat',resave: true, saveUninitialized:true})); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions

//Models
var models = require("./models");
 
 
//Routes
var authRoute = require('./routes/auth.js')(app,passport);

//load passport strategies
require('./config/passport/passport.js')(passport, models.customer);




//Sync Database
models.sequelize.sync().then(function() {

    app.listen(8080, function(err) {
    
        if (!err)
            console.log("Site is live");
        else console.log(err)
    
    });
}).catch(function(err) {
 
    console.log(err, "Something went wrong with the Database Update!")
 
});