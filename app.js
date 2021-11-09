//Env variables
require('dotenv').config();
const appPort = process.env.APP_PORT;
const appHost = process.env.APP_HOST;
const databaseName = process.env.DB_NAME;
const databaseHost = process.env.DB_HOST;
const databasePort = process.env.DB_PORT;

//Required packages
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook');
const findOrCreate = require('mongoose-findorcreate');


const app = express();

//Middleware
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine','ejs');
app.use(express.static("public"));
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

//Connect mongoose
mongoose.connect(`mongodb://${databaseHost}:${databasePort}/${databaseName}`, function(err) {
  if(err) {
    console.log(err);
  } else {
    console.log("Mongoose connected to MongoDB.");
  }
});

//Schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Model
const User = new mongoose.model("User", userSchema);
// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `http://${appHost}:${appPort}/auth/google/secrets`,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: `http://${appHost}:${appPort}/auth/facebook/secrets`
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",(req,res)=>{
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"]})
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: '/login'}),
  (req,res) => {
    res.redirect('/secrets');
  }
);

app.get("/auth/facebook",
  passport.authenticate("facebook")
);

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: '/login'}),
  (req,res) => {
    res.redirect('/secrets');
  }
);

app.get("/login",(req,res)=>{
  res.render("login");
});

app.get("/register",(req,res)=>{
  res.render("register");
});

app.get("/secrets",(req,res)=>{
  User.find({"secret":{$ne:null}},(err,foundUsers)=>{
    if(err){
      console.log(err);
    } else {
      if(foundUsers && foundUsers.length > 0) {
        res.render("secrets",{usersWithSecrets:foundUsers});
      } else {
        res.render("secrets",{usersWithSecrets:[{secret:"No secrets found.  Add one!"}]})
      }
    }
  });
});

app.get("/logout",(req,res)=>{
  req.logout();
  res.redirect("/");
});

app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/register",(req,res)=>{
  User.register({username: req.body.username},req.body.password,(err, user)=>{
    if(err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login",(req,res)=>{
  const user = new User({
    username: req.body.username,
    password: req.body.password
  })
  req.login(user,(err)=>{
    if(err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit",(req,res)=>{
  const submittedSecret = req.body.secret;
  User.findById(req.user.id,(err,foundUser)=>{
    if(err){
      console.log(err);
    } else {
      if(foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(()=>{
          res.redirect("/secrets");
        });
      } else {
        console.log(`Unable to find user ${req.user.id} to update secret.`);
        res.redirect("/secrets");
      }
    }
  });

});

app.listen(appPort, appHost, function () {
  console.log(`Server Started on ${appHost}:${appPort}`);
});
