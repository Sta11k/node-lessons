// const jwt = require("jsonwebtoken");

// const payload = { id: 123456, username: "Larson" };
// const secret = "secret word";
// const token = jwt.sign(payload, secret);

// console.log(token);

const passport = require("passport");
const passportJWT = require("passport-jwt");
const User = require("../schemas/user");
require("dotenv").config();
const secret = process.env.SECRET;

const ExtractJWT = passportJWT.ExtractJwt;
const Strategy = passportJWT.Strategy;
const params = {
  secretOrKey: secret,
  jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
};

// JWT Strategy
passport.use(
  new Strategy(params, function (payload, done) {
    User.find({ _id: payload.id })
      .then(([user]) => {
        if (!user) {
          return done(new Error("User not found"));
        }
        return done(null, user);
      })
      .catch((err) => done(err));
  })
);
