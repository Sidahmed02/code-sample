const fs = require("fs");
const path = require("path");

const JWTStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
//user model
const userModel = require("../models/user");
const User = userModel.User;

//store path to public key in a variable
const pathToPubKey = path.join(__dirname, "cipherKeys/rsa_pub_key.pem");

//retrive the public key from the file
const PUB_KEY = fs.readFileSync(pathToPubKey, "utf8");

//option to state how to extract JWT from HTTP request to be used in jwt.verify middleware
const options = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: PUB_KEY,
  algorithms: ["RS256"]
};

//JWT strategy to verify the JWT received in the request and check if the user exist in the database after it is confirmed
const strategy = new JWTStrategy(options, async (payload, done) => {
  try {
    const user = await User.findOne({ _id: payload.sub });

    if (user) {
      return done(null, user);
    } else {
      return done(null, false);
    }
  } catch (e) {
    next(e);
  }
});

//add the strategy sub middleware to the passport middleware
module.exports = passport => {
  passport.use(strategy);
};
