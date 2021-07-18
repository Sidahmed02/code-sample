let express = require("express");
let authUtilities = require("../auth/authUtils");
let httpCodes = require("http-status-codes");

//create user model instance
const userModel = require("../models/user");
const User = userModel.User;

module.exports.processUserLogin = async (req, res, next) => {
  try {
    //check if user exist in database to allow login
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      res
        .status(httpCodes.StatusCodes.UNAUTHORIZED)
        .json({ success: false, msg: "could not find user" });
    } else {
      //if user found- check password provided
      const isValidPassword = authUtilities.validatePassword(
        req.body.password,
        user.password,
        user.salt
      );
      //if password is validated issue a JWT else notify client that password id wrong
      if (isValidPassword) {
        const jwt = authUtilities.issueJWT(user);
        res.status(httpCodes.StatusCodes.OK).json({
          success: true,
          token: jwt.token,
          expiresIn: jwt.expiresIn
        });
      } else {
        res
          .status(httpCodes.StatusCodes.UNAUTHORIZED)
          .json({ success: false, msg: "entered wrong password" });
      }
    }
  } catch (err) {
    console.log("error from user login controller ---->");
    next(err);
  }
};

module.exports.processUserRegistration = async (req, res, next) => {
  try {
    //check if email exist in database before creating a new user
    const user = await User.findOne({ email: req.body.email });

    //if email exist return a msg to notify the clinet
    if (user) {
      res
        .status(httpCodes.StatusCodes.UNAUTHORIZED)
        .json({ success: false, msg: "email already exists!!" });
    } else {
      //hash the user password
      const saltAndHashedPsw = authUtilities.hashPassword(req.body.password);
      const { salt, hashedPassword } = saltAndHashedPsw;

      const newUser = new User({
        fName: req.body.fName,
        lName: req.body.lName,
        password: hashedPassword,
        salt: salt,
        email: req.body.email
      });

      const savedUser = await newUser.save();
      //generate a JWT to send to the client
      const jwt = authUtilities.issueJWT(savedUser);
      res.status(httpCodes.StatusCodes.OK).json({
        success: true,
        token: jwt.token,
        expiresIn: jwt.expiresIn
      });
    }
  } catch (err) {
    console.log("error from user register controller ---->");
    next(err);
  }
};

module.exports.processUserInfo = (req, res, next) => {
  //return the user info if authenticated successfully
  res.status(httpCodes.StatusCodes.OK).json({
    success: true,
    fName: req.user.fName,
    lName: req.user.lName,
    email: req.user.email,
    feeds: req.user.feeds,
    created: req.user.created,
    update: req.user.update
  });
};
