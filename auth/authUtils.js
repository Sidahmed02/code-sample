const crypto = require("crypto");
const jsonwebtoken = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const constants = require("../constants");

// get crypto options from constants file
const { cryptOption } = constants;

//store path to privet key in a variable
const pathToPrivKey = path.join(__dirname, "cipherKeys/rsa_priv_key.pem");
//get the private key from the file and store it in a variable
const PRIV_KEY = fs.readFileSync(pathToPrivKey, "utf8");

//hashing user password before storing it
function hashPassword(password) {
  //generating random charachters to use as a salt when hashing the passord
  var salt = crypto.randomBytes(32).toString("hex");

  // using Password-Based Key Derivation Function 2 to hash the password-used recommended options
  var passwordHash = crypto
    .pbkdf2Sync(
      password,
      salt,
      cryptOption.iterations,
      cryptOption.keylen.key64,
      cryptOption.digest.sha512
    )
    .toString("hex");

  return {
    salt: salt,
    hashedPassword: passwordHash
  };
}

//verify if the password provided after hashed similair to the one in database
function validatePassword(password, hashedPassword, salt) {
  // using Password-Based Key Derivation Function 2 to hash the password-used similar options when hashing
  var hashVerify = crypto
    .pbkdf2Sync(
      password,
      salt,
      cryptOption.iterations,
      cryptOption.keylen.key64,
      cryptOption.digest.sha512
    )
    .toString("hex");
  return hashedPassword === hashVerify;
}

//generate JWT for the user to authenticate when accesing secured routes
function issueJWT(user) {
  const _id = user._id;
  const email = user.email;
  //duration when token expires
  const expiresIn = "1w";
  //payload to attach to the token
  const payload = {
    sub: _id,
    email: email,
    iat: Date.now()
  };
  //generate token and sign it using private key
  const signedToken = jsonwebtoken.sign(payload, PRIV_KEY, {
    expiresIn: expiresIn,
    algorithm: "RS256"
  });

  return { token: "Bearer " + signedToken, expiresIn: expiresIn };
}

module.exports.validatePassword = validatePassword;
module.exports.hashPassword = hashPassword;
module.exports.issueJWT = issueJWT;
