const crypto = require("crypto");
const fs = require("fs");

function genKeyPair() {
  // Generates an object where the keys are stored in properties `privateKey` and `publicKey`
  const keyPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096, // bits - standard for RSA keys
    publicKeyEncoding: {
      type: "pkcs1", // "Public Key Cryptography Standards 1"
      format: "pem" // Privacy Enhanced Mail - Most common formatting choice to store crypto keys
    },
    privateKeyEncoding: {
      type: "pkcs1", // "Public Key Cryptography Standards 1"
      format: "pem" // Most common formatting choice
    }
  });

  try {
    //check if the keys are already generated, else created a private and public keys
    if (fs.existsSync(__dirname + "/rsa_pub_key.pem")) {
      console.log("Keys already generated...");
    } else {
      // Create the public key file
      fs.writeFileSync(__dirname + "/rsa_pub_key.pem", keyPair.publicKey);

      // Create the private key file
      fs.writeFileSync(__dirname + "/rsa_priv_key.pem", keyPair.privateKey);
    }
  } catch (e) {
    console.log(e);
  }
}

// Generates the keypair
genKeyPair();
